//! Probe command - test connectivity through various adapters
//!
//! This command allows testing SOCKS5, HTTP, and other adapter connectivity
//! with comprehensive timing and error reporting.

use clap::{Args as ClapArgs, Subcommand};
use anyhow::{Context, Result};
use serde::Serialize;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use crate::cli::Format;

#[cfg(feature = "adapter-socks")]
use sb_adapters::outbound::socks5::Socks5Connector;
#[cfg(feature = "adapter-http")]
use sb_adapters::outbound::http::HttpProxyConnector;
use sb_adapters::traits::{DialOpts, OutboundConnector, Target, ResolveMode, RetryPolicy, BoxedStream};

#[derive(ClapArgs, Debug)]
pub struct ProbeArgs {
    #[command(subcommand)]
    pub cmd: ProbeCmd,
}

#[derive(Subcommand, Debug)]
pub enum ProbeCmd {
    /// Test SOCKS5 proxy connectivity
    #[cfg(feature = "adapter-socks")]
    Socks {
        /// Proxy address (e.g., 127.0.0.1:1080)
        #[arg(long)]
        proxy: String,
        /// Target to connect to (default: httpbin.org:80)
        #[arg(long, default_value = "httpbin.org:80")]
        target: String,
        /// Username for authentication
        #[arg(long)]
        user: Option<String>,
        /// Password for authentication
        #[arg(long)]
        pass: Option<String>,
        /// Connection timeout in seconds
        #[arg(long, default_value = "10")]
        timeout: u64,
        /// Output format
        #[arg(long, value_enum, default_value = "human")]
        format: Format,
        /// Test UDP ASSOCIATE if supported
        #[arg(long)]
        udp: bool,
        /// Resolve mode (local or remote)
        #[arg(long, value_enum, default_value = "remote")]
        resolve: ResolveMode,
    },
    /// Test HTTP proxy connectivity
    #[cfg(feature = "adapter-http")]
    Http {
        /// Proxy address (e.g., 127.0.0.1:8080)
        #[arg(long)]
        proxy: String,
        /// Target to connect to (default: httpbin.org:80)
        #[arg(long, default_value = "httpbin.org:80")]
        target: String,
        /// Username for authentication
        #[arg(long)]
        user: Option<String>,
        /// Password for authentication
        #[arg(long)]
        pass: Option<String>,
        /// Connection timeout in seconds
        #[arg(long, default_value = "10")]
        timeout: u64,
        /// Use HTTPS proxy (TLS)
        #[arg(long)]
        tls: bool,
        /// Output format
        #[arg(long, value_enum, default_value = "human")]
        format: Format,
        /// Resolve mode (local or remote)
        #[arg(long, value_enum, default_value = "remote")]
        resolve: ResolveMode,
    },
    /// Test direct TCP connectivity (no proxy)
    Direct {
        /// Target address to connect to
        #[arg(long)]
        target: String,
        /// Connection timeout in seconds
        #[arg(long, default_value = "10")]
        timeout: u64,
        /// Output format
        #[arg(long, value_enum, default_value = "human")]
        format: Format,
        /// Send HTTP GET request after connecting
        #[arg(long)]
        http: bool,
    },
}

#[derive(Serialize, Debug)]
struct ProbeResult {
    success: bool,
    connect_time_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    adapter_type: String,
    target: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    response_size: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    total_time_ms: Option<u64>,
    timestamp: String,
}

impl ProbeResult {
    fn new(adapter_type: impl Into<String>, target: impl Into<String>) -> Self {
        Self {
            success: false,
            connect_time_ms: 0,
            error: None,
            adapter_type: adapter_type.into(),
            target: target.into(),
            response_size: None,
            total_time_ms: None,
            timestamp: chrono::Utc::now().to_rfc3339(),
        }
    }

    fn with_success(mut self, connect_time: Duration) -> Self {
        self.success = true;
        self.connect_time_ms = connect_time.as_millis() as u64;
        self
    }

    fn with_error(mut self, error: anyhow::Error) -> Self {
        self.success = false;
        self.error = Some(error.to_string());
        self
    }

    fn with_response(mut self, size: usize, total_time: Duration) -> Self {
        self.response_size = Some(size);
        self.total_time_ms = Some(total_time.as_millis() as u64);
        self
    }
}

pub async fn main(args: ProbeArgs) -> Result<()> {
    match args.cmd {
        #[cfg(feature = "adapter-socks")]
        ProbeCmd::Socks { proxy, target, user, pass, timeout, format, udp, resolve } => {
            probe_socks(proxy, target, user, pass, Duration::from_secs(timeout), format, udp, resolve).await
        },
        #[cfg(feature = "adapter-http")]
        ProbeCmd::Http { proxy, target, user, pass, timeout, tls, format, resolve } => {
            probe_http(proxy, target, user, pass, Duration::from_secs(timeout), tls, format, resolve).await
        },
        ProbeCmd::Direct { target, timeout, format, http } => {
            probe_direct(target, Duration::from_secs(timeout), format, http).await
        },
    }
}

#[cfg(feature = "adapter-socks")]
async fn probe_socks(
    proxy: String,
    target: String,
    user: Option<String>,
    pass: Option<String>,
    timeout: Duration,
    format: Format,
    test_udp: bool,
    resolve_mode: ResolveMode
) -> Result<()> {
    let mut result = ProbeResult::new("socks5", &target);

    let connector = if let (Some(u), Some(p)) = (user, pass) {
        Socks5Connector::with_auth(proxy, &u, &p)
    } else {
        Socks5Connector::no_auth(proxy)
    };

    // Parse target
    let (host, port) = parse_target(&target)?;
    let target = Target::tcp(host, port);

    let opts = DialOpts {
        connect_timeout: timeout,
        read_timeout: timeout,
        retry_policy: RetryPolicy::new().with_max_retries(0),
        resolve_mode,
    };

    let start = Instant::now();
    match connector.dial(target.clone(), opts).await {
        Ok(mut stream) => {
            let connect_time = start.elapsed();
            result = result.with_success(connect_time);

            // Test basic HTTP request
            if let Err(e) = test_http_request(&mut stream, &target, start).await {
                result = result.with_error(e.into());
            }
        },
        Err(e) => {
            result = result.with_error(e.into());
        }
    }

    // Optionally test UDP ASSOCIATE
    if test_udp {
        // Note: UDP testing would require additional implementation
        // For now, just log that it's not yet implemented
        if matches!(format, Format::Human) {
            eprintln!("UDP ASSOCIATE testing not yet implemented");
        }
    }

    output_result(&result, format)
}

#[cfg(feature = "adapter-http")]
async fn probe_http(
    proxy: String,
    target: String,
    user: Option<String>,
    pass: Option<String>,
    timeout: Duration,
    use_tls: bool,
    format: Format,
    resolve_mode: ResolveMode
) -> Result<()> {
    let mut result = ProbeResult::new("http", &target);

    let connector = if let (Some(u), Some(p)) = (user, pass) {
        if use_tls {
            #[cfg(feature = "http-tls")]
            {
                HttpProxyConnector::with_auth_tls(proxy, &u, &p)
            }
            #[cfg(not(feature = "http-tls"))]
            {
                anyhow::bail!("TLS support not compiled in (missing http-tls feature)");
            }
        } else {
            HttpProxyConnector::with_auth(proxy, &u, &p)
        }
    } else {
        if use_tls {
            #[cfg(feature = "http-tls")]
            {
                HttpProxyConnector::no_auth_tls(proxy)
            }
            #[cfg(not(feature = "http-tls"))]
            {
                anyhow::bail!("TLS support not compiled in (missing http-tls feature)");
            }
        } else {
            HttpProxyConnector::no_auth(proxy)
        }
    };

    // Parse target
    let (host, port) = parse_target(&target)?;
    let target = Target::tcp(host, port);

    let opts = DialOpts {
        connect_timeout: timeout,
        read_timeout: timeout,
        retry_policy: RetryPolicy::new().with_max_retries(0),
        resolve_mode,
    };

    let start = Instant::now();
    match connector.dial(target.clone(), opts).await {
        Ok(mut stream) => {
            let connect_time = start.elapsed();
            result = result.with_success(connect_time);

            // Test basic HTTP request
            if let Err(e) = test_http_request(&mut stream, &target, start).await {
                result = result.with_error(e.into());
            }
        },
        Err(e) => {
            result = result.with_error(e.into());
        }
    }

    output_result(&result, format)
}

async fn probe_direct(target: String, timeout: Duration, format: Format, test_http: bool) -> Result<()> {
    let mut result = ProbeResult::new("direct", &target);

    let (host, port) = parse_target(&target)?;
    let addr = format!("{}:{}", host, port);

    let start = Instant::now();
    match tokio::time::timeout(timeout, tokio::net::TcpStream::connect(&addr)).await {
        Ok(Ok(stream)) => {
            let connect_time = start.elapsed();
            result = result.with_success(connect_time);

            if test_http {
                let target = Target::tcp(host, port);
                let mut boxed_stream: BoxedStream = Box::new(stream);
                if let Err(e) = test_http_request(&mut boxed_stream, &target, start).await {
                    result = result.with_error(e.into());
                }
            } else {
                result = result.with_response(0, start.elapsed());
            }
        },
        Ok(Err(e)) => {
            result = result.with_error(e.into());
        },
        Err(_) => {
            result = result.with_error(anyhow::anyhow!("Connection timed out"));
        }
    }

    output_result(&result, format)
}

async fn test_http_request(stream: &mut BoxedStream, target: &Target, _start_time: Instant) -> Result<()> {
    // Send simple HTTP GET request
    let request = format!("GET / HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n", target.host);
    stream.write_all(request.as_bytes()).await?;

    // Read response
    let mut buffer = Vec::new();
    let mut temp = [0u8; 1024];

    // Read with timeout
    match tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let n = stream.read(&mut temp).await?;
            if n == 0 { break; }
            buffer.extend_from_slice(&temp[..n]);
            if buffer.len() > 10_000 { break; } // Limit response size
        }
        Ok::<_, anyhow::Error>(())
    }).await {
        Ok(Ok(())) => {
            // Successfully read response
            Ok(())
        },
        Ok(Err(e)) => Err(e),
        Err(_) => Err(anyhow::anyhow!("HTTP request timed out")),
    }
}

fn parse_target(target: &str) -> Result<(String, u16)> {
    if let Some((host, port_str)) = target.rsplit_once(':') {
        let port = port_str.parse::<u16>()
            .with_context(|| format!("Invalid port in target: {}", target))?;
        Ok((host.to_string(), port))
    } else {
        anyhow::bail!("Target must be in format host:port, got: {}", target);
    }
}

fn output_result(result: &ProbeResult, format: Format) -> Result<()> {
    match format {
        Format::Json => {
            println!("{}", serde_json::to_string_pretty(result)?);
        },
        Format::Human => {
            if result.success {
                println!("✓ Connection successful to {} via {}", result.target, result.adapter_type);
                println!("  Connect time: {}ms", result.connect_time_ms);
                if let Some(total_time) = result.total_time_ms {
                    println!("  Total time: {}ms", total_time);
                }
                if let Some(size) = result.response_size {
                    println!("  Response size: {} bytes", size);
                }
            } else {
                println!("✗ Connection failed to {} via {}", result.target, result.adapter_type);
                if let Some(error) = &result.error {
                    println!("  Error: {}", error);
                }
            }
        },
        Format::Sarif => {
            // SARIF format for static analysis tools (simplified)
            let sarif = serde_json::json!({
                "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0.json",
                "version": "2.1.0",
                "runs": [{
                    "tool": {
                        "driver": {
                            "name": "sb-probe",
                            "version": "0.1.0"
                        }
                    },
                    "results": [{
                        "ruleId": "connectivity-test",
                        "level": if result.success { "note" } else { "error" },
                        "message": {
                            "text": format!("Connection test for {} via {}: {}",
                                result.target, result.adapter_type,
                                if result.success { "SUCCESS" } else { "FAILED" })
                        },
                        "properties": {
                            "connect_time_ms": result.connect_time_ms,
                            "adapter_type": result.adapter_type,
                            "timestamp": result.timestamp
                        }
                    }]
                }]
            });
            println!("{}", serde_json::to_string_pretty(&sarif)?);
        }
    }
    Ok(())
}