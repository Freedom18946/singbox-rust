use anyhow::{Context, Result};
use clap::Parser;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

#[cfg(any(feature = "adapters", feature = "adapter-vless"))]
use sb_adapters::outbound::vless::{Encryption, FlowControl, VlessConfig, VlessConnector};
#[cfg(any(feature = "adapters", feature = "adapter-vless"))]
use sb_adapters::traits::{DialOpts, OutboundConnector as _, Target, TransportKind};
#[cfg(any(feature = "adapters", feature = "adapter-vless"))]
use sb_tls::TlsConnector as _;

#[derive(Parser, Debug)]
#[command(name = "probe-outbound")]
#[command(about = "Probe a named outbound (VMess/VLESS/Trojan) with layered transports", long_about = None)]
struct Args {
    /// Path to config file (YAML/JSON)
    #[arg(long)]
    config: String,
    /// Outbound tag/name to use
    #[arg(long)]
    outbound: String,
    /// Target host:port to connect to through the outbound
    #[arg(long)]
    target: String,
    /// Connection timeout in seconds
    #[arg(long, default_value_t = 10)]
    timeout: u64,
    /// Print derived transport chain for the outbound
    #[arg(long, default_value_t = false)]
    print_transport: bool,
}

enum ProbeStream {
    Raw(TcpStream),
    Layered(sb_transport::IoStream),
}

impl ProbeStream {
    async fn write_all(&mut self, buf: &[u8]) -> std::io::Result<()> {
        match self {
            Self::Raw(stream) => stream.write_all(buf).await,
            Self::Layered(stream) => stream.write_all(buf).await,
        }
    }

    async fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Self::Raw(stream) => stream.read(buf).await,
            Self::Layered(stream) => stream.read(buf).await,
        }
    }

    fn mode(&self) -> &'static str {
        match self {
            Self::Raw(_) => "connect",
            Self::Layered(_) => "connect_io",
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    #[cfg(feature = "tls_reality")]
    sb_tls::ensure_crypto_provider();

    // Load config and convert to IR
    let cfg = sb_config::Config::load(&args.config)
        .with_context(|| format!("load config: {}", &args.config))?;
    let ir = sb_config::present::to_ir(&cfg).context("config -> IR")?;
    let (host, port) = parse_hostport(&args.target)?;

    #[cfg(any(feature = "adapters", feature = "adapter-vless"))]
    let selected_outbound = ir
        .outbounds
        .iter()
        .find(|o| o.name.as_deref() == Some(args.outbound.as_str()));

    #[cfg(any(feature = "adapters", feature = "adapter-vless"))]
    if let Some(outbound) = selected_outbound {
        maybe_probe_vless_direct("pre_bridge", outbound, &host, port, args.timeout).await;
    }

    // Register adapters before bridge assembly.
    register_adapters_once();

    // Build adapter-aware bridge and find outbound.
    let bridge = {
        let engine = sb_core::routing::engine::Engine::new(std::sync::Arc::new(ir.clone()));
        sb_core::adapter::bridge::build_bridge(&ir, engine, sb_core::context::Context::default())
    };

    if args.print_transport {
        #[cfg(feature = "v2ray_transport")]
        {
            if let Some(ob) = ir
                .outbounds
                .iter()
                .find(|o| o.name.as_deref() == Some(args.outbound.as_str()))
            {
                let chain = sb_core::runtime::transport::map::chain_from_ir(ob);
                eprintln!("transport_chain={}", chain.join(","));
            } else {
                eprintln!("outbound not found: {}", args.outbound);
            }
        }
        #[cfg(not(feature = "v2ray_transport"))]
        {
            eprintln!(
                "transport chain inspection requires the `v2ray_transport` feature. \
                 Re-run with `--features v2ray_transport`."
            );
        }
    }

    let connector = bridge
        .get_member(&args.outbound)
        .ok_or_else(|| anyhow::anyhow!("outbound not found: {}", args.outbound))?;

    #[cfg(any(feature = "adapters", feature = "adapter-vless"))]
    if let Some(outbound) = selected_outbound {
        maybe_probe_vless_direct("post_bridge", outbound, &host, port, args.timeout).await;
    }

    // Dial and send a basic HTTP GET to validate end-to-end
    let started = Instant::now();
    let mut stream = match tokio::time::timeout(
        Duration::from_secs(args.timeout),
        connector.connect(&host, port),
    )
    .await
    .map_err(|_| anyhow::anyhow!("connect timeout after {}s", args.timeout))?
    {
        Ok(stream) => ProbeStream::Raw(stream),
        Err(connect_err) => {
            let stream = tokio::time::timeout(
                Duration::from_secs(args.timeout),
                connector.connect_io(&host, port),
            )
            .await
            .map_err(|_| anyhow::anyhow!("connect_io timeout after {}s", args.timeout))?
            .with_context(|| {
                format!("dial outbound via connect_io after connect error: {connect_err}")
            })?;
            ProbeStream::Layered(stream)
        }
    };
    let connected_ms = started.elapsed().as_millis() as u64;

    // Write a GET request
    let req = format!(
        "GET / HTTP/1.1\r\nHost: {}\r\nUser-Agent: singbox-rust/cli\r\nConnection: close\r\n\r\n",
        host
    );
    stream
        .write_all(req.as_bytes())
        .await
        .context("write request")?;

    // Read some response bytes (up to 4 KB)
    let mut buf = vec![0u8; 4096];
    let n = stream.read(&mut buf).await.context("read response")?;

    println!(
        "OK stream_mode={} connect_time_ms={} response_bytes={} first_line={}",
        stream.mode(),
        connected_ms,
        n,
        extract_first_line(&buf[..n])
    );

    Ok(())
}

fn parse_hostport(s: &str) -> Result<(String, u16)> {
    if let Some((h, p)) = s.rsplit_once(':') {
        let port: u16 = p.parse().context("parse port")?;
        Ok((h.to_string(), port))
    } else {
        Err(anyhow::anyhow!("invalid host:port: {}", s))
    }
}

fn extract_first_line(bytes: &[u8]) -> String {
    let s = String::from_utf8_lossy(bytes);
    s.lines().next().unwrap_or("").to_string()
}

#[inline]
fn register_adapters_once() {
    #[cfg(feature = "sb-adapters")]
    sb_adapters::register_all();
}

#[cfg(any(feature = "adapters", feature = "adapter-vless"))]
async fn maybe_probe_vless_direct(
    phase: &'static str,
    outbound: &sb_config::ir::OutboundIR,
    host: &str,
    port: u16,
    timeout_secs: u64,
) {
    if outbound.ty != sb_config::ir::OutboundType::Vless {
        return;
    }

    let Some(server) = outbound.server.clone() else {
        eprintln!("direct_vless_dial phase={phase} result=skip reason=missing_server");
        return;
    };
    let Some(server_port) = outbound.port else {
        eprintln!("direct_vless_dial phase={phase} result=skip reason=missing_port");
        return;
    };
    let Some(uuid_raw) = outbound.uuid.as_deref() else {
        eprintln!("direct_vless_dial phase={phase} result=skip reason=missing_uuid");
        return;
    };
    let uuid = match uuid::Uuid::parse_str(uuid_raw) {
        Ok(uuid) => uuid,
        Err(error) => {
            eprintln!("direct_vless_dial phase={phase} result=skip reason=bad_uuid error={error}");
            return;
        }
    };
    if outbound
        .transport
        .as_ref()
        .is_some_and(|entries| !entries.is_empty())
    {
        eprintln!("direct_vless_dial phase={phase} result=skip reason=non_tcp_transport");
        return;
    }

    let flow = match outbound.flow.as_deref() {
        Some("xtls-rprx-vision") => FlowControl::XtlsRprxVision,
        Some("xtls-rprx-direct") => FlowControl::XtlsRprxDirect,
        _ => FlowControl::None,
    };
    let encryption = match outbound.encryption.as_deref() {
        Some("aes-128-gcm") => Encryption::Aes128Gcm,
        Some("chacha20-poly1305") | Some("chacha20-ietf-poly1305") => Encryption::ChaCha20Poly1305,
        _ => Encryption::None,
    };
    let reality = if outbound.reality_enabled.unwrap_or(false) {
        outbound
            .reality_public_key
            .as_ref()
            .map(|public_key| sb_tls::RealityClientConfig {
                target: outbound
                    .reality_server_name
                    .clone()
                    .or_else(|| outbound.tls_sni.clone())
                    .unwrap_or_else(|| server.clone()),
                server_name: outbound
                    .reality_server_name
                    .clone()
                    .or_else(|| outbound.tls_sni.clone())
                    .unwrap_or_else(|| server.clone()),
                public_key: public_key.clone(),
                short_id: outbound.reality_short_id.clone(),
                fingerprint: outbound
                    .utls_fingerprint
                    .clone()
                    .unwrap_or_else(|| "chrome".to_string()),
                alpn: outbound.tls_alpn.clone().unwrap_or_default(),
            })
    } else {
        None
    };
    if let Some(reality_config) = reality.as_ref() {
        eprintln!(
            "direct_vless_config phase={phase} server={server} port={server_port} sni={} fp={} short_id_len={} alpn_len={}",
            reality_config.server_name,
            reality_config.fingerprint,
            reality_config.short_id.as_deref().unwrap_or_default().len(),
            reality_config.alpn.len()
        );
        let started = Instant::now();
        let result = tokio::time::timeout(Duration::from_secs(timeout_secs), async {
            let stream = TcpStream::connect((server.as_str(), server_port)).await?;
            let connector = sb_tls::RealityConnector::new(reality_config.clone())?;
            let _tls = connector
                .connect(stream, &reality_config.server_name)
                .await?;
            Result::<(), Box<dyn std::error::Error + Send + Sync>>::Ok(())
        })
        .await;
        match result {
            Ok(Ok(())) => eprintln!(
                "direct_reality phase={phase} result=ok elapsed_ms={}",
                started.elapsed().as_millis()
            ),
            Ok(Err(error)) => eprintln!(
                "direct_reality phase={phase} result=err elapsed_ms={} error={}",
                started.elapsed().as_millis(),
                error
            ),
            Err(_) => eprintln!(
                "direct_reality phase={phase} result=timeout elapsed_ms={}",
                started.elapsed().as_millis()
            ),
        }
    } else {
        eprintln!("direct_reality phase={phase} result=skip reason=no_reality_config");
    }

    let connector = VlessConnector::new(VlessConfig {
        server,
        port: server_port,
        uuid,
        flow,
        encryption,
        headers: std::collections::HashMap::new(),
        timeout: Some(30),
        tcp_fast_open: false,
        transport_layer: sb_adapters::transport_config::TransportConfig::Tcp,
        multiplex: None,
        #[cfg(feature = "tls_reality")]
        reality,
        #[cfg(feature = "transport_ech")]
        ech: None,
    });
    let target = Target {
        host: host.to_string(),
        port,
        kind: TransportKind::Tcp,
    };

    let started = Instant::now();
    match tokio::time::timeout(
        Duration::from_secs(timeout_secs),
        connector.dial(target, DialOpts::new()),
    )
    .await
    {
        Ok(Ok(_)) => eprintln!(
            "direct_vless_dial phase={phase} result=ok elapsed_ms={}",
            started.elapsed().as_millis()
        ),
        Ok(Err(error)) => eprintln!(
            "direct_vless_dial phase={phase} result=err elapsed_ms={} error={}",
            started.elapsed().as_millis(),
            error
        ),
        Err(_) => eprintln!(
            "direct_vless_dial phase={phase} result=timeout elapsed_ms={}",
            started.elapsed().as_millis()
        ),
    }
}
