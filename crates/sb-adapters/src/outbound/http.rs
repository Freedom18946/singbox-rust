//! HTTP proxy outbound implementation
//!
//! This module provides HTTP CONNECT proxy support for outbound connections.
//! It implements the HTTP CONNECT method as defined in RFC 7231 Section 4.3.6.

use crate::outbound::prelude::*;
use crate::traits::ResolveMode;
use anyhow::Context;
use base64::prelude::*;
use std::net::{IpAddr, SocketAddr};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

#[cfg(feature = "http-tls")]
use rustls_pki_types::ServerName;
#[cfg(feature = "http-tls")]
use tokio_rustls::{rustls::ClientConfig, TlsConnector};

use sb_config::outbound::HttpProxyConfig;

/// HTTP proxy outbound connector
#[derive(Debug, Clone)]
pub struct HttpProxyConnector {
    config: HttpProxyConfig,
    use_tls: bool,
    #[cfg(feature = "transport_ech")]
    #[allow(dead_code)]
    ech_config: Option<sb_tls::EchClientConfig>,
}

impl HttpProxyConnector {
    pub fn new(config: HttpProxyConfig) -> Self {
        #[cfg(feature = "transport_ech")]
        let ech_config = config
            .tls
            .as_ref()
            .and_then(|tls| tls.ech.as_ref())
            .filter(|ech| ech.enabled)
            .map(|ech| sb_tls::EchClientConfig {
                enabled: ech.enabled,
                config: ech.config.clone(),
                config_list: None, // Will be decoded from config
                pq_signature_schemes_enabled: ech.pq_signature_schemes_enabled,
                dynamic_record_sizing_disabled: ech.dynamic_record_sizing_disabled,
            });

        Self {
            config,
            use_tls: false,
            #[cfg(feature = "transport_ech")]
            ech_config,
        }
    }

    /// Create a connector with TLS support
    #[cfg(feature = "http-tls")]
    pub fn with_tls(config: HttpProxyConfig) -> Self {
        #[cfg(feature = "transport_ech")]
        let ech_config = config
            .tls
            .as_ref()
            .and_then(|tls| tls.ech.as_ref())
            .filter(|ech| ech.enabled)
            .map(|ech| sb_tls::EchClientConfig {
                enabled: ech.enabled,
                config: ech.config.clone(),
                config_list: None,
                pq_signature_schemes_enabled: ech.pq_signature_schemes_enabled,
                dynamic_record_sizing_disabled: ech.dynamic_record_sizing_disabled,
            });

        Self {
            config,
            use_tls: true,
            #[cfg(feature = "transport_ech")]
            ech_config,
        }
    }

    /// Create a connector with no authentication
    pub fn no_auth(server: impl Into<String>) -> Self {
        Self {
            config: HttpProxyConfig {
                server: server.into(),
                tag: None,
                username: None,
                password: None,
                connect_timeout_sec: Some(30),
                tls: None,
            },
            use_tls: false,
            #[cfg(feature = "transport_ech")]
            ech_config: None,
        }
    }

    /// Create a TLS connector with no authentication
    #[cfg(feature = "http-tls")]
    pub fn no_auth_tls(server: impl Into<String>) -> Self {
        Self {
            config: HttpProxyConfig {
                server: server.into(),
                tag: None,
                username: None,
                password: None,
                connect_timeout_sec: Some(30),
                tls: None,
            },
            use_tls: true,
            #[cfg(feature = "transport_ech")]
            ech_config: None,
        }
    }

    /// Create a connector with username/password authentication
    pub fn with_auth(
        server: impl Into<String>,
        username: impl Into<String>,
        password: impl Into<String>,
    ) -> Self {
        Self {
            config: HttpProxyConfig {
                server: server.into(),
                tag: None,
                username: Some(username.into()),
                password: Some(password.into()),
                connect_timeout_sec: Some(30),
                tls: None,
            },
            use_tls: false,
            #[cfg(feature = "transport_ech")]
            ech_config: None,
        }
    }

    /// Create a TLS connector with username/password authentication
    #[cfg(feature = "http-tls")]
    pub fn with_auth_tls(
        server: impl Into<String>,
        username: impl Into<String>,
        password: impl Into<String>,
    ) -> Self {
        Self {
            config: HttpProxyConfig {
                server: server.into(),
                tag: None,
                username: Some(username.into()),
                password: Some(password.into()),
                connect_timeout_sec: Some(30),
                tls: None,
            },
            use_tls: true,
            #[cfg(feature = "transport_ech")]
            ech_config: None,
        }
    }
}

impl Default for HttpProxyConnector {
    fn default() -> Self {
        Self::no_auth("127.0.0.1:8080")
    }
}

#[async_trait]
impl OutboundConnector for HttpProxyConnector {
    fn name(&self) -> &'static str {
        "http"
    }

    async fn start(&self) -> Result<()> {
        #[cfg(not(feature = "adapter-http"))]
        return Err(AdapterError::NotImplemented {
            what: "adapter-http",
        });

        #[cfg(feature = "adapter-http")]
        Ok(())
    }

    async fn dial(&self, target: Target, opts: DialOpts) -> Result<BoxedStream> {
        #[cfg(not(feature = "adapter-http"))]
        return Err(AdapterError::NotImplemented {
            what: "adapter-http",
        });

        #[cfg(feature = "adapter-http")]
        {
            let _span = crate::outbound::span_dial("http", &target);

            // Start metrics timing
            #[cfg(feature = "metrics")]
            let start_time = sb_metrics::start_adapter_timer();

            if target.kind != TransportKind::Tcp {
                return Err(AdapterError::Protocol(
                    "HTTP proxy only supports TCP".to_string(),
                ));
            }

            let dial_result = async {
                if self.use_tls {
                    #[cfg(not(feature = "http-tls"))]
                    return Err(AdapterError::NotImplemented { what: "http-tls" });

                    #[cfg(feature = "http-tls")]
                    {
                        // Parse proxy server address (host:port)
                        let proxy_url = if !self.config.server.contains("://") {
                            format!("https://{}", self.config.server)
                        } else {
                            self.config.server.clone()
                        };

                        let url = url::Url::parse(&proxy_url)
                            .with_context(|| format!("Invalid HTTPS proxy URL: {}", proxy_url))
                            .map_err(|e| AdapterError::Other(e.to_string()))?;

                        let host = url.host_str().ok_or({
                            AdapterError::InvalidConfig("HTTPS proxy URL missing host")
                        })?;
                        let port = url.port().unwrap_or(443);
                        let proxy_addr = SocketAddr::new(
                            host.parse()
                                .map_err(|_| AdapterError::InvalidConfig("Invalid proxy host"))?,
                            port,
                        );

                        // Connect to proxy server with timeout
                        let tcp_stream = tokio::time::timeout(
                            opts.connect_timeout,
                            TcpStream::connect(proxy_addr),
                        )
                        .await
                        .with_context(|| format!("Failed to connect to HTTPS proxy {}", proxy_addr))
                        .map_err(|e| AdapterError::Other(e.to_string()))?
                        .with_context(|| {
                            format!("TCP connection to HTTPS proxy {} failed", proxy_addr)
                        })
                        .map_err(|e| AdapterError::Other(e.to_string()))?;

                        // Create TLS config
                        let root_store = tokio_rustls::rustls::RootCertStore {
                            roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
                        };

                        let config = ClientConfig::builder()
                            .with_root_certificates(root_store)
                            .with_no_client_auth();

                        let connector = TlsConnector::from(Arc::new(config));

                        let server_name = ServerName::try_from(host)
                            .map_err(|_| {
                                AdapterError::InvalidConfig("Invalid server name for TLS")
                            })?
                            .to_owned();

                        // Perform TLS handshake
                        let tls_stream = tokio::time::timeout(
                            opts.connect_timeout,
                            connector.connect(server_name, tcp_stream),
                        )
                        .await
                        .with_context(|| format!("TLS handshake timeout with HTTPS proxy {}", host))
                        .map_err(|e| AdapterError::Other(e.to_string()))?
                        .with_context(|| format!("TLS handshake failed with HTTPS proxy {}", host))
                        .map_err(|e| AdapterError::Other(e.to_string()))?;

                        // Send HTTP CONNECT request over TLS
                        let mut boxed_stream = Box::new(tls_stream) as BoxedStream;
                        self.http_connect_generic(&mut boxed_stream, &target, &opts)
                            .await?;

                        // Return the TLS stream
                        Ok(boxed_stream)
                    }
                } else {
                    // Regular HTTP proxy
                    let proxy_addr: SocketAddr = self
                        .config
                        .server
                        .parse()
                        .with_context(|| {
                            format!("Invalid HTTP proxy address: {}", self.config.server)
                        })
                        .map_err(|e| AdapterError::Other(e.to_string()))?;

                    // Connect to proxy server with timeout
                    let mut stream =
                        tokio::time::timeout(opts.connect_timeout, TcpStream::connect(proxy_addr))
                            .await
                            .with_context(|| {
                                format!("Failed to connect to HTTP proxy {}", proxy_addr)
                            })
                            .map_err(|e| AdapterError::Other(e.to_string()))?
                            .with_context(|| {
                                format!("TCP connection to HTTP proxy {} failed", proxy_addr)
                            })
                            .map_err(|e| AdapterError::Other(e.to_string()))?;

                    // Send HTTP CONNECT request
                    self.http_connect(&mut stream, &target, &opts).await?;

                    // Return the connected stream
                    Ok(Box::new(stream) as BoxedStream)
                }
            }
            .await;

            // Record metrics for the dial attempt (both success and failure)
            #[cfg(feature = "metrics")]
            {
                let result = match &dial_result {
                    Ok(_) => Ok(()),
                    Err(e) => Err(e as &dyn core::fmt::Display),
                };
                sb_metrics::record_adapter_dial("http", start_time, result);
            }

            // Handle the result
            match dial_result {
                Ok(stream) => {
                    tracing::debug!(
                        server = %self.config.server,
                        target = %format!("{}:{}", target.host, target.port),
                        has_auth = %self.config.username.is_some(),
                        use_tls = %self.use_tls,
                        "HTTP connection established"
                    );
                    Ok(stream)
                }
                Err(e) => {
                    tracing::debug!(
                        server = %self.config.server,
                        target = %format!("{}:{}", target.host, target.port),
                        has_auth = %self.config.username.is_some(),
                        use_tls = %self.use_tls,
                        error = %e,
                        "HTTP connection failed"
                    );
                    Err(e)
                }
            }
        }
    }
}

#[cfg(feature = "adapter-http")]
impl HttpProxyConnector {
    /// Send HTTP CONNECT request and parse response
    async fn http_connect(
        &self,
        stream: &mut TcpStream,
        target: &Target,
        opts: &DialOpts,
    ) -> Result<()> {
        // Determine target address based on resolve mode
        let (connect_host, host_header) = match opts.resolve_mode {
            ResolveMode::Local => {
                // Resolve locally first, but still send original hostname in Host header
                if let Ok(ip) = target.host.parse::<IpAddr>() {
                    // Already an IP address
                    (ip.to_string(), target.host.clone())
                } else {
                    // Domain name - resolve locally
                    match tokio::net::lookup_host((target.host.clone(), target.port)).await {
                        Ok(mut addrs) => {
                            if let Some(addr) = addrs.next() {
                                (addr.ip().to_string(), target.host.clone())
                            } else {
                                return Err(AdapterError::Network(format!(
                                    "Failed to resolve {}",
                                    target.host
                                )));
                            }
                        }
                        Err(e) => {
                            return Err(AdapterError::Network(format!(
                                "DNS resolution failed for {}: {}",
                                target.host, e
                            )));
                        }
                    }
                }
            }
            ResolveMode::Remote => {
                // Send original hostname to proxy for remote resolution
                (target.host.clone(), target.host.clone())
            }
        };

        // Build HTTP CONNECT request
        let mut request = format!(
            "CONNECT {}:{} HTTP/1.1\r\nHost: {}:{}\r\n",
            connect_host, target.port, host_header, target.port
        );

        // Add Proxy-Authorization header if credentials are provided
        if let (Some(username), Some(password)) = (&self.config.username, &self.config.password) {
            let credentials = format!("{}:{}", username, password);
            let encoded = BASE64_STANDARD.encode(credentials.as_bytes());
            request.push_str(&format!("Proxy-Authorization: Basic {}\r\n", encoded));
        }

        // Add Connection header and end request
        request.push_str("Connection: keep-alive\r\n\r\n");

        // Send request with timeout
        tokio::time::timeout(opts.connect_timeout, stream.write_all(request.as_bytes()))
            .await
            .map_err(|_| {
                AdapterError::Io(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "HTTP request write timeout",
                ))
            })??;

        // Read and parse response
        let mut reader = BufReader::new(stream);
        let mut status_line = String::new();

        tokio::time::timeout(opts.connect_timeout, reader.read_line(&mut status_line))
            .await
            .map_err(|_| {
                AdapterError::Io(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "HTTP response read timeout",
                ))
            })??;

        // Parse HTTP status line
        let parts: Vec<&str> = status_line.split_whitespace().collect();
        if parts.len() < 3 {
            return Err(AdapterError::Protocol(
                "Invalid HTTP response format".to_string(),
            ));
        }

        let status_code = parts[1];
        if status_code != "200" {
            return Err(AdapterError::Protocol(format!(
                "HTTP CONNECT failed: {} {}",
                status_code,
                parts.get(2).unwrap_or(&"")
            )));
        }

        // Skip remaining headers until empty line
        loop {
            let mut header_line = String::new();
            tokio::time::timeout(opts.connect_timeout, reader.read_line(&mut header_line))
                .await
                .map_err(|_| {
                    AdapterError::Io(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "HTTP headers read timeout",
                    ))
                })??;

            if header_line.trim().is_empty() {
                break; // End of headers
            }
        }

        Ok(())
    }

    /// Send HTTP CONNECT request on a generic stream (works with both TCP and TLS)
    #[allow(dead_code)]
    async fn http_connect_generic(
        &self,
        stream: &mut BoxedStream,
        target: &Target,
        opts: &DialOpts,
    ) -> Result<()> {
        // Determine target address based on resolve mode
        let (connect_host, host_header) = match opts.resolve_mode {
            ResolveMode::Local => {
                // Resolve locally first, but still send original hostname in Host header
                if let Ok(ip) = target.host.parse::<IpAddr>() {
                    // Already an IP address
                    (ip.to_string(), target.host.clone())
                } else {
                    // Domain name - resolve locally
                    match tokio::net::lookup_host((target.host.clone(), target.port)).await {
                        Ok(mut addrs) => {
                            if let Some(addr) = addrs.next() {
                                (addr.ip().to_string(), target.host.clone())
                            } else {
                                return Err(AdapterError::Network(format!(
                                    "Failed to resolve {}",
                                    target.host
                                )));
                            }
                        }
                        Err(e) => {
                            return Err(AdapterError::Network(format!(
                                "DNS resolution failed for {}: {}",
                                target.host, e
                            )));
                        }
                    }
                }
            }
            ResolveMode::Remote => {
                // Send original hostname to proxy for remote resolution
                (target.host.clone(), target.host.clone())
            }
        };

        // Build HTTP CONNECT request
        let mut request = format!(
            "CONNECT {}:{} HTTP/1.1\r\nHost: {}:{}\r\n",
            connect_host, target.port, host_header, target.port
        );

        // Add Proxy-Authorization header if credentials are provided
        if let (Some(username), Some(password)) = (&self.config.username, &self.config.password) {
            let credentials = format!("{}:{}", username, password);
            let encoded = BASE64_STANDARD.encode(credentials.as_bytes());
            request.push_str(&format!("Proxy-Authorization: Basic {}\r\n", encoded));
        }

        // Add Connection header and end request
        request.push_str("Connection: keep-alive\r\n\r\n");

        // Send request with timeout
        tokio::time::timeout(opts.connect_timeout, stream.write_all(request.as_bytes()))
            .await
            .map_err(|_| {
                AdapterError::Io(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "HTTPS request write timeout",
                ))
            })??;

        // Read and parse response
        let mut reader = BufReader::new(stream);
        let mut status_line = String::new();

        tokio::time::timeout(opts.connect_timeout, reader.read_line(&mut status_line))
            .await
            .map_err(|_| {
                AdapterError::Io(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "HTTPS response read timeout",
                ))
            })??;

        // Parse HTTP status line
        let parts: Vec<&str> = status_line.split_whitespace().collect();
        if parts.len() < 3 {
            return Err(AdapterError::Protocol(
                "Invalid HTTPS response format".to_string(),
            ));
        }

        let status_code = parts[1];
        if status_code != "200" {
            return Err(AdapterError::Protocol(format!(
                "HTTPS CONNECT failed: {} {}",
                status_code,
                parts.get(2).unwrap_or(&"")
            )));
        }

        // Skip remaining headers until empty line
        loop {
            let mut header_line = String::new();
            tokio::time::timeout(opts.connect_timeout, reader.read_line(&mut header_line))
                .await
                .map_err(|_| {
                    AdapterError::Io(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "HTTPS headers read timeout",
                    ))
                })??;

            if header_line.trim().is_empty() {
                break; // End of headers
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_http_connector_creation() {
        let config = HttpProxyConfig {
            server: "127.0.0.1:8080".to_string(),
            tag: Some("test".to_string()),
            username: None,
            password: None,
            connect_timeout_sec: Some(30),
            tls: None,
        };

        let connector = HttpProxyConnector::new(config);
        assert_eq!(connector.name(), "http");
    }
}
