//! SOCKS4 outbound connector implementation  
//! SOCKS4 出站连接器实现
//!
//! This module provides SOCKS4 proxy support for outbound connections.
//! 本模块为出站连接提供 SOCKS4 代理支持。
//! Implements SOCKS4 protocol as defined in RFC 1928 precursor.
//! 实现 SOCKS4 协议（RFC 1928 的前身）。
//!
//! ## SOCKS4 vs SOCKS5
//! - SOCKS4: IPv4 only, CONNECT only, optional user ID
//! - SOCKS5: IPv4/IPv6/Domain, CONNECT/BIND/UDP, authentication methods
//!
//! ## SOCKS4a Extension
//! SOCKS4a adds domain name support by sending 0.0.0.x as IP,
//! followed by null-terminated domain name.

use crate::outbound::prelude::*;
use crate::traits::ResolveMode;
use anyhow::Context;
use std::net::{IpAddr, SocketAddr};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use sb_config::outbound::Socks4Config;

/// SOCKS4 outbound connector
/// SOCKS4 出站连接器
#[derive(Debug, Clone)]
pub struct Socks4Connector {
    config: Socks4Config,
}

impl Socks4Connector {
    pub fn new(config: Socks4Config) -> Self {
        Self { config }
    }

    /// Create a connector with no user ID
    /// 创建无用户 ID 的连接器
    pub fn no_auth(server: impl Into<String>) -> Self {
        Self {
            config: Socks4Config {
                server: server.into(),
                tag: None,
                user_id: None,
                connect_timeout_sec: Some(30),
            },
        }
    }

    /// Create a connector with user ID
    /// 创建带用户 ID 的连接器
    pub fn with_user_id(server: impl Into<String>, user_id: impl Into<String>) -> Self {
        Self {
            config: Socks4Config {
                server: server.into(),
                tag: None,
                user_id: Some(user_id.into()),
                connect_timeout_sec: Some(30),
            },
        }
    }
}

impl Default for Socks4Connector {
    fn default() -> Self {
        Self::no_auth("127.0.0.1:1080")
    }
}

#[async_trait]
impl OutboundConnector for Socks4Connector {
    fn name(&self) -> &'static str {
        "socks4"
    }

    async fn start(&self) -> Result<()> {
        Ok(())
    }

    async fn dial(&self, target: Target, opts: DialOpts) -> Result<BoxedStream> {
        let _span = crate::outbound::span_dial("socks4", &target);

        // Start metrics timing
        #[cfg(feature = "metrics")]
        let start_time = sb_metrics::start_adapter_timer();

        // SOCKS4 only supports TCP
        if target.kind != TransportKind::Tcp {
            return Err(AdapterError::Protocol(
                "SOCKS4 only supports TCP connections".to_string(),
            ));
        }

        let dial_result = async {
            // Parse proxy server address
            let proxy_addr: SocketAddr = self
                .config
                .server
                .parse()
                .with_context(|| format!("Invalid SOCKS4 proxy address: {}", self.config.server))
                .map_err(|e| AdapterError::Other(e.to_string()))?;

            // Connect to proxy server with timeout
            let mut stream =
                tokio::time::timeout(opts.connect_timeout, TcpStream::connect(proxy_addr))
                    .await
                    .with_context(|| format!("Failed to connect to SOCKS4 proxy {}", proxy_addr))
                    .map_err(|e| AdapterError::Other(e.to_string()))?
                    .with_context(|| {
                        format!("TCP connection to SOCKS4 proxy {} failed", proxy_addr)
                    })
                    .map_err(|e| AdapterError::Other(e.to_string()))?;

            // Perform SOCKS4/SOCKS4a handshake
            self.socks4_connect(&mut stream, &target, &opts).await?;

            Ok(Box::new(stream) as BoxedStream)
        }
        .await;

        // Record metrics
        #[cfg(feature = "metrics")]
        {
            let result = match &dial_result {
                Ok(_) => Ok(()),
                Err(e) => Err(e as &dyn core::fmt::Display),
            };
            sb_metrics::record_adapter_dial("socks4", start_time, result);
        }

        // Handle result
        match dial_result {
            Ok(stream) => {
                tracing::debug!(
                    server = %self.config.server,
                    target = %format!("{}:{}", target.host, target.port),
                    has_user_id = %self.config.user_id.is_some(),
                    "SOCKS4 connection established"
                );
                Ok(stream)
            }
            Err(e) => {
                tracing::debug!(
                    server = %self.config.server,
                    target = %format!("{}:{}", target.host, target.port),
                    has_user_id = %self.config.user_id.is_some(),
                    error = %e,
                    "SOCKS4 connection failed"
                );
                Err(e)
            }
        }
    }
}

impl Socks4Connector {
    /// Perform SOCKS4 CONNECT request
    /// 执行 SOCKS4 CONNECT 请求
    async fn socks4_connect(
        &self,
        stream: &mut TcpStream,
        target: &Target,
        opts: &DialOpts,
    ) -> Result<()> {
        // Determine if we need SOCKS4a (for domain names)
        let use_socks4a = target.host.parse::<IpAddr>().is_err();

        // Build SOCKS4/4a request
        let mut request = Vec::new();

        // Version (1 byte): 0x04
        request.push(0x04);

        // Command (1 byte): 0x01 = CONNECT
        request.push(0x01);

        // Port (2 bytes, big endian)
        request.extend_from_slice(&target.port.to_be_bytes());

        // IP address (4 bytes)
        if use_socks4a {
            // SOCKS4a: Use 0.0.0.x (x != 0) to indicate domain name follows
            // We use 0.0.0.1 as the marker IP
            request.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]);
        } else {
            // SOCKS4: Direct IPv4 address (resolve first if needed)
            let ipv4 = match opts.resolve_mode {
                ResolveMode::Local => {
                    // Resolve locally
                    let ip = target.host.parse::<IpAddr>().map_err(|_| {
                        AdapterError::Network(format!("Failed to parse IP: {}", target.host))
                    })?;

                    match ip {
                        IpAddr::V4(ipv4) => ipv4,
                        IpAddr::V6(_) => {
                            return Err(AdapterError::Protocol(
                                "SOCKS4 does not support IPv6".to_string(),
                            ))
                        }
                    }
                }
                ResolveMode::Remote => {
                    // For SOCKS4 without 4a support, we must resolve locally
                    // Try to parse as IP first

                    if let Ok(ip) = target.host.parse::<IpAddr>() {
                        match ip {
                            IpAddr::V4(ipv4) => ipv4,
                            IpAddr::V6(_) => {
                                return Err(AdapterError::Protocol(
                                    "SOCKS4 does not support IPv6".to_string(),
                                ))
                            }
                        }
                    } else {
                        // Must use SOCKS4a for remote resolution
                        return Err(AdapterError::Protocol(
                            "SOCKS4 requires local DNS resolution or SOCKS4a for domains"
                                .to_string(),
                        ));
                    }
                }
            };

            request.extend_from_slice(&ipv4.octets());
        }

        // User ID (null-terminated string)
        if let Some(ref user_id) = self.config.user_id {
            request.extend_from_slice(user_id.as_bytes());
        }
        request.push(0x00); // Null terminator

        // SOCKS4a: Domain name (null-terminated string)
        if use_socks4a {
            request.extend_from_slice(target.host.as_bytes());
            request.push(0x00); // Null terminator
        }

        // Send SOCKS4 request
        tokio::time::timeout(opts.connect_timeout, stream.write_all(&request))
            .await
            .map_err(|_| {
                AdapterError::Io(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "SOCKS4 request write timeout",
                ))
            })??;

        // Read SOCKS4 response (8 bytes)
        let mut response = [0u8; 8];
        tokio::time::timeout(opts.connect_timeout, stream.read_exact(&mut response))
            .await
            .map_err(|_| {
                AdapterError::Io(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "SOCKS4 response read timeout",
                ))
            })??;

        // Parse response
        // Byte 0: should be 0x00 (reply version)
        if response[0] != 0x00 {
            return Err(AdapterError::Protocol(format!(
                "Invalid SOCKS4 response version: {}",
                response[0]
            )));
        }

        // Byte 1: status code
        match response[1] {
            0x5A => {
                // Request granted
                tracing::debug!("SOCKS4 CONNECT successful");
                Ok(())
            }
            0x5B => Err(AdapterError::Protocol(
                "SOCKS4: Request rejected or failed".to_string(),
            )),
            0x5C => Err(AdapterError::Protocol(
                "SOCKS4: Cannot connect to identd".to_string(),
            )),
            0x5D => Err(AdapterError::Protocol(
                "SOCKS4: Identd user ID mismatch".to_string(),
            )),
            code => Err(AdapterError::Protocol(format!(
                "SOCKS4: Unknown status code: 0x{:02X}",
                code
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_socks4_connector_creation() {
        let config = Socks4Config {
            server: "127.0.0.1:1080".to_string(),
            tag: Some("test".to_string()),
            user_id: None,
            connect_timeout_sec: Some(30),
        };

        let connector = Socks4Connector::new(config);
        assert_eq!(connector.name(), "socks4");
    }

    #[test]
    fn test_socks4_connector_no_auth() {
        let connector = Socks4Connector::no_auth("127.0.0.1:1080");
        assert!(connector.config.user_id.is_none());
        assert_eq!(connector.config.server, "127.0.0.1:1080");
    }

    #[test]
    fn test_socks4_connector_with_user_id() {
        let connector = Socks4Connector::with_user_id("127.0.0.1:1080", "testuser");
        assert_eq!(connector.config.user_id.as_deref(), Some("testuser"));
    }
}
