//! Direct outbound connector implementation
//!
//! This module provides a direct connection implementation of OutboundConnector
//! that connects directly to targets without any proxy.

use crate::{
    error::{ErrorClass, SbError, SbResult},
    outbound::traits::{OutboundConnector as AsyncOutboundConnector, UdpTransport},
    types::{ConnCtx, Endpoint, Host},
};
use async_trait::async_trait;
use std::net::SocketAddr;
use tokio::net::{lookup_host, TcpStream, UdpSocket};
use tokio::time::{timeout, Duration};

/// Direct outbound connector that connects directly to targets
#[derive(Debug, Clone)]
pub struct DirectConnector {
    connect_timeout: Duration,
}

impl DirectConnector {
    /// Create a new direct connector with default timeout
    pub fn new() -> Self {
        Self {
            connect_timeout: Duration::from_secs(10),
        }
    }

    /// Create a new direct connector with custom timeout
    pub fn with_timeout(connect_timeout: Duration) -> Self {
        Self { connect_timeout }
    }

    /// Resolve endpoint to socket address
    async fn resolve_endpoint(&self, endpoint: &Endpoint) -> SbResult<SocketAddr> {
        match &endpoint.host {
            Host::Ip(ip) => Ok(SocketAddr::new(*ip, endpoint.port)),
            Host::Name(domain) => {
                let addr_str = format!("{}:{}", domain, endpoint.port);
                let mut addrs = lookup_host(&addr_str).await.map_err(|e| {
                    SbError::network(
                        ErrorClass::Connection,
                        format!("DNS resolution failed: {}", e),
                    )
                })?;

                addrs.next().ok_or_else(|| {
                    SbError::network(
                        ErrorClass::Connection,
                        "No addresses resolved for domain".to_string(),
                    )
                })
            }
        }
    }
}

impl Default for DirectConnector {
    fn default() -> Self {
        Self::new()
    }
}

// Implementation for the async OutboundConnector trait
#[async_trait]
impl AsyncOutboundConnector for DirectConnector {
    async fn connect_tcp(&self, ctx: &ConnCtx) -> SbResult<TcpStream> {
        // Global backpressure via semaphore
        let (sem, q_ms) = global_limiters();
        let _permit = tokio::time::timeout(Duration::from_millis(q_ms), sem.acquire())
            .await
            .map_err(|_| SbError::timeout("outbound_queue", q_ms))
            .and_then(|r| {
                r.map_err(|_| SbError::Canceled {
                    operation: "acquire_semaphore".to_string(),
                })
            })?;
        let addr = self.resolve_endpoint(&ctx.dst).await?;

        let stream = timeout(self.connect_timeout, TcpStream::connect(addr))
            .await
            .map_err(|_| SbError::timeout("tcp_connect", self.connect_timeout.as_millis() as u64))?
            .map_err(|e| {
                SbError::network(
                    ErrorClass::Connection,
                    format!("TCP connection failed: {}", e),
                )
            })?;

        Ok(stream)
    }

    async fn connect_udp(&self, ctx: &ConnCtx) -> SbResult<Box<dyn UdpTransport>> {
        let addr = self.resolve_endpoint(&ctx.dst).await?;

        // For UDP, we create a socket and connect it to the target
        let socket = UdpSocket::bind("0.0.0.0:0").await.map_err(|e| {
            SbError::network(ErrorClass::Connection, format!("UDP bind failed: {}", e))
        })?;

        socket.connect(addr).await.map_err(|e| {
            SbError::network(ErrorClass::Connection, format!("UDP connect failed: {}", e))
        })?;

        Ok(Box::new(DirectUdpTransport::new(socket)))
    }
}

fn global_limiters() -> (&'static tokio::sync::Semaphore, u64) {
    use std::sync::OnceLock;
    static SEM: OnceLock<tokio::sync::Semaphore> = OnceLock::new();
    let max = std::env::var("SB_OUT_MAX_CONCURRENCY")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(256)
        .max(1);
    let q_ms = std::env::var("SB_OUT_QUEUE_MS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(5_000);
    let sem = SEM.get_or_init(|| tokio::sync::Semaphore::new(max));
    (sem, q_ms)
}

/// Direct UDP transport implementation
pub struct DirectUdpTransport {
    socket: UdpSocket,
}

impl DirectUdpTransport {
    fn new(socket: UdpSocket) -> Self {
        Self { socket }
    }
}

#[async_trait]
impl UdpTransport for DirectUdpTransport {
    async fn send_to(&self, buf: &[u8], dst: &Endpoint) -> SbResult<usize> {
        // For connected UDP socket, we can use send instead of send_to
        // But we'll implement send_to for flexibility
        let addr = match &dst.host {
            Host::Ip(ip) => SocketAddr::new(*ip, dst.port),
            Host::Name(domain) => {
                let addr_str = format!("{}:{}", domain, dst.port);
                let mut addrs = lookup_host(&addr_str).await.map_err(|e| {
                    SbError::network(
                        ErrorClass::Connection,
                        format!("DNS resolution failed: {}", e),
                    )
                })?;

                addrs.next().ok_or_else(|| {
                    SbError::network(
                        ErrorClass::Connection,
                        "No addresses resolved for domain".to_string(),
                    )
                })?
            }
        };

        self.socket.send_to(buf, addr).await.map_err(|e| {
            SbError::network(ErrorClass::Connection, format!("UDP send failed: {}", e))
        })
    }

    async fn recv_from(&self, buf: &mut [u8]) -> SbResult<(usize, SocketAddr)> {
        self.socket.recv_from(buf).await.map_err(|e| {
            SbError::network(ErrorClass::Connection, format!("UDP recv failed: {}", e))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Host;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn test_direct_connector_creation() {
        let connector = DirectConnector::new();
        assert_eq!(connector.connect_timeout, Duration::from_secs(10));

        let connector = DirectConnector::with_timeout(Duration::from_secs(5));
        assert_eq!(connector.connect_timeout, Duration::from_secs(5));
    }

    #[tokio::test]
    async fn test_resolve_endpoint_ip() {
        let connector = DirectConnector::new();
        let endpoint = Endpoint::new(Host::ip(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))), 8080);

        let result = connector.resolve_endpoint(&endpoint).await;
        assert!(result.is_ok());
        let addr = result.unwrap();
        assert_eq!(addr.ip(), IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
        assert_eq!(addr.port(), 8080);
    }

    #[tokio::test]
    async fn test_resolve_endpoint_domain() {
        let connector = DirectConnector::new();
        let endpoint = Endpoint::new(Host::domain("localhost"), 8080);

        let result = connector.resolve_endpoint(&endpoint).await;
        // This might fail in some environments, but should work in most cases
        if result.is_ok() {
            let addr = result.unwrap();
            assert_eq!(addr.port(), 8080);
            // localhost should resolve to either 127.0.0.1 or ::1
            assert!(addr.ip().is_loopback());
        }
    }

    #[test]
    fn test_direct_udp_transport_creation() {
        // We can't easily test the actual UDP functionality without setting up
        // a real UDP server, but we can test the structure
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let _transport = DirectUdpTransport::new(socket);
            // If we get here, the transport was created successfully
        });
    }

    #[tokio::test]
    async fn test_async_connector_interface() {
        use crate::adapter::OutboundConnector;
        let connector = DirectConnector::new();
        let result = connector.connect("127.0.0.1", 80).await;
        // This will fail because nothing is listening, but it tests the interface
        assert!(result.is_err());
    }
}

// Implementation for the async OutboundConnector trait used by adapter
#[async_trait::async_trait]
impl crate::adapter::OutboundConnector for DirectConnector {
    async fn connect(&self, host: &str, port: u16) -> std::io::Result<tokio::net::TcpStream> {
        let endpoint =
            crate::types::Endpoint::new(crate::types::Host::domain(host.to_string()), port);
        let src =
            std::net::SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0)), 0);
        let ctx = crate::types::ConnCtx::new(
            0, // id
            crate::types::Network::Tcp,
            src,
            endpoint,
        );

        self.connect_tcp(&ctx)
            .await
            .map_err(|e| std::io::Error::other(e.to_string()))
    }
}
