//! Outbound connector traits
//!
//! This module defines the standard traits for outbound connections
//! according to the architecture specifications.

use crate::{
    error::SbResult,
    types::{ConnCtx, Endpoint},
};
use async_trait::async_trait;
use std::net::SocketAddr;
// Keep minimal imports; AsyncIo trait removed, OutboundConnectorIo returns sb_transport::IoStream

/// Standard outbound connector trait for TCP and UDP connections
#[async_trait]
pub trait OutboundConnector: Send + Sync + std::fmt::Debug {
    /// Connect TCP to the target specified in the connection context
    async fn connect_tcp(&self, ctx: &ConnCtx) -> SbResult<tokio::net::TcpStream>;

    /// Connect UDP to the target specified in the connection context
    async fn connect_udp(&self, ctx: &ConnCtx) -> SbResult<Box<dyn UdpTransport>>;
}

/// UDP transport abstraction for bidirectional UDP communication
#[async_trait]
pub trait UdpTransport: Send + Sync {
    /// Send data to the specified destination
    async fn send_to(&self, buf: &[u8], dst: &Endpoint) -> SbResult<usize>;

    /// Receive data from any source, returning the data size and source address
    async fn recv_from(&self, buf: &mut [u8]) -> SbResult<(usize, SocketAddr)>;
}

/// Generic AsyncRead/Write connector (feature-gated)
///
/// Provides a way to obtain a fully-established TCP-like stream that may be
/// layered over transports such as TLS, WebSocket, or HTTP/2. This is used to
/// integrate V2Ray-style transports without breaking existing TcpStream-based
/// connectors.
#[cfg(feature = "v2ray_transport")]
#[async_trait]
pub trait OutboundConnectorIo: Send + Sync + std::fmt::Debug {
    /// Establish a full-duplex byte stream to the destination in `ConnCtx`.
    async fn connect_tcp_io(
        &self,
        ctx: &crate::types::ConnCtx,
    ) -> crate::error::SbResult<sb_transport::IoStream>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Endpoint, Host};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use tokio::net::TcpStream;

    // Mock implementation for testing
    #[derive(Debug)]
    struct MockOutboundConnector;

    #[async_trait]
    impl OutboundConnector for MockOutboundConnector {
        async fn connect_tcp(&self, _ctx: &ConnCtx) -> SbResult<TcpStream> {
            // This would fail in real tests, but demonstrates the interface
            Err(crate::error::SbError::network(
                crate::error::ErrorClass::Connection,
                "Mock connector test error".to_string(),
            ))
        }

        async fn connect_udp(&self, _ctx: &ConnCtx) -> SbResult<Box<dyn UdpTransport>> {
            Err(crate::error::SbError::network(
                crate::error::ErrorClass::Connection,
                "Mock connector test error".to_string(),
            ))
        }
    }

    struct MockUdpTransport;

    #[async_trait]
    impl UdpTransport for MockUdpTransport {
        async fn send_to(&self, _buf: &[u8], _dst: &Endpoint) -> SbResult<usize> {
            Ok(0)
        }

        async fn recv_from(&self, _buf: &mut [u8]) -> SbResult<(usize, SocketAddr)> {
            Ok((
                0,
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 0),
            ))
        }
    }

    #[test]
    fn test_trait_compilation() {
        // This test just ensures the traits compile correctly
        let _connector: Box<dyn OutboundConnector> = Box::new(MockOutboundConnector);
        let _transport: Box<dyn UdpTransport> = Box::new(MockUdpTransport);
    }

    #[tokio::test]
    async fn test_mock_udp_transport() {
        let transport = MockUdpTransport;
        let endpoint = Endpoint::new(Host::ip(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))), 8080);

        let result = transport.send_to(b"test", &endpoint).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 0);

        let mut buf = [0u8; 1024];
        let result = transport.recv_from(&mut buf).await;
        assert!(result.is_ok());
        let (size, addr) = result.unwrap();
        assert_eq!(size, 0);
        assert_eq!(addr.ip(), IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
    }
}
