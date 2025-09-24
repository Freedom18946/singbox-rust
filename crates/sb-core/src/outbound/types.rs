//! Outbound types and traits
//!
//! Common types and traits used across all outbound implementations.

use async_trait::async_trait;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use tokio::io::{AsyncRead, AsyncWrite};

// Re-export TargetAddr from net module for convenience
pub use crate::net::udp_nat::TargetAddr;

/// Host and port combination for target addressing
#[derive(Clone, Debug)]
pub struct HostPort {
    pub host: String,
    pub port: u16,
}

impl HostPort {
    pub fn new(host: String, port: u16) -> Self {
        Self { host, port }
    }
}

/// Address types for different protocols
#[derive(Clone, Debug)]
pub enum Addr {
    Domain(String),
    V4(Ipv4Addr),
    V6(Ipv6Addr),
}

impl From<&HostPort> for Addr {
    fn from(h: &HostPort) -> Self {
        match h.host.parse::<IpAddr>() {
            Ok(IpAddr::V4(v)) => Self::V4(v),
            Ok(IpAddr::V6(v)) => Self::V6(v),
            _ => Self::Domain(h.host.clone()),
        }
    }
}

/// Trait for TCP outbound connections
#[async_trait]
pub trait OutboundTcp: Send + Sync {
    type IO: AsyncRead + AsyncWrite + Unpin + Send + 'static;

    async fn connect(&self, target: &HostPort) -> std::io::Result<Self::IO>;

    fn protocol_name(&self) -> &'static str {
        "unknown"
    }
}

/// Encode address in Shadowsocks/SOCKS format
pub fn encode_ss_addr(addr: &Addr, port: u16, buf: &mut Vec<u8>) {
    match addr {
        Addr::V4(ip) => {
            buf.push(0x01); // IPv4
            buf.extend_from_slice(&ip.octets());
        }
        Addr::V6(ip) => {
            buf.push(0x04); // IPv6
            buf.extend_from_slice(&ip.octets());
        }
        Addr::Domain(domain) => {
            buf.push(0x03); // Domain
            buf.push(domain.len() as u8);
            buf.extend_from_slice(domain.as_bytes());
        }
    }
    buf.extend_from_slice(&port.to_be_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hostport_creation() {
        let hp = HostPort::new("example.com".to_string(), 443);
        assert_eq!(hp.host, "example.com");
        assert_eq!(hp.port, 443);
    }

    #[test]
    fn test_addr_from_hostport() {
        let hp = HostPort::new("127.0.0.1".to_string(), 80);
        let addr = Addr::from(&hp);
        matches!(addr, Addr::V4(_));

        let hp = HostPort::new("example.com".to_string(), 80);
        let addr = Addr::from(&hp);
        matches!(addr, Addr::Domain(_));
    }

    #[test]
    fn test_encode_ss_addr() {
        let mut buf = Vec::new();
        let addr = Addr::Domain("example.com".to_string());
        encode_ss_addr(&addr, 443, &mut buf);

        assert_eq!(buf[0], 0x03); // Domain type
        assert_eq!(buf[1], 11); // Domain length
        assert_eq!(&buf[2..13], b"example.com");
        assert_eq!(&buf[13..15], &443u16.to_be_bytes());
    }
}

/// Request for TCP connection
#[derive(Clone, Debug)]
pub struct TcpConnectRequest {
    pub target: TargetAddr,
    pub timeout_ms: Option<u64>,
}

impl TcpConnectRequest {
    pub fn new(target: TargetAddr) -> Self {
        Self {
            target,
            timeout_ms: None,
        }
    }

    pub fn with_timeout(mut self, timeout_ms: u64) -> Self {
        self.timeout_ms = Some(timeout_ms);
        self
    }
}

/// Request for UDP bind
#[derive(Clone, Debug)]
pub struct UdpBindRequest {
    pub bind: SocketAddr,
    pub target: Option<TargetAddr>,
}

impl UdpBindRequest {
    pub fn new(bind: SocketAddr) -> Self {
        Self { bind, target: None }
    }

    pub fn with_target(mut self, target: TargetAddr) -> Self {
        self.target = Some(target);
        self
    }
}

impl Default for UdpBindRequest {
    fn default() -> Self {
        Self::new("0.0.0.0:0".parse().unwrap())
    }
}

/// Generic outbound connection trait
#[async_trait]
pub trait Outbound: Send + Sync {
    /// Connect TCP to target
    async fn tcp_connect(&self, req: TcpConnectRequest) -> anyhow::Result<tokio::net::TcpStream>;

    /// Connect TCP with TLS to target
    async fn tcp_connect_tls(
        &self,
        req: TcpConnectRequest,
    ) -> anyhow::Result<crate::transport::TlsStream<tokio::net::TcpStream>>;

    /// Bind UDP socket
    async fn udp_bind(&self, req: UdpBindRequest) -> anyhow::Result<tokio::net::UdpSocket>;

    /// Get outbound name/identifier
    fn name(&self) -> &'static str;
}
