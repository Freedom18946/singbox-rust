//! Core types for singbox-rust
//!
//! This module defines the fundamental types used throughout the system,
//! including Host, Endpoint, ConnCtx, and Network types.

use std::fmt;
use std::net::{IpAddr, SocketAddr};

// Type aliases for compatibility with existing code
pub type HostPort = Endpoint;
pub type DnsRecord = crate::dns::message::Record;

/// UDP socket binding configuration
#[derive(Debug, Clone)]
pub struct UdpSocketBind {
    pub addr: SocketAddr,
    pub reuse_addr: bool,
    pub reuse_port: bool,
}

impl UdpSocketBind {
    pub fn new(addr: SocketAddr) -> Self {
        Self {
            addr,
            reuse_addr: false,
            reuse_port: false,
        }
    }

    pub fn with_reuse_addr(mut self, reuse: bool) -> Self {
        self.reuse_addr = reuse;
        self
    }

    pub fn with_reuse_port(mut self, reuse: bool) -> Self {
        self.reuse_port = reuse;
        self
    }
}

/// Host representation that can be either a domain name or IP address
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Host {
    Ip(IpAddr),
    Name(Box<str>),
}

impl Host {
    /// Create a new Host from a domain name
    pub fn domain(domain: impl Into<String>) -> Self {
        Self::Name(domain.into().into_boxed_str())
    }

    /// Create a new Host from an IP address
    pub fn ip(ip: IpAddr) -> Self {
        Self::Ip(ip)
    }

    /// Parse a host from a string (domain or IP)
    pub fn parse(s: &str) -> Self {
        match s.parse::<IpAddr>() {
            Ok(ip) => Self::Ip(ip),
            Err(_) => Self::Name(s.into()),
        }
    }

    /// Check if this host is a domain name
    pub fn is_domain(&self) -> bool {
        matches!(self, Host::Name(_))
    }

    /// Check if this host is an IP address
    pub fn is_ip(&self) -> bool {
        matches!(self, Host::Ip(_))
    }

    /// Get the domain name if this is a domain host
    pub fn as_domain(&self) -> Option<&str> {
        match self {
            Host::Name(d) => Some(d),
            Host::Ip(_) => None,
        }
    }

    /// Get the IP address if this is an IP host
    pub fn as_ip(&self) -> Option<IpAddr> {
        match self {
            Host::Name(_) => None,
            Host::Ip(ip) => Some(*ip),
        }
    }
}

impl fmt::Display for Host {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Host::Name(d) => write!(f, "{}", d),
            Host::Ip(ip) => write!(f, "{}", ip),
        }
    }
}

impl From<IpAddr> for Host {
    fn from(ip: IpAddr) -> Self {
        Self::ip(ip)
    }
}

impl From<String> for Host {
    fn from(s: String) -> Self {
        Self::parse(&s)
    }
}

impl From<&str> for Host {
    fn from(s: &str) -> Self {
        Self::parse(s)
    }
}

/// Endpoint combining host and port
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Endpoint {
    pub host: Host,
    pub port: u16,
}

impl Endpoint {
    /// Create a new endpoint
    pub fn new(host: impl Into<Host>, port: u16) -> Self {
        Self {
            host: host.into(),
            port,
        }
    }

    /// Create endpoint from socket address
    pub fn from_socket_addr(addr: SocketAddr) -> Self {
        Self {
            host: Host::ip(addr.ip()),
            port: addr.port(),
        }
    }

    /// Convert to socket address if host is an IP
    pub fn to_socket_addr(&self) -> Option<SocketAddr> {
        self.host.as_ip().map(|ip| SocketAddr::new(ip, self.port))
    }
}

impl fmt::Display for Endpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.host.is_ip() && matches!(self.host.as_ip(), Some(IpAddr::V6(_))) {
            write!(f, "[{}]:{}", self.host, self.port)
        } else {
            write!(f, "{}:{}", self.host, self.port)
        }
    }
}

impl From<SocketAddr> for Endpoint {
    fn from(addr: SocketAddr) -> Self {
        Self::from_socket_addr(addr)
    }
}

/// Network protocol type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Network {
    Tcp,
    Udp,
}

impl fmt::Display for Network {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Network::Tcp => write!(f, "tcp"),
            Network::Udp => write!(f, "udp"),
        }
    }
}

/// Process information for connection context
#[derive(Debug, Clone, PartialEq)]
pub struct ProcessInfo {
    pub name: String,
    pub path: String,
    pub pid: u32,
}

impl ProcessInfo {
    pub fn new(name: String, path: String, pid: u32) -> Self {
        Self { name, path, pid }
    }
}

/// Connection context containing all relevant information for routing decisions
#[derive(Debug)]
pub struct ConnCtx {
    pub id: u64,
    pub network: Network,
    pub src: SocketAddr,
    pub dst: Endpoint,
    pub sni: Option<Box<str>>,
    pub user: Option<Box<str>>,
    pub process_info: Option<ProcessInfo>,
    pub now: std::time::Instant,
}

impl ConnCtx {
    /// Create a new connection context
    pub fn new(id: u64, network: Network, src: SocketAddr, dst: Endpoint) -> Self {
        Self {
            id,
            network,
            src,
            dst,
            sni: None,
            user: None,
            process_info: None,
            now: std::time::Instant::now(),
        }
    }

    /// Set SNI for TLS connections
    pub fn with_sni(mut self, sni: impl Into<String>) -> Self {
        self.sni = Some(sni.into().into_boxed_str());
        self
    }

    /// Set user information
    pub fn with_user(mut self, user: impl Into<String>) -> Self {
        self.user = Some(user.into().into_boxed_str());
        self
    }

    /// Set process information
    pub fn with_process_info(mut self, process_info: ProcessInfo) -> Self {
        self.process_info = Some(process_info);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn test_host_creation() {
        let domain_host = Host::domain("example.com");
        assert!(domain_host.is_domain());
        assert_eq!(domain_host.as_domain(), Some("example.com"));

        let ip_host = Host::ip(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
        assert!(ip_host.is_ip());
        assert_eq!(
            ip_host.as_ip(),
            Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)))
        );
    }

    #[test]
    fn test_host_parse() {
        let domain_host = Host::parse("example.com");
        assert!(domain_host.is_domain());

        let ip_host = Host::parse("127.0.0.1");
        assert!(ip_host.is_ip());

        let ipv6_host = Host::parse("::1");
        assert!(ipv6_host.is_ip());
    }

    #[test]
    fn test_endpoint_creation() {
        let endpoint = Endpoint::new("example.com", 443);
        assert_eq!(endpoint.host.as_domain(), Some("example.com"));
        assert_eq!(endpoint.port, 443);

        let socket_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);
        let endpoint = Endpoint::from_socket_addr(socket_addr);
        assert_eq!(endpoint.to_socket_addr(), Some(socket_addr));
    }

    #[test]
    fn test_endpoint_display() {
        let endpoint = Endpoint::new("example.com", 443);
        assert_eq!(endpoint.to_string(), "example.com:443");

        let ipv4_endpoint = Endpoint::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);
        assert_eq!(ipv4_endpoint.to_string(), "127.0.0.1:8080");

        let ipv6_endpoint = Endpoint::new(IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)), 8080);
        assert_eq!(ipv6_endpoint.to_string(), "[::1]:8080");
    }

    #[test]
    fn test_network_display() {
        assert_eq!(Network::Tcp.to_string(), "tcp");
        assert_eq!(Network::Udp.to_string(), "udp");
    }

    #[test]
    fn test_conn_ctx_creation() {
        let src = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), 12345);
        let dst = Endpoint::new("example.com", 443);
        let process_info =
            ProcessInfo::new("firefox".to_string(), "/usr/bin/firefox".to_string(), 1234);

        let ctx = ConnCtx::new(1, Network::Tcp, src, dst.clone())
            .with_sni("example.com")
            .with_user("test_user")
            .with_process_info(process_info.clone());

        assert_eq!(ctx.id, 1);
        assert_eq!(ctx.network, Network::Tcp);
        assert_eq!(ctx.src, src);
        assert_eq!(ctx.dst, dst);
        assert_eq!(ctx.sni.as_deref(), Some("example.com"));
        assert_eq!(ctx.user.as_deref(), Some("test_user"));
        assert_eq!(ctx.process_info, Some(process_info));
    }

    #[test]
    fn test_process_info() {
        let process = ProcessInfo::new("firefox".to_string(), "/usr/bin/firefox".to_string(), 1234);

        assert_eq!(process.name, "firefox");
        assert_eq!(process.path, "/usr/bin/firefox");
        assert_eq!(process.pid, 1234);
    }
}
