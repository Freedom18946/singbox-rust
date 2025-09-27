use async_trait::async_trait;
use std::net::SocketAddr;
use tokio::io::{AsyncRead, AsyncWrite};

/// Simplified host:port target representation
#[derive(Clone, Debug)]
pub struct HostPort {
    pub host: String,
    pub port: u16,
}

impl HostPort {
    pub fn new(host: String, port: u16) -> Self {
        Self { host, port }
    }

    pub fn from_domain(domain: &str, port: u16) -> Self {
        Self {
            host: domain.to_string(),
            port,
        }
    }
}

impl std::fmt::Display for HostPort {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.host, self.port)
    }
}

/// Unified TCP outbound interface for encrypted protocols
#[async_trait]
pub trait OutboundTcp: Send + Sync {
    type IO: AsyncRead + AsyncWrite + Unpin + Send + 'static;

    /// Connect to target through this outbound
    async fn connect(&self, target: &HostPort) -> std::io::Result<Self::IO>;

    /// Get protocol name for metrics/logging
    fn protocol_name(&self) -> &'static str;
}

/// Unified UDP outbound interface
#[async_trait]
pub trait OutboundUdp: Send + Sync {
    /// Bind UDP socket for outbound traffic
    async fn bind(&self) -> std::io::Result<tokio::net::UdpSocket>;

    /// Connect to specific peer (optional operation for some protocols)
    async fn connect_addr(&self, _peer: &SocketAddr) -> std::io::Result<()> {
        Ok(())
    }

    /// Get protocol name for metrics/logging
    fn protocol_name(&self) -> &'static str;
}

/// Outbound kind enumeration supporting encrypted protocols
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OutboundKind {
    Direct,
    Block,
    Socks,
    Http,
    #[cfg(feature = "out_trojan")]
    Trojan,
    #[cfg(feature = "out_ss")]
    Shadowsocks,
    #[cfg(feature = "out_shadowtls")]
    ShadowTls,
    #[cfg(feature = "out_naive")]
    Naive,
    #[cfg(feature = "out_vless")]
    Vless,
    #[cfg(feature = "out_vmess")]
    Vmess,
    #[cfg(feature = "out_tuic")]
    Tuic,
    #[cfg(feature = "out_hysteria2")]
    Hysteria2,
    #[cfg(feature = "out_wireguard")]
    WireGuard,
    #[cfg(feature = "out_ssh")]
    Ssh,
}

 

impl std::fmt::Display for OutboundKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OutboundKind::Direct => write!(f, "direct"),
            OutboundKind::Block => write!(f, "block"),
            OutboundKind::Socks => write!(f, "socks"),
            OutboundKind::Http => write!(f, "http"),
            #[cfg(feature = "out_trojan")]
            OutboundKind::Trojan => write!(f, "trojan"),
            #[cfg(feature = "out_ss")]
            OutboundKind::Shadowsocks => write!(f, "shadowsocks"),
            #[cfg(feature = "out_shadowtls")]
            OutboundKind::ShadowTls => write!(f, "shadowtls"),
            #[cfg(feature = "out_naive")]
            OutboundKind::Naive => write!(f, "naive"),
            #[cfg(feature = "out_vless")]
            OutboundKind::Vless => write!(f, "vless"),
            #[cfg(feature = "out_vmess")]
            OutboundKind::Vmess => write!(f, "vmess"),
            #[cfg(feature = "out_tuic")]
            OutboundKind::Tuic => write!(f, "tuic"),
            #[cfg(feature = "out_hysteria2")]
            OutboundKind::Hysteria2 => write!(f, "hysteria2"),
            #[cfg(feature = "out_wireguard")]
            OutboundKind::WireGuard => write!(f, "wireguard"),
            #[cfg(feature = "out_ssh")]
            OutboundKind::Ssh => write!(f, "ssh"),
        }
    }
}
