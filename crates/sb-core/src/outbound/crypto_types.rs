/// Simplified host:port target representation
#[derive(Clone, Debug)]
pub struct HostPort {
    pub host: String,
    pub port: u16,
}

impl HostPort {
    pub const fn new(host: String, port: u16) -> Self {
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
            Self::Direct => write!(f, "direct"),
            Self::Block => write!(f, "block"),
            Self::Socks => write!(f, "socks"),
            Self::Http => write!(f, "http"),
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
