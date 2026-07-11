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

    Trojan,

    Shadowsocks,

    ShadowTls,

    Naive,

    Vless,

    Vmess,

    Tuic,

    Hysteria2,

    WireGuard,

    Ssh,
}

impl std::fmt::Display for OutboundKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Direct => write!(f, "direct"),
            Self::Block => write!(f, "block"),
            Self::Socks => write!(f, "socks"),
            Self::Http => write!(f, "http"),

            OutboundKind::Trojan => write!(f, "trojan"),

            OutboundKind::Shadowsocks => write!(f, "shadowsocks"),

            OutboundKind::ShadowTls => write!(f, "shadowtls"),

            OutboundKind::Naive => write!(f, "naive"),

            OutboundKind::Vless => write!(f, "vless"),

            OutboundKind::Vmess => write!(f, "vmess"),

            OutboundKind::Tuic => write!(f, "tuic"),

            OutboundKind::Hysteria2 => write!(f, "hysteria2"),

            OutboundKind::WireGuard => write!(f, "wireguard"),

            OutboundKind::Ssh => write!(f, "ssh"),
        }
    }
}
