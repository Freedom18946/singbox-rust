#[derive(Debug, Clone)]
pub enum ProxyChoice {
    Direct,
    Http(String),   // "host:port"
    Socks5(String), // "host:port"
}

impl ProxyChoice {
    pub fn label(&self) -> &'static str {
        match self {
            ProxyChoice::Direct => "direct",
            ProxyChoice::Http(_) => "http",
            ProxyChoice::Socks5(_) => "socks5",
        }
    }
}

/// Parse default proxy from injected runtime options.
pub fn parse_proxy_from_env() -> ProxyChoice {
    parse_proxy(&crate::runtime_options::RouterRuntimeOptions::default())
}

pub fn parse_proxy(options: &crate::runtime_options::RouterRuntimeOptions) -> ProxyChoice {
    let mut choice = ProxyChoice::Direct;
    if let Some(v) = options.default_proxy.as_deref() {
        let s = v.trim();
        if s.eq_ignore_ascii_case("direct") {
            choice = ProxyChoice::Direct;
        } else if let Some(addr) = s.strip_prefix("http://") {
            choice = ProxyChoice::Http(addr.to_string());
        } else if let Some(addr) = s.strip_prefix("socks5://") {
            choice = ProxyChoice::Socks5(addr.to_string());
        }
    } else if let (Some(kind), Some(addr)) = (
        options.default_proxy_kind.as_deref(),
        options.default_proxy_addr.as_deref(),
    ) {
        match kind.to_ascii_lowercase().as_str() {
            "http" => choice = ProxyChoice::Http(addr.to_string()),
            "socks5" => choice = ProxyChoice::Socks5(addr.to_string()),
            "direct" => choice = ProxyChoice::Direct,
            _ => {}
        }
    }
    choice
}
