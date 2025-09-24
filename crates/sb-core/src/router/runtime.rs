use once_cell::sync::OnceCell;
use std::sync::Arc;

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

static GLOBAL_PROXY: OnceCell<Arc<ProxyChoice>> = OnceCell::new();

/// 从环境变量解析默认代理（内部解析函数，供测试使用）
pub fn parse_proxy_from_env() -> ProxyChoice {
    let mut choice = ProxyChoice::Direct;
    if let Ok(v) = std::env::var("SB_ROUTER_DEFAULT_PROXY") {
        let s = v.trim();
        if s.eq_ignore_ascii_case("direct") {
            choice = ProxyChoice::Direct;
        } else if let Some(addr) = s.strip_prefix("http://") {
            choice = ProxyChoice::Http(addr.to_string());
        } else if let Some(addr) = s.strip_prefix("socks5://") {
            choice = ProxyChoice::Socks5(addr.to_string());
        }
    } else if let (Ok(kind), Ok(addr)) = (
        std::env::var("SB_ROUTER_DEFAULT_PROXY_KIND"),
        std::env::var("SB_ROUTER_DEFAULT_PROXY_ADDR"),
    ) {
        match kind.to_ascii_lowercase().as_str() {
            "http" => choice = ProxyChoice::Http(addr),
            "socks5" => choice = ProxyChoice::Socks5(addr),
            "direct" => choice = ProxyChoice::Direct,
            _ => {}
        }
    }
    choice
}

/// 从环境变量解析默认代理：
/// - SB_ROUTER_DEFAULT_PROXY="direct" | "http://host:port" | "socks5://host:port"
/// - 或 SB_ROUTER_DEFAULT_PROXY_KIND="http|socks5|direct" + SB_ROUTER_DEFAULT_PROXY_ADDR="host:port"
pub fn init_default_proxy_from_env() {
    let choice = parse_proxy_from_env();
    let _ = GLOBAL_PROXY.set(Arc::new(choice));
}

pub fn default_proxy() -> &'static ProxyChoice {
    GLOBAL_PROXY
        .get()
        .map(|x| x.as_ref())
        .unwrap_or(&ProxyChoice::Direct)
}
