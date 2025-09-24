use std::net::SocketAddr;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProxyKind {
    Http,
    Socks5,
}

#[derive(Clone, Debug)]
pub struct ProxyEndpoint {
    pub kind: ProxyKind,
    pub addr: SocketAddr,
    pub auth: Option<(String, String)>, // user, pass (reserved for future use)
    pub weight: u32,                    // Load balancing weight (default 1)
    pub max_fail: u32,                  // Consecutive failure threshold for circuit breaking
    pub open_ms: u64,                   // Circuit breaker open duration in milliseconds
    pub half_open_ms: u64,              // Half-open probe interval in milliseconds
}

impl ProxyEndpoint {
    pub fn parse(s: &str) -> Option<Self> {
        // Support http://host:port and socks5://host:port
        // Additional fields (weight, circuit breaker settings) should be set by upper layer
        let lower = s.to_ascii_lowercase();
        if let Some(rest) = lower.strip_prefix("http://") {
            return rest.parse::<SocketAddr>().ok().map(|addr| Self {
                kind: ProxyKind::Http,
                addr,
                auth: None,
                weight: 1,
                max_fail: 3,
                open_ms: 5000,
                half_open_ms: 1000,
            });
        }
        if let Some(rest) = lower.strip_prefix("socks5://") {
            return rest.parse::<SocketAddr>().ok().map(|addr| Self {
                kind: ProxyKind::Socks5,
                addr,
                auth: None,
                weight: 1,
                max_fail: 3,
                open_ms: 5000,
                half_open_ms: 1000,
            });
        }
        None
    }
}
