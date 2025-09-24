//! Local IR types for routing engine to avoid circular dependencies
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum InboundType {
    Socks,
    Http,
    Tun,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum OutboundType {
    Direct,
    Http,
    Socks,
    Block,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InboundIR {
    pub ty: InboundType,
    pub listen: String,
    pub port: u16,
    #[serde(default)]
    pub sniff: bool,
    #[serde(default)]
    pub udp: bool,
    #[serde(default)]
    pub auth: Option<(String, String)>, // (username, password)
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OutboundIR {
    pub ty: OutboundType,
    #[serde(default)]
    pub server: Option<String>,
    #[serde(default)]
    pub port: Option<u16>,
    #[serde(default)]
    pub udp: Option<String>, // "passthrough" | "socks5-upstream"
    #[serde(default)]
    pub name: Option<String>, // 命名出站（供选择器/路由引用）
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct RuleIR {
    // 正向维度
    #[serde(default)]
    pub domain: Vec<String>,
    #[serde(default)]
    pub geosite: Vec<String>,
    #[serde(default)]
    pub geoip: Vec<String>,
    #[serde(default)]
    pub ipcidr: Vec<String>,
    #[serde(default)]
    pub port: Vec<String>, // "80" | "80-90"
    #[serde(default)]
    pub process: Vec<String>,
    #[serde(default)]
    pub network: Vec<String>, // "tcp" | "udp"
    #[serde(default)]
    pub protocol: Vec<String>, // "http" | "socks"
    #[serde(default)]
    pub source: Vec<String>,
    #[serde(default)]
    pub dest: Vec<String>,
    #[serde(default)]
    pub user_agent: Vec<String>,
    // 否定维度
    #[serde(default)]
    pub not_domain: Vec<String>,
    #[serde(default)]
    pub not_geosite: Vec<String>,
    #[serde(default)]
    pub not_geoip: Vec<String>,
    #[serde(default)]
    pub not_ipcidr: Vec<String>,
    #[serde(default)]
    pub not_port: Vec<String>,
    #[serde(default)]
    pub not_process: Vec<String>,
    #[serde(default)]
    pub not_network: Vec<String>,
    #[serde(default)]
    pub not_protocol: Vec<String>,
    // 目的出站
    #[serde(default)]
    pub outbound: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct RouteIR {
    #[serde(default)]
    pub rules: Vec<RuleIR>,
    #[serde(default)]
    pub default: Option<String>, // 默认出站
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct ConfigIR {
    #[serde(default)]
    pub inbounds: Vec<InboundIR>,
    #[serde(default)]
    pub outbounds: Vec<OutboundIR>,
    #[serde(default)]
    pub route: RouteIR,
}

impl ConfigIR {
    pub fn has_any_negation(&self) -> bool {
        self.route.rules.iter().any(|r| {
            !r.not_domain.is_empty()
                || !r.not_geosite.is_empty()
                || !r.not_geoip.is_empty()
                || !r.not_ipcidr.is_empty()
                || !r.not_port.is_empty()
                || !r.not_process.is_empty()
                || !r.not_network.is_empty()
                || !r.not_protocol.is_empty()
        })
    }
}
