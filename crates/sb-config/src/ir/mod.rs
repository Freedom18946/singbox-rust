//! Strongly-typed intermediate representation (IR) for config and routing rules.
//! - v1/v2 均转换到 IR，再由路由/适配层消费
//! - 字段命名向 Go 对齐；新增字段仅扩展，不改变默认行为
use serde::{Deserialize, Serialize};

pub mod diff;

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Credentials {
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
    /// if present, read username from this env var (takes precedence over `username`)
    #[serde(default)]
    pub username_env: Option<String>,
    /// if present, read password from this env var (takes precedence over `password`)
    #[serde(default)]
    pub password_env: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum InboundType {
    Socks,
    Http,
    Tun,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum OutboundType {
    #[default]
    Direct,
    Http,
    Socks,
    Block,
    Selector,
    Vless,
    Vmess,
    Trojan,
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
    /// HTTP 入站的 Basic 认证（可选）
    #[serde(default)]
    pub basic_auth: Option<Credentials>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
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
    /// for selector: list of member outbound names
    #[serde(default)]
    pub members: Option<Vec<String>>,
    /// 上游出站的认证信息（SOCKS/HTTP 均可用）
    #[serde(default)]
    pub credentials: Option<Credentials>,
    /// VLESS-specific fields
    #[serde(default)]
    pub uuid: Option<String>,
    #[serde(default)]
    pub flow: Option<String>,
    #[serde(default)]
    pub network: Option<String>,
    #[serde(default)]
    pub packet_encoding: Option<String>,
    /// Transport nesting (e.g., ["tls","ws"]) for V2Ray-style transports
    #[serde(default)]
    pub transport: Option<Vec<String>>,
    /// Optional WebSocket path and Host header override
    #[serde(default)]
    pub ws_path: Option<String>,
    #[serde(default)]
    pub ws_host: Option<String>,
    /// Optional HTTP/2 path and Host/authority override
    #[serde(default)]
    pub h2_path: Option<String>,
    #[serde(default)]
    pub h2_host: Option<String>,
    /// Optional TLS SNI and ALPN list
    #[serde(default)]
    pub tls_sni: Option<String>,
    #[serde(default)]
    pub tls_alpn: Option<String>,
    /// Trojan-specific fields
    #[serde(default)]
    pub password: Option<String>,
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

impl OutboundIR {
    pub fn ty_str(&self) -> &'static str {
        match self.ty {
            OutboundType::Direct => "direct",
            OutboundType::Http => "http",
            OutboundType::Socks => "socks",
            OutboundType::Block => "block",
            OutboundType::Selector => "selector",
            OutboundType::Vless => "vless",
            OutboundType::Vmess => "vmess",
            OutboundType::Trojan => "trojan",
        }
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn negation_detect() {
        let mut cfg = ConfigIR::default();
        cfg.route.rules.push(RuleIR {
            not_geoip: vec!["CN".into()],
            ..Default::default()
        });
        assert!(cfg.has_any_negation());
    }
}
