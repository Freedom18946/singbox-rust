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
    /// HTTP CONNECT proxy
    Socks,
    Http,
    Tun,
    /// Direct TCP/UDP forwarder (override destination)
    Direct,
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
    Shadowtls,
    Hysteria2,
    Vless,
    Vmess,
    Trojan,
    Ssh,
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
    /// For direct inbound: override destination host (required for production use)
    #[serde(default)]
    pub override_host: Option<String>,
    /// For direct inbound: override destination port
    #[serde(default)]
    pub override_port: Option<u16>,
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
    /// REALITY TLS configuration
    #[serde(default)]
    pub reality_enabled: Option<bool>,
    #[serde(default)]
    pub reality_public_key: Option<String>,
    #[serde(default)]
    pub reality_short_id: Option<String>,
    #[serde(default)]
    pub reality_server_name: Option<String>,
    /// Trojan-specific fields
    #[serde(default)]
    pub password: Option<String>,

    // SSH-specific fields (optional)
    #[serde(default)]
    pub ssh_private_key: Option<String>, // PEM content or file path (when _path not used)
    #[serde(default)]
    pub ssh_private_key_path: Option<String>,
    #[serde(default)]
    pub ssh_private_key_passphrase: Option<String>,
    #[serde(default)]
    pub ssh_host_key_verification: Option<bool>,
    #[serde(default)]
    pub ssh_known_hosts_path: Option<String>,
    #[serde(default)]
    pub ssh_connection_pool_size: Option<usize>,
    #[serde(default)]
    pub ssh_compression: Option<bool>,
    #[serde(default)]
    pub ssh_keepalive_interval: Option<u64>,
    #[serde(default)]
    pub connect_timeout_sec: Option<u32>,
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
    /// Sniffed ALPN protocols (e.g., "h2", "http/1.1", "h3")
    #[serde(default)]
    pub alpn: Vec<String>,
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
    /// Exclude connections whose sniffed ALPN is in this list
    #[serde(default)]
    pub not_alpn: Vec<String>,
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
            OutboundType::Shadowtls => "shadowtls",
            OutboundType::Hysteria2 => "hysteria2",
            OutboundType::Vless => "vless",
            OutboundType::Vmess => "vmess",
            OutboundType::Trojan => "trojan",
            OutboundType::Ssh => "ssh",
        }
    }

    /// Validate REALITY configuration if enabled
    pub fn validate_reality(&self) -> Result<(), String> {
        // Only validate if REALITY is explicitly enabled
        if let Some(true) = self.reality_enabled {
            // Validate public_key (must be 64 hex chars for X25519)
            if let Some(ref public_key) = self.reality_public_key {
                if !is_valid_hex(public_key) || public_key.len() != 64 {
                    return Err(format!(
                        "outbound '{}': reality.public_key must be 64 hex characters (X25519 public key)",
                        self.name.as_deref().unwrap_or("unnamed")
                    ));
                }
            } else {
                return Err(format!(
                    "outbound '{}': reality.public_key is required when reality is enabled",
                    self.name.as_deref().unwrap_or("unnamed")
                ));
            }

            // Validate short_id if present (0-16 hex chars, even length)
            if let Some(ref short_id) = self.reality_short_id {
                if !short_id.is_empty() {
                    if !is_valid_hex(short_id) {
                        return Err(format!(
                            "outbound '{}': reality.short_id must be hex characters",
                            self.name.as_deref().unwrap_or("unnamed")
                        ));
                    }
                    if short_id.len() > 16 || short_id.len() % 2 != 0 {
                        return Err(format!(
                            "outbound '{}': reality.short_id must be 0-16 hex chars (length multiple of 2)",
                            self.name.as_deref().unwrap_or("unnamed")
                        ));
                    }
                }
            }

            // Validate server_name is present
            if self.reality_server_name.is_none() || self.reality_server_name.as_ref().map(|s| s.is_empty()).unwrap_or(true) {
                return Err(format!(
                    "outbound '{}': reality.server_name is required when reality is enabled",
                    self.name.as_deref().unwrap_or("unnamed")
                ));
            }
        }

        Ok(())
    }
}

/// Helper function to validate hex strings
fn is_valid_hex(s: &str) -> bool {
    s.chars().all(|c| c.is_ascii_hexdigit())
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

    /// Validate all outbound configurations including REALITY
    pub fn validate(&self) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();

        // Validate REALITY configuration for all outbounds
        for outbound in &self.outbounds {
            if let Err(e) = outbound.validate_reality() {
                errors.push(e);
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
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

    #[test]
    fn test_reality_validation_valid() {
        let outbound = OutboundIR {
            ty: OutboundType::Vless,
            name: Some("test-vless".to_string()),
            reality_enabled: Some(true),
            reality_public_key: Some("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string()),
            reality_short_id: Some("01ab".to_string()),
            reality_server_name: Some("www.apple.com".to_string()),
            ..Default::default()
        };

        assert!(outbound.validate_reality().is_ok());
    }

    #[test]
    fn test_reality_validation_missing_public_key() {
        let outbound = OutboundIR {
            ty: OutboundType::Vless,
            name: Some("test-vless".to_string()),
            reality_enabled: Some(true),
            reality_public_key: None,
            reality_short_id: Some("01ab".to_string()),
            reality_server_name: Some("www.apple.com".to_string()),
            ..Default::default()
        };

        assert!(outbound.validate_reality().is_err());
        let err = outbound.validate_reality().unwrap_err();
        assert!(err.contains("public_key is required"));
    }

    #[test]
    fn test_reality_validation_invalid_public_key() {
        let outbound = OutboundIR {
            ty: OutboundType::Vless,
            name: Some("test-vless".to_string()),
            reality_enabled: Some(true),
            reality_public_key: Some("invalid".to_string()),
            reality_short_id: Some("01ab".to_string()),
            reality_server_name: Some("www.apple.com".to_string()),
            ..Default::default()
        };

        assert!(outbound.validate_reality().is_err());
        let err = outbound.validate_reality().unwrap_err();
        assert!(err.contains("64 hex characters"));
    }

    #[test]
    fn test_reality_validation_invalid_short_id() {
        let outbound = OutboundIR {
            ty: OutboundType::Vless,
            name: Some("test-vless".to_string()),
            reality_enabled: Some(true),
            reality_public_key: Some("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string()),
            reality_short_id: Some("xyz".to_string()), // Invalid hex
            reality_server_name: Some("www.apple.com".to_string()),
            ..Default::default()
        };

        assert!(outbound.validate_reality().is_err());
        let err = outbound.validate_reality().unwrap_err();
        assert!(err.contains("hex characters"));
    }

    #[test]
    fn test_reality_validation_missing_server_name() {
        let outbound = OutboundIR {
            ty: OutboundType::Vless,
            name: Some("test-vless".to_string()),
            reality_enabled: Some(true),
            reality_public_key: Some("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string()),
            reality_short_id: Some("01ab".to_string()),
            reality_server_name: None,
            ..Default::default()
        };

        assert!(outbound.validate_reality().is_err());
        let err = outbound.validate_reality().unwrap_err();
        assert!(err.contains("server_name is required"));
    }

    #[test]
    fn test_reality_validation_disabled() {
        // When REALITY is not enabled, validation should pass even with missing fields
        let outbound = OutboundIR {
            ty: OutboundType::Vless,
            name: Some("test-vless".to_string()),
            reality_enabled: Some(false),
            reality_public_key: None,
            reality_short_id: None,
            reality_server_name: None,
            ..Default::default()
        };

        assert!(outbound.validate_reality().is_ok());
    }

    #[test]
    fn test_config_ir_validate_reality() {
        let mut config = ConfigIR::default();
        
        // Add valid outbound
        config.outbounds.push(OutboundIR {
            ty: OutboundType::Vless,
            name: Some("valid".to_string()),
            reality_enabled: Some(true),
            reality_public_key: Some("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string()),
            reality_short_id: Some("01ab".to_string()),
            reality_server_name: Some("www.apple.com".to_string()),
            ..Default::default()
        });

        assert!(config.validate().is_ok());

        // Add invalid outbound
        config.outbounds.push(OutboundIR {
            ty: OutboundType::Vless,
            name: Some("invalid".to_string()),
            reality_enabled: Some(true),
            reality_public_key: None, // Missing required field
            reality_short_id: Some("01ab".to_string()),
            reality_server_name: Some("www.apple.com".to_string()),
            ..Default::default()
        });

        assert!(config.validate().is_err());
        let errors = config.validate().unwrap_err();
        assert_eq!(errors.len(), 1);
        assert!(errors[0].contains("public_key is required"));
    }
}
