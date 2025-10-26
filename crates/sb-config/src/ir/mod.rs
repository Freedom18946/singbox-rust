//! Strongly-typed intermediate representation (IR) for config and routing rules.
//!
//! Both V1 and V2 formats are converted to IR, which is then consumed by routing
//! and adapter layers. Field naming aligns with Go sing-box; new fields extend
//! without changing default behavior.

use serde::{Deserialize, Serialize};

pub mod diff;

/// Authentication credentials with optional environment variable support.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Credentials {
    /// Username (literal value).
    #[serde(default)]
    pub username: Option<String>,
    /// Password (literal value).
    #[serde(default)]
    pub password: Option<String>,
    /// Read username from this environment variable (takes precedence over `username`).
    #[serde(default)]
    pub username_env: Option<String>,
    /// Read password from this environment variable (takes precedence over `password`).
    #[serde(default)]
    pub password_env: Option<String>,
}

/// Inbound proxy type.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum InboundType {
    /// SOCKS5 proxy.
    Socks,
    /// HTTP CONNECT proxy.
    Http,
    /// TUN device inbound.
    Tun,
    /// Direct TCP/UDP forwarder with optional destination override.
    Direct,
}

/// Outbound proxy type.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum OutboundType {
    /// Direct connection (no proxy).
    #[default]
    Direct,
    /// HTTP proxy.
    Http,
    /// SOCKS5 proxy.
    Socks,
    /// Block connection.
    Block,
    /// Manual selector (user-selected proxy).
    Selector,
    /// Shadowsocks proxy.
    Shadowsocks,
    /// ShadowTLS proxy.
    Shadowtls,
    /// Automatic selector based on URL test latency.
    UrlTest,
    /// Hysteria2 protocol.
    Hysteria2,
    /// TUIC protocol.
    Tuic,
    /// VLESS protocol.
    Vless,
    /// VMess protocol.
    Vmess,
    /// Trojan protocol.
    Trojan,
    /// SSH tunnel.
    Ssh,
}

/// Inbound listener configuration.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InboundIR {
    /// Inbound type.
    pub ty: InboundType,
    /// Listen address (IP or hostname).
    pub listen: String,
    /// Listen port.
    pub port: u16,
    /// Enable traffic sniffing.
    #[serde(default)]
    pub sniff: bool,
    /// Enable UDP support.
    #[serde(default)]
    pub udp: bool,
    /// Basic authentication for HTTP inbound (optional).
    #[serde(default)]
    pub basic_auth: Option<Credentials>,
    /// Override destination host (for direct inbound).
    #[serde(default)]
    pub override_host: Option<String>,
    /// Override destination port (for direct inbound).
    #[serde(default)]
    pub override_port: Option<u16>,
}

/// Outbound proxy configuration.
///
/// Supports multiple protocols (HTTP, SOCKS, Shadowsocks, VLESS, etc.)
/// with protocol-specific fields marked as optional.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct OutboundIR {
    pub ty: OutboundType,
    /// Server address (IP or hostname).
    #[serde(default)]
    pub server: Option<String>,
    /// Server port.
    #[serde(default)]
    pub port: Option<u16>,
    /// UDP mode: `"passthrough"` or `"socks5-upstream"`.
    #[serde(default)]
    pub udp: Option<String>,
    /// Named outbound (for selector/router references).
    #[serde(default)]
    pub name: Option<String>,
    /// Member outbound names (for selector/urltest).
    #[serde(default)]
    pub members: Option<Vec<String>>,
    /// Default member name for selector-like outbounds.
    #[serde(default)]
    pub default_member: Option<String>,
    /// Method identifier (e.g., Shadowsocks cipher).
    #[serde(default)]
    pub method: Option<String>,
    /// Authentication credentials for upstream proxies (SOCKS/HTTP).
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
    /// Protocol-specific congestion control (TUIC) or flow (VLESS)
    #[serde(default)]
    pub congestion_control: Option<String>,
    /// TUIC authentication token
    #[serde(default)]
    pub token: Option<String>,
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
    /// Optional gRPC service name
    #[serde(default)]
    pub grpc_service: Option<String>,
    /// Optional gRPC method name
    #[serde(default)]
    pub grpc_method: Option<String>,
    /// Optional gRPC authority (host override)
    #[serde(default)]
    pub grpc_authority: Option<String>,
    /// Additional gRPC metadata headers
    #[serde(default)]
    pub grpc_metadata: Vec<HeaderEntry>,
    /// Optional HTTP Upgrade path
    #[serde(default)]
    pub http_upgrade_path: Option<String>,
    /// Additional HTTP Upgrade headers
    #[serde(default)]
    pub http_upgrade_headers: Vec<HeaderEntry>,
    /// Optional TLS SNI and ALPN list
    #[serde(default)]
    pub tls_sni: Option<String>,
    #[serde(default)]
    pub tls_alpn: Option<String>,
    /// Explicit ALPN override for transports that do not use tls_alpn (e.g., TUIC)
    #[serde(default)]
    pub alpn: Option<String>,
    /// Whether to skip TLS certificate verification (TUIC)
    #[serde(default)]
    pub skip_cert_verify: Option<bool>,
    /// UDP relay mode for TUIC ("native" | "quic")
    #[serde(default)]
    pub udp_relay_mode: Option<String>,
    /// Whether TUIC should tunnel UDP over stream
    #[serde(default)]
    pub udp_over_stream: Option<bool>,
    /// Optional upload bandwidth limit in Mbps (Hysteria2)
    #[serde(default)]
    pub up_mbps: Option<u32>,
    /// Optional download bandwidth limit in Mbps (Hysteria2)
    #[serde(default)]
    pub down_mbps: Option<u32>,
    /// Optional obfuscation key/mode (Hysteria2)
    #[serde(default)]
    pub obfs: Option<String>,
    /// Optional Salamander fingerprint string (Hysteria2)
    #[serde(default)]
    pub salamander: Option<String>,
    /// Brutal congestion control upload limit (Hysteria2)
    #[serde(default)]
    pub brutal_up_mbps: Option<u32>,
    /// Brutal congestion control download limit (Hysteria2)
    #[serde(default)]
    pub brutal_down_mbps: Option<u32>,
    /// REALITY TLS configuration.
    #[serde(default)]
    pub reality_enabled: Option<bool>,
    #[serde(default)]
    pub reality_public_key: Option<String>,
    #[serde(default)]
    pub reality_short_id: Option<String>,
    #[serde(default)]
    pub reality_server_name: Option<String>,
    /// Trojan password.
    #[serde(default)]
    pub password: Option<String>,

    // SSH-specific fields
    /// SSH private key content or file path (when `ssh_private_key_path` is not used).
    #[serde(default)]
    pub ssh_private_key: Option<String>,
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
    /// URLTest probe configuration
    #[serde(default)]
    pub test_url: Option<String>,
    #[serde(default)]
    pub test_interval_ms: Option<u64>,
    #[serde(default)]
    pub test_timeout_ms: Option<u64>,
    #[serde(default)]
    pub test_tolerance_ms: Option<u64>,
    #[serde(default)]
    pub interrupt_exist_connections: Option<bool>,
}

/// HTTP header entry (for gRPC metadata or HTTP Upgrade headers).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct HeaderEntry {
    /// Header name.
    pub name: String,
    /// Header value.
    pub value: String,
}

/// Routing rule intermediate representation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct RuleIR {
    // Positive match conditions
    /// Domain exact match list.
    #[serde(default)]
    pub domain: Vec<String>,
    /// Geosite category list.
    #[serde(default)]
    pub geosite: Vec<String>,
    /// GeoIP country code list.
    #[serde(default)]
    pub geoip: Vec<String>,
    /// IP CIDR list.
    #[serde(default)]
    pub ipcidr: Vec<String>,
    /// Port or port range (e.g., `"80"`, `"80-90"`).
    #[serde(default)]
    pub port: Vec<String>,
    /// Process name list.
    #[serde(default)]
    pub process: Vec<String>,
    /// Network type: `"tcp"` or `"udp"`.
    #[serde(default)]
    pub network: Vec<String>,
    /// Protocol list: `"http"`, `"socks"`, etc.
    #[serde(default)]
    pub protocol: Vec<String>,
    /// Sniffed ALPN protocols (e.g., `"h2"`, `"http/1.1"`, `"h3"`).
    #[serde(default)]
    pub alpn: Vec<String>,
    /// Source address list.
    #[serde(default)]
    pub source: Vec<String>,
    /// Destination address list.
    #[serde(default)]
    pub dest: Vec<String>,
    /// User-Agent pattern list.
    #[serde(default)]
    pub user_agent: Vec<String>,

    // Negative match conditions (exclusions)
    /// Exclude domains.
    #[serde(default)]
    pub not_domain: Vec<String>,
    /// Exclude geosite categories.
    #[serde(default)]
    pub not_geosite: Vec<String>,
    /// Exclude GeoIP countries.
    #[serde(default)]
    pub not_geoip: Vec<String>,
    /// Exclude IP CIDRs.
    #[serde(default)]
    pub not_ipcidr: Vec<String>,
    /// Exclude ports.
    #[serde(default)]
    pub not_port: Vec<String>,
    /// Exclude processes.
    #[serde(default)]
    pub not_process: Vec<String>,
    /// Exclude networks.
    #[serde(default)]
    pub not_network: Vec<String>,
    /// Exclude protocols.
    #[serde(default)]
    pub not_protocol: Vec<String>,
    /// Exclude ALPN protocols.
    #[serde(default)]
    pub not_alpn: Vec<String>,

    /// Target outbound name.
    #[serde(default)]
    pub outbound: Option<String>,
}

/// Routing table configuration.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct RouteIR {
    /// Routing rules (evaluated in order).
    #[serde(default)]
    pub rules: Vec<RuleIR>,
    /// Default outbound name (fallback).
    #[serde(default)]
    pub default: Option<String>,
}

/// Complete configuration intermediate representation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct ConfigIR {
    /// Inbound listeners.
    #[serde(default)]
    pub inbounds: Vec<InboundIR>,
    /// Outbound proxies.
    #[serde(default)]
    pub outbounds: Vec<OutboundIR>,
    /// Routing configuration.
    #[serde(default)]
    pub route: RouteIR,
}

impl OutboundIR {
    /// Return the string representation of the outbound type.
    #[must_use]
    pub fn ty_str(&self) -> &'static str {
        match self.ty {
            OutboundType::Direct => "direct",
            OutboundType::Http => "http",
            OutboundType::Socks => "socks",
            OutboundType::Block => "block",
            OutboundType::Selector => "selector",
            OutboundType::Shadowsocks => "shadowsocks",
            OutboundType::UrlTest => "urltest",
            OutboundType::Shadowtls => "shadowtls",
            OutboundType::Hysteria2 => "hysteria2",
            OutboundType::Tuic => "tuic",
            OutboundType::Vless => "vless",
            OutboundType::Vmess => "vmess",
            OutboundType::Trojan => "trojan",
            OutboundType::Ssh => "ssh",
        }
    }

    /// Validate REALITY configuration if enabled.
    ///
    /// # Errors
    /// Returns an error if REALITY is enabled but required fields are missing or malformed.
    pub fn validate_reality(&self) -> Result<(), String> {
        // Only validate if REALITY is explicitly enabled
        if let Some(true) = self.reality_enabled {
            let outbound_name = self.name.as_deref().unwrap_or("unnamed");

            // Validate public_key (must be 64 hex chars for X25519)
            if let Some(ref public_key) = self.reality_public_key {
                if !is_valid_hex(public_key) || public_key.len() != 64 {
                    return Err(format!(
                        "outbound '{outbound_name}': reality.public_key must be 64 hex characters (X25519 public key)"
                    ));
                }
            } else {
                return Err(format!(
                    "outbound '{outbound_name}': reality.public_key is required when reality is enabled"
                ));
            }

            // Validate short_id if present (0-16 hex chars, even length)
            if let Some(ref short_id) = self.reality_short_id {
                if !short_id.is_empty() {
                    if !is_valid_hex(short_id) {
                        return Err(format!(
                            "outbound '{outbound_name}': reality.short_id must be hex characters"
                        ));
                    }
                    if short_id.len() > 16 || short_id.len() % 2 != 0 {
                        return Err(format!(
                            "outbound '{outbound_name}': reality.short_id must be 0-16 hex chars (length multiple of 2)"
                        ));
                    }
                }
            }

            // Validate server_name is present
            if self
                .reality_server_name
                .as_ref()
                .is_none_or(String::is_empty)
            {
                return Err(format!(
                    "outbound '{outbound_name}': reality.server_name is required when reality is enabled"
                ));
            }
        }

        Ok(())
    }
}

/// Helper function to validate hex strings.
fn is_valid_hex(s: &str) -> bool {
    s.chars().all(|c| c.is_ascii_hexdigit())
}

impl ConfigIR {
    /// Check if any routing rule uses negation conditions.
    ///
    /// This is used to determine if the router needs to support negation logic.
    #[must_use]
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
                || !r.not_alpn.is_empty()
        })
    }

    /// Validate all outbound configurations.
    ///
    /// # Errors
    /// Returns a list of validation errors if any outbound configuration is invalid.
    pub fn validate(&self) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();

        // Validate REALITY configuration for all outbounds
        for outbound in &self.outbounds {
            let outbound_name = outbound.name.as_deref().unwrap_or("unnamed");

            if let Err(e) = outbound.validate_reality() {
                errors.push(e);
            }

            // Validate selector/urltest members
            if matches!(outbound.ty, OutboundType::Selector | OutboundType::UrlTest)
                && outbound.members.as_ref().is_none_or(Vec::is_empty)
            {
                errors.push(format!(
                    "outbound '{outbound_name}': selector/urltest requires at least one member"
                ));
            }

            // Validate Shadowsocks configuration
            if outbound.ty == OutboundType::Shadowsocks {
                Self::validate_shadowsocks(outbound, &mut errors);
            }

            // Validate TUIC configuration
            if outbound.ty == OutboundType::Tuic {
                Self::validate_tuic(outbound, &mut errors);
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    /// Validate Shadowsocks outbound configuration.
    fn validate_shadowsocks(outbound: &OutboundIR, errors: &mut Vec<String>) {
        let name = outbound.name.as_deref().unwrap_or("unnamed");

        if outbound.server.as_ref().is_none_or(|s| s.trim().is_empty()) {
            errors.push(format!("outbound '{name}': shadowsocks.server is required"));
        }
        if outbound.port.is_none() {
            errors.push(format!("outbound '{name}': shadowsocks.port is required"));
        }
        if outbound.password.as_ref().is_none_or(|p| p.trim().is_empty()) {
            errors.push(format!("outbound '{name}': shadowsocks.password is required"));
        }

        let method = outbound.method.as_deref().unwrap_or_default();
        let method_ok = matches!(
            method.to_ascii_lowercase().as_str(),
            "aes-256-gcm" | "chacha20-poly1305"
        );
        if !method_ok {
            errors.push(format!(
                "outbound '{name}': shadowsocks.method must be aes-256-gcm or chacha20-poly1305"
            ));
        }
    }

    /// Validate TUIC outbound configuration.
    fn validate_tuic(outbound: &OutboundIR, errors: &mut Vec<String>) {
        let name = outbound.name.as_deref().unwrap_or("unnamed");

        if outbound.server.as_ref().is_none_or(|s| s.trim().is_empty()) {
            errors.push(format!("outbound '{name}': tuic.server is required"));
        }
        if outbound.port.is_none() {
            errors.push(format!("outbound '{name}': tuic.port is required"));
        }

        match outbound.uuid.as_ref() {
            Some(uuid) if !uuid.trim().is_empty() => {
                if uuid::Uuid::parse_str(uuid).is_err() {
                    errors.push(format!(
                        "outbound '{name}': tuic.uuid must be a valid UUID string"
                    ));
                }
            }
            _ => errors.push(format!("outbound '{name}': tuic.uuid is required")),
        }

        if outbound.token.as_ref().is_none_or(|t| t.trim().is_empty()) {
            errors.push(format!("outbound '{name}': tuic.token is required"));
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
            reality_public_key: Some(
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string(),
            ),
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
            reality_public_key: Some(
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string(),
            ),
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
            reality_public_key: Some(
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string(),
            ),
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
            reality_public_key: Some(
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string(),
            ),
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

    #[test]
    fn tuic_validation_reports_missing_fields() {
        let mut cfg = ConfigIR::default();
        cfg.outbounds.push(OutboundIR {
            ty: OutboundType::Tuic,
            name: Some("tuic-out".to_string()),
            server: None,
            port: None,
            uuid: Some("not-a-uuid".to_string()),
            token: None,
            ..Default::default()
        });

        let result = cfg.validate();
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert!(errors.iter().any(|e| e.contains("tuic.server is required")));
        assert!(errors.iter().any(|e| e.contains("tuic.port is required")));
        assert!(errors
            .iter()
            .any(|e| e.contains("tuic.uuid must be a valid UUID string")));
        assert!(errors.iter().any(|e| e.contains("tuic.token is required")));
    }

    #[test]
    fn tuic_validation_accepts_complete_configuration() {
        let mut cfg = ConfigIR::default();
        cfg.outbounds.push(OutboundIR {
            ty: OutboundType::Tuic,
            name: Some("tuic-out".to_string()),
            server: Some("example.com".to_string()),
            port: Some(443),
            uuid: Some("12345678-1234-1234-1234-123456789abc".to_string()),
            token: Some("secret-token".to_string()),
            ..Default::default()
        });

        assert!(cfg.validate().is_ok());
    }
}
