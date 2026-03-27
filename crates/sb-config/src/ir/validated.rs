//! Validated root-level IR types for the configuration model.
//!
//! This module holds the **Validated root IR** — the strongly-typed intermediate
//! representation that has already passed structural validation (field presence,
//! enum tag coverage, cross-reference consistency).
//!
//! ## Current contents
//!
//! - [`ConfigIR`] — the top-level configuration aggregate
//! - [`CertificateIR`] — global certificate/trust store configuration
//! - [`LogIR`] — logging configuration
//! - [`NtpIR`] — NTP service configuration
//! - `impl ConfigIR` — `validate()`, `has_any_negation()`, and per-protocol
//!   validation helpers
//!
//! ## Deserialization (WP-30b)
//!
//! `ConfigIR` no longer derives `Deserialize` directly. Instead, deserialization
//! goes through [`super::raw::RawConfigRoot`] which carries
//! `#[serde(deny_unknown_fields)]`, ensuring unknown top-level keys are rejected
//! at parse time. `Serialize` remains derived.
//!
//! ## Phase-3 roadmap (WP-30)
//!
//! ```text
//! raw.rs          →  RawConfigRoot (root-level pilot, WP-30b done)
//! validated.rs    →  (this module) strongly-typed Validated IR
//! planned.rs      →  RuntimePlan: defaults resolved, tags unique, refs bound (skeleton)
//! normalize.rs    →  IR normalization entry point (skeleton)
//! ```

use serde::{Deserialize, Serialize};

use super::raw::RawConfigRoot;
use super::{
    DnsIR, EndpointIR, ExperimentalIR, InboundIR, OutboundIR, OutboundType, RouteIR, ServiceIR,
};

/// Complete configuration intermediate representation.
///
/// Deserialization goes through [`RawConfigRoot`] (which carries
/// `#[serde(deny_unknown_fields)]`) so unknown top-level keys are
/// rejected at parse time. `Serialize` remains derived directly.
#[derive(Debug, Clone, Serialize, PartialEq, Default)]
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
    /// Optional log configuration
    #[serde(default)]
    pub log: Option<LogIR>,
    /// Optional NTP service configuration
    #[serde(default)]
    pub ntp: Option<NtpIR>,
    /// Optional certificate configuration (global trust augmentation)
    #[serde(default)]
    pub certificate: Option<CertificateIR>,
    /// Optional DNS configuration
    #[serde(default)]
    pub dns: Option<DnsIR>,
    /// Endpoint configurations (WireGuard, Tailscale, etc.)
    #[serde(default)]
    pub endpoints: Vec<EndpointIR>,
    /// Service configurations (Resolved, DERP, SSM, etc.)
    #[serde(default)]
    pub services: Vec<ServiceIR>,
    /// Optional experimental configuration blob (schema v2 passthrough).
    ///
    /// This mirrors Go's top-level `experimental` field and allows unknown or
    /// forward-compatible options to be preserved without strong typing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub experimental: Option<ExperimentalIR>,
}

impl<'de> Deserialize<'de> for ConfigIR {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        RawConfigRoot::deserialize(deserializer).map(Into::into)
    }
}

/// Certificate configuration (global)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct CertificateIR {
    /// Certificate store mode: "system", "mozilla", or "none"
    /// Defaults to "system" (Go parity)
    #[serde(default)]
    pub store: Option<String>,
    /// Additional CA certificate file paths (PEM)
    #[serde(default)]
    pub ca_paths: Vec<String>,
    /// Additional CA certificate PEM blocks (inline)
    #[serde(default)]
    pub ca_pem: Vec<String>,
    /// Directory path to load additional CA certificates from (recursive PEM scan)
    #[serde(default)]
    pub certificate_directory_path: Option<String>,
}

/// Log configuration (IR)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct LogIR {
    /// Log level: error|warn|info|debug|trace
    #[serde(default)]
    pub level: Option<String>,
    /// Include timestamp in logs
    #[serde(default)]
    pub timestamp: Option<bool>,
    /// Optional output format (non-standard extension): json|compact
    #[serde(default)]
    pub format: Option<String>,
    /// Disable logging entirely (Go parity: log.disabled)
    #[serde(default)]
    pub disabled: Option<bool>,
    /// Output destination: stdout/stderr/path (Go parity: log.output)
    #[serde(default)]
    pub output: Option<String>,
}

/// NTP service configuration (IR)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct NtpIR {
    /// Enable NTP service
    #[serde(default)]
    pub enabled: bool,
    /// NTP server hostname (without port) or host:port
    #[serde(default)]
    pub server: Option<String>,
    /// NTP server port (e.g., 123)
    #[serde(default)]
    pub server_port: Option<u16>,
    /// Sync interval in milliseconds
    #[serde(default)]
    pub interval_ms: Option<u64>,
    /// Timeout in milliseconds (optional)
    #[serde(default)]
    pub timeout_ms: Option<u64>,
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
                || !r.not_process_name.is_empty()
                || !r.not_network.is_empty()
                || !r.not_protocol.is_empty()
                || !r.not_alpn.is_empty()
                || !r.not_wifi_ssid.is_empty()
                || !r.not_wifi_bssid.is_empty()
                || !r.not_rule_set.is_empty()
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

            // Validate ShadowTLS configuration
            if outbound.ty == OutboundType::Shadowtls {
                Self::validate_shadowtls(outbound, &mut errors);
            }

            // Validate TUIC configuration
            if outbound.ty == OutboundType::Tuic {
                Self::validate_tuic(outbound, &mut errors);
            }

            // Validate transport conflicts (WS/H2/HTTPUpgrade/gRPC are mutually exclusive)
            if let Some(e) = Self::validate_transport_conflicts(outbound) {
                errors.push(format!("outbound '{outbound_name}': {e}"));
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
        if outbound
            .password
            .as_ref()
            .is_none_or(|p| p.trim().is_empty())
        {
            errors.push(format!(
                "outbound '{name}': shadowsocks.password is required"
            ));
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

    /// Validate ShadowTLS outbound configuration.
    fn validate_shadowtls(outbound: &OutboundIR, errors: &mut Vec<String>) {
        let name = outbound.name.as_deref().unwrap_or("unnamed");

        if outbound.server.as_ref().is_none_or(|s| s.trim().is_empty()) {
            errors.push(format!("outbound '{name}': shadowtls.server is required"));
        }
        if outbound.port.is_none() {
            errors.push(format!("outbound '{name}': shadowtls.port is required"));
        }
        if outbound
            .password
            .as_ref()
            .is_none_or(|p| p.trim().is_empty())
        {
            errors.push(format!("outbound '{name}': shadowtls.password is required"));
        }

        if let Some(version) = outbound.version {
            if !(1..=3).contains(&version) {
                errors.push(format!(
                    "outbound '{name}': shadowtls.version must be 1, 2, or 3"
                ));
            }
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

    /// Validate transport conflicts in a single outbound IR.
    ///
    /// The application-layer transports WebSocket (ws), HTTP/2 (h2), HTTP Upgrade (httpupgrade)
    /// and gRPC (grpc) are mutually exclusive. They cannot be enabled at the same time via either
    /// explicit transport chain (e.g. transport: ["ws", "h2"]) or via hint fields
    /// (e.g. simultaneously providing `ws_*` and `h2_*` fields).
    fn validate_transport_conflicts(outbound: &OutboundIR) -> Option<String> {
        // Detect presence from explicit chain
        let mut ws = false;
        let mut h2 = false;
        let mut hup = false;
        let mut grpc = false;

        if let Some(chain) = outbound.transport.as_ref() {
            for t in chain {
                let t = t.to_ascii_lowercase();
                match t.as_str() {
                    "ws" | "websocket" => ws = true,
                    "h2" | "http2" => h2 = true,
                    "httpupgrade" | "http_upgrade" => hup = true,
                    "grpc" => grpc = true,
                    _ => {}
                }
            }
        }

        // Detect presence from hint fields
        ws |= outbound.ws_path.is_some() || outbound.ws_host.is_some();
        h2 |= outbound.h2_path.is_some() || outbound.h2_host.is_some();
        hup |= outbound.http_upgrade_path.is_some() || !outbound.http_upgrade_headers.is_empty();
        grpc |= outbound.grpc_service.is_some()
            || outbound.grpc_method.is_some()
            || outbound.grpc_authority.is_some()
            || !outbound.grpc_metadata.is_empty();

        let count = ws as u8 + h2 as u8 + hup as u8 + grpc as u8;
        if count > 1 {
            let mut kinds = Vec::new();
            if ws {
                kinds.push("ws");
            }
            if h2 {
                kinds.push("h2");
            }
            if hup {
                kinds.push("httpupgrade");
            }
            if grpc {
                kinds.push("grpc");
            }
            return Some(format!(
                "conflicting transports selected: {} (select at most one of ws/h2/httpupgrade/grpc)",
                kinds.join(", ")
            ));
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::super::{EndpointType, RuleIR, ServiceType};
    use super::*;
    use serde_json::json;

    #[test]
    fn config_ir_with_endpoints_and_services() {
        let data = json!({
            "inbounds": [],
            "outbounds": [],
            "route": {},
            "endpoints": [
                {
                    "type": "wireguard",
                    "tag": "wg0",
                    "wireguard_private_key": "test-key"
                }
            ],
            "services": [
                {
                    "type": "resolved",
                    "tag": "dns-svc"
                }
            ]
        });
        let config: ConfigIR = serde_json::from_value(data).unwrap();
        assert_eq!(config.endpoints.len(), 1);
        assert_eq!(config.services.len(), 1);
        assert_eq!(config.endpoints[0].ty, EndpointType::Wireguard);
        assert_eq!(config.services[0].ty, ServiceType::Resolved);
    }

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

    #[test]
    fn shadowtls_validation_reports_missing_password_and_bad_version() {
        let mut cfg = ConfigIR::default();
        cfg.outbounds.push(OutboundIR {
            ty: OutboundType::Shadowtls,
            name: Some("shadowtls-out".to_string()),
            server: Some("example.com".to_string()),
            port: Some(443),
            version: Some(9),
            ..Default::default()
        });

        let result = cfg.validate();
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert!(errors
            .iter()
            .any(|e| e.contains("shadowtls.password is required")));
        assert!(errors
            .iter()
            .any(|e| e.contains("shadowtls.version must be 1, 2, or 3")));
    }

    #[test]
    fn transport_conflict_detects_ws_and_h2_hints() {
        let mut cfg = ConfigIR::default();
        cfg.outbounds.push(OutboundIR {
            ty: OutboundType::Vmess,
            name: Some("vmess-out".to_string()),
            ws_path: Some("/ws".to_string()),
            h2_host: Some("example.com".to_string()),
            ..Default::default()
        });

        let result = cfg.validate();
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert!(errors
            .iter()
            .any(|e| e.contains("conflicting transports selected")));
    }

    #[test]
    fn transport_conflict_detects_chain_multiple() {
        let mut cfg = ConfigIR::default();
        cfg.outbounds.push(OutboundIR {
            ty: OutboundType::Vless,
            name: Some("vless-out".to_string()),
            transport: Some(vec!["tls".into(), "ws".into(), "grpc".into()]),
            ..Default::default()
        });

        let result = cfg.validate();
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert!(errors
            .iter()
            .any(|e| e.contains("conflicting transports selected: ws, grpc")));
    }

    #[test]
    fn transport_single_ok_ws() {
        let mut cfg = ConfigIR::default();
        cfg.outbounds.push(OutboundIR {
            ty: OutboundType::Vless,
            name: Some("vless-ws".to_string()),
            ws_path: Some("/".to_string()),
            tls_sni: Some("example.com".to_string()),
            ..Default::default()
        });
        assert!(cfg.validate().is_ok());
    }
}
