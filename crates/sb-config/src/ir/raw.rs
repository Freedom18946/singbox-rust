//! Raw (serde-facing) configuration types — **root-level pilot**.
//!
//! ## Purpose
//!
//! This module holds the **Raw** configuration types that map 1:1 to the
//! on-disk JSON/YAML schema. All Raw types derive `Deserialize` with
//! `#[serde(deny_unknown_fields)]` to enforce strict input boundaries.
//!
//! ## Current status (WP-30b)
//!
//! [`RawConfigRoot`] is the **root-level strict input boundary**. It carries
//! `#[serde(deny_unknown_fields)]` so that any unknown top-level key in user
//! input is rejected at the serde layer. `ConfigIR` no longer derives
//! `Deserialize` directly; instead it deserializes via the `RawConfigRoot`
//! bridge (`RawConfigRoot::deserialize(d).map(Into::into)`).
//!
//! **Nested child types** (`InboundIR`, `OutboundIR`, `RouteIR`, `DnsIR`,
//! `EndpointIR`, `ServiceIR`, `ExperimentalIR`, etc.) are **still reused from
//! validated IR** — this is intentional. The current card is a root-level
//! pilot only. Nested Raw types (e.g. `RawInbound`, `RawOutbound`) are a
//! separate future effort.
//!
//! ## Future work
//!
//! - Define nested Raw types (`RawInbound`, `RawOutbound`, `RawRoute`, etc.)
//!   with their own `deny_unknown_fields`
//! - The existing `outbound.rs` raw types (the outbound Raw/Validated boundary
//!   pilot completed earlier) remain in their current location
//! - `planned.rs` / `normalize.rs` remain skeletons

use serde::Deserialize;

use super::validated::ConfigIR;
use super::{
    CertificateIR, DnsIR, EndpointIR, ExperimentalIR, InboundIR, LogIR, NtpIR, OutboundIR, RouteIR,
    ServiceIR,
};

/// Raw top-level configuration root — the serde entry point.
///
/// This struct maps 1:1 to the on-disk JSON schema and carries
/// `#[serde(deny_unknown_fields)]` so any unrecognized top-level key
/// is rejected at parse time.
///
/// Field names, types, and default semantics are identical to [`ConfigIR`].
/// The only difference is that `RawConfigRoot` is the deserialization target,
/// while `ConfigIR` is the validated domain type.
///
/// # Design note
///
/// Child field types currently reuse validated IR types (e.g. `InboundIR`,
/// `OutboundIR`). This is intentional — this card is a root-level strict
/// boundary pilot. Nested Raw types are future work.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawConfigRoot {
    /// Inbound listeners.
    #[serde(default)]
    pub inbounds: Vec<InboundIR>,
    /// Outbound proxies.
    #[serde(default)]
    pub outbounds: Vec<OutboundIR>,
    /// Routing configuration.
    #[serde(default)]
    pub route: RouteIR,
    /// Optional log configuration.
    #[serde(default)]
    pub log: Option<LogIR>,
    /// Optional NTP service configuration.
    #[serde(default)]
    pub ntp: Option<NtpIR>,
    /// Optional certificate configuration (global trust augmentation).
    #[serde(default)]
    pub certificate: Option<CertificateIR>,
    /// Optional DNS configuration.
    #[serde(default)]
    pub dns: Option<DnsIR>,
    /// Endpoint configurations (WireGuard, Tailscale, etc.).
    #[serde(default)]
    pub endpoints: Vec<EndpointIR>,
    /// Service configurations (Resolved, DERP, SSM, etc.).
    #[serde(default)]
    pub services: Vec<ServiceIR>,
    /// Optional experimental configuration blob (schema v2 passthrough).
    #[serde(default)]
    pub experimental: Option<ExperimentalIR>,
}

impl From<RawConfigRoot> for ConfigIR {
    fn from(raw: RawConfigRoot) -> Self {
        Self {
            inbounds: raw.inbounds,
            outbounds: raw.outbounds,
            route: raw.route,
            log: raw.log,
            ntp: raw.ntp,
            certificate: raw.certificate,
            dns: raw.dns,
            endpoints: raw.endpoints,
            services: raw.services,
            experimental: raw.experimental,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn raw_config_root_rejects_unknown_top_level_field() {
        let data = json!({
            "inbounds": [],
            "outbounds": [],
            "bogus_top_level": true
        });
        let result = serde_json::from_value::<RawConfigRoot>(data);
        assert!(
            result.is_err(),
            "unknown top-level field should be rejected"
        );
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("unknown field") || err.contains("bogus_top_level"),
            "error should mention unknown field, got: {err}"
        );
    }

    #[test]
    fn raw_config_root_parses_minimal_empty_config() {
        let data = json!({});
        let raw: RawConfigRoot = serde_json::from_value(data).unwrap();
        assert!(raw.inbounds.is_empty());
        assert!(raw.outbounds.is_empty());
        assert!(raw.log.is_none());
        assert!(raw.experimental.is_none());
    }

    #[test]
    fn raw_config_root_converts_to_config_ir() {
        let data = json!({
            "inbounds": [],
            "outbounds": [],
            "route": {},
            "log": { "level": "debug" },
            "experimental": {
                "clash_api": {
                    "external_controller": "127.0.0.1:9090"
                }
            }
        });
        let raw: RawConfigRoot = serde_json::from_value(data).unwrap();
        let ir: ConfigIR = raw.into();
        assert_eq!(ir.log.as_ref().unwrap().level.as_deref(), Some("debug"));
        assert!(ir.experimental.is_some());
    }

    #[test]
    fn config_ir_deserialize_rejects_unknown_top_level_field() {
        // ConfigIR deserialization now goes through RawConfigRoot bridge,
        // so unknown top-level fields must be rejected.
        let data = json!({
            "inbounds": [],
            "unknown_key": 42
        });
        let result = serde_json::from_value::<ConfigIR>(data);
        assert!(
            result.is_err(),
            "ConfigIR should reject unknown top-level fields via raw bridge"
        );
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("unknown field") || err.contains("unknown_key"),
            "error should mention unknown field, got: {err}"
        );
    }

    #[test]
    fn config_ir_deserialize_valid_root_config() {
        let data = json!({
            "inbounds": [],
            "outbounds": [],
            "route": {},
            "endpoints": [{
                "type": "wireguard",
                "tag": "wg0",
                "wireguard_private_key": "test-key"
            }],
            "services": [{
                "type": "resolved",
                "tag": "dns-svc"
            }],
            "log": { "level": "info" },
            "ntp": { "enabled": true, "server": "pool.ntp.org" },
            "certificate": { "store": "system" },
            "dns": { "servers": [] },
            "experimental": {
                "cache_file": { "enabled": true }
            }
        });
        let ir: ConfigIR = serde_json::from_value(data).unwrap();
        assert_eq!(ir.endpoints.len(), 1);
        assert_eq!(ir.services.len(), 1);
        assert_eq!(ir.log.as_ref().unwrap().level.as_deref(), Some("info"));
        assert!(ir.ntp.as_ref().unwrap().enabled);
        assert_eq!(
            ir.certificate.as_ref().unwrap().store.as_deref(),
            Some("system")
        );
        assert!(ir.dns.is_some());
        assert!(
            ir.experimental
                .as_ref()
                .unwrap()
                .cache_file
                .as_ref()
                .unwrap()
                .enabled
        );
    }

    #[test]
    fn config_ir_experimental_roundtrip() {
        let data = json!({
            "experimental": {
                "clash_api": {
                    "external_controller": "127.0.0.1:9090",
                    "secret": "test-secret"
                },
                "v2ray_api": {
                    "listen": "127.0.0.1:10085",
                    "stats": { "enabled": true, "inbounds": ["mixed-in"] }
                },
                "cache_file": {
                    "enabled": true,
                    "path": "/tmp/cache.db",
                    "store_fakeip": true
                }
            }
        });
        let ir: ConfigIR = serde_json::from_value(data.clone()).unwrap();
        let serialized = serde_json::to_value(&ir).unwrap();
        let ir2: ConfigIR = serde_json::from_value(serialized).unwrap();
        assert_eq!(ir.experimental, ir2.experimental);
    }

    #[test]
    fn config_ir_default_semantics_unchanged() {
        let def = ConfigIR::default();
        assert!(def.inbounds.is_empty());
        assert!(def.outbounds.is_empty());
        assert!(def.endpoints.is_empty());
        assert!(def.services.is_empty());
        assert!(def.log.is_none());
        assert!(def.ntp.is_none());
        assert!(def.certificate.is_none());
        assert!(def.dns.is_none());
        assert!(def.experimental.is_none());
        assert!(!def.has_any_negation());
        assert!(def.validate().is_ok());
    }

    /// Boundary documentation test: nested child types do NOT yet have
    /// deny_unknown_fields (that is future work). This test documents
    /// the current boundary — it is NOT a bug, just an explicit statement
    /// of what the root-level pilot covers.
    #[test]
    fn nested_unknown_fields_not_yet_strict_boundary_doc() {
        // An unknown field inside a nested child type (e.g. log) is currently
        // accepted because child types still use standard derive(Deserialize).
        // This will change when nested Raw types are implemented.
        let data = json!({
            "log": {
                "level": "debug",
                "nested_unknown": true
            }
        });
        // This should currently succeed (nested not yet strict).
        // When nested Raw types land, this test should be updated to assert error.
        let result = serde_json::from_value::<ConfigIR>(data);
        assert!(
            result.is_ok(),
            "nested unknown fields are not yet strict (root-level pilot only)"
        );
    }
}
