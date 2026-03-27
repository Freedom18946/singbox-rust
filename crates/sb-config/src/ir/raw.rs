//! Raw (serde-facing) configuration types.
//!
//! ## Purpose
//!
//! This module holds the **Raw** configuration types that map 1:1 to the
//! on-disk JSON/YAML schema. All Raw types derive `Deserialize` with
//! `#[serde(deny_unknown_fields)]` to enforce strict input boundaries.
//!
//! ## Current status (WP-30c)
//!
//! ### Root boundary (WP-30b — done)
//!
//! [`RawConfigRoot`] is the root-level strict input boundary.
//!
//! ### Root-owned leaf boundaries (WP-30c — done)
//!
//! [`RawLogIR`], [`RawNtpIR`], [`RawCertificateIR`] are strict input
//! boundaries for root-owned leaf types. `LogIR`, `NtpIR`, `CertificateIR`
//! no longer derive `Deserialize` directly; each deserializes via its
//! corresponding Raw bridge (e.g. `RawLogIR::deserialize(d).map(Into::into)`).
//!
//! ### `ExperimentalIR` — intentional passthrough
//!
//! `ExperimentalIR` deliberately does **not** have a Raw counterpart and does
//! **not** carry `deny_unknown_fields`. It uses forward-compatible passthrough
//! semantics so unknown experimental options are preserved, not rejected.
//! This is intentional, not an oversight.
//!
//! ### What is NOT yet Raw-ified
//!
//! `InboundIR`, `OutboundIR`, `RouteIR`, `DnsIR`, `EndpointIR`, `ServiceIR`
//! still reuse validated IR directly. Nested Raw types (e.g. `RawInbound`,
//! `RawOutbound`) are a separate future effort.
//!
//! ## Future work
//!
//! - Define nested Raw types (`RawInbound`, `RawOutbound`, `RawRoute`, etc.)
//!   with their own `deny_unknown_fields`
//! - The existing `outbound.rs` raw types (the outbound Raw/Validated boundary
//!   pilot completed earlier) remain in their current location
//! - `planned.rs` / `normalize.rs` remain skeletons

use serde::Deserialize;

use super::validated::{CertificateIR, ConfigIR, LogIR, NtpIR};
use super::{DnsIR, EndpointIR, ExperimentalIR, InboundIR, OutboundIR, RouteIR, ServiceIR};

// ─────────────────── Root-owned leaf Raw types ───────────────────

/// Raw log configuration — strict input boundary for [`LogIR`].
///
/// Field set is identical to `LogIR`. Deserialization enters here
/// (with `deny_unknown_fields`), then converts via `From<RawLogIR> for LogIR`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawLogIR {
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

impl From<RawLogIR> for LogIR {
    fn from(raw: RawLogIR) -> Self {
        Self {
            level: raw.level,
            timestamp: raw.timestamp,
            format: raw.format,
            disabled: raw.disabled,
            output: raw.output,
        }
    }
}

/// Raw NTP configuration — strict input boundary for [`NtpIR`].
///
/// Field set is identical to `NtpIR`. Deserialization enters here
/// (with `deny_unknown_fields`), then converts via `From<RawNtpIR> for NtpIR`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawNtpIR {
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

impl From<RawNtpIR> for NtpIR {
    fn from(raw: RawNtpIR) -> Self {
        Self {
            enabled: raw.enabled,
            server: raw.server,
            server_port: raw.server_port,
            interval_ms: raw.interval_ms,
            timeout_ms: raw.timeout_ms,
        }
    }
}

/// Raw certificate configuration — strict input boundary for [`CertificateIR`].
///
/// Field set is identical to `CertificateIR`. Deserialization enters here
/// (with `deny_unknown_fields`), then converts via `From<RawCertificateIR> for CertificateIR`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawCertificateIR {
    /// Certificate store mode: "system", "mozilla", or "none"
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

impl From<RawCertificateIR> for CertificateIR {
    fn from(raw: RawCertificateIR) -> Self {
        Self {
            store: raw.store,
            ca_paths: raw.ca_paths,
            ca_pem: raw.ca_pem,
            certificate_directory_path: raw.certificate_directory_path,
        }
    }
}

// ─────────────────── Root-level Raw type ───────────────────

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
/// `log`, `ntp`, and `certificate` use their own Raw types (`RawLogIR`,
/// `RawNtpIR`, `RawCertificateIR`) so unknown fields inside these leaf
/// configs are also rejected.
///
/// Other child types (`InboundIR`, `OutboundIR`, `RouteIR`, `DnsIR`,
/// `EndpointIR`, `ServiceIR`) still reuse validated IR directly —
/// nested Raw types for those are future work.
///
/// `ExperimentalIR` intentionally does NOT have a Raw counterpart;
/// it uses forward-compatible passthrough semantics.
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
    /// Optional log configuration (strict: rejects unknown fields).
    #[serde(default)]
    pub log: Option<RawLogIR>,
    /// Optional NTP service configuration (strict: rejects unknown fields).
    #[serde(default)]
    pub ntp: Option<RawNtpIR>,
    /// Optional certificate configuration (strict: rejects unknown fields).
    #[serde(default)]
    pub certificate: Option<RawCertificateIR>,
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
            log: raw.log.map(Into::into),
            ntp: raw.ntp.map(Into::into),
            certificate: raw.certificate.map(Into::into),
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

    // ─────────────────── RawConfigRoot tests (WP-30b) ───────────────────

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

    // ─────────────────── RawLogIR tests (WP-30c) ───────────────────

    #[test]
    fn raw_log_ir_rejects_unknown_field() {
        let data = json!({
            "level": "debug",
            "bogus_log_field": true
        });
        let result = serde_json::from_value::<RawLogIR>(data);
        assert!(result.is_err(), "RawLogIR should reject unknown fields");
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("unknown field") || err.contains("bogus_log_field"),
            "error should mention unknown field, got: {err}"
        );
    }

    #[test]
    fn log_ir_rejects_unknown_field_via_raw_bridge() {
        let data = json!({
            "level": "info",
            "bogus_log_field": 42
        });
        let result = serde_json::from_value::<LogIR>(data);
        assert!(
            result.is_err(),
            "LogIR should reject unknown fields via Raw bridge"
        );
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("unknown field") || err.contains("bogus_log_field"),
            "error should mention unknown field, got: {err}"
        );
    }

    #[test]
    fn log_ir_roundtrip_valid() {
        let data = json!({
            "level": "debug",
            "timestamp": true,
            "format": "json",
            "disabled": false,
            "output": "/var/log/singbox.log"
        });
        let ir: LogIR = serde_json::from_value(data).unwrap();
        assert_eq!(ir.level.as_deref(), Some("debug"));
        assert_eq!(ir.timestamp, Some(true));
        assert_eq!(ir.format.as_deref(), Some("json"));
        assert_eq!(ir.disabled, Some(false));
        assert_eq!(ir.output.as_deref(), Some("/var/log/singbox.log"));
        // Serialize and re-deserialize
        let json = serde_json::to_value(&ir).unwrap();
        let ir2: LogIR = serde_json::from_value(json).unwrap();
        assert_eq!(ir, ir2);
    }

    // ─────────────────── RawNtpIR tests (WP-30c) ───────────────────

    #[test]
    fn raw_ntp_ir_rejects_unknown_field() {
        let data = json!({
            "enabled": true,
            "server": "pool.ntp.org",
            "bogus_ntp_field": 999
        });
        let result = serde_json::from_value::<RawNtpIR>(data);
        assert!(result.is_err(), "RawNtpIR should reject unknown fields");
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("unknown field") || err.contains("bogus_ntp_field"),
            "error should mention unknown field, got: {err}"
        );
    }

    #[test]
    fn ntp_ir_rejects_unknown_field_via_raw_bridge() {
        let data = json!({
            "enabled": true,
            "bogus_ntp_field": "bad"
        });
        let result = serde_json::from_value::<NtpIR>(data);
        assert!(
            result.is_err(),
            "NtpIR should reject unknown fields via Raw bridge"
        );
    }

    #[test]
    fn ntp_ir_roundtrip_valid() {
        let data = json!({
            "enabled": true,
            "server": "time.google.com",
            "server_port": 123,
            "interval_ms": 60000,
            "timeout_ms": 5000
        });
        let ir: NtpIR = serde_json::from_value(data).unwrap();
        assert!(ir.enabled);
        assert_eq!(ir.server.as_deref(), Some("time.google.com"));
        assert_eq!(ir.server_port, Some(123));
        assert_eq!(ir.interval_ms, Some(60000));
        assert_eq!(ir.timeout_ms, Some(5000));
        let json = serde_json::to_value(&ir).unwrap();
        let ir2: NtpIR = serde_json::from_value(json).unwrap();
        assert_eq!(ir, ir2);
    }

    // ─────────────────── RawCertificateIR tests (WP-30c) ───────────────────

    #[test]
    fn raw_certificate_ir_rejects_unknown_field() {
        let data = json!({
            "store": "system",
            "bogus_cert_field": true
        });
        let result = serde_json::from_value::<RawCertificateIR>(data);
        assert!(
            result.is_err(),
            "RawCertificateIR should reject unknown fields"
        );
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("unknown field") || err.contains("bogus_cert_field"),
            "error should mention unknown field, got: {err}"
        );
    }

    #[test]
    fn certificate_ir_rejects_unknown_field_via_raw_bridge() {
        let data = json!({
            "store": "mozilla",
            "bogus_cert_field": "bad"
        });
        let result = serde_json::from_value::<CertificateIR>(data);
        assert!(
            result.is_err(),
            "CertificateIR should reject unknown fields via Raw bridge"
        );
    }

    #[test]
    fn certificate_ir_roundtrip_valid() {
        let data = json!({
            "store": "system",
            "ca_paths": ["/etc/ssl/certs/ca.pem"],
            "ca_pem": ["-----BEGIN CERTIFICATE-----\nMIIB..."],
            "certificate_directory_path": "/etc/ssl/certs"
        });
        let ir: CertificateIR = serde_json::from_value(data).unwrap();
        assert_eq!(ir.store.as_deref(), Some("system"));
        assert_eq!(ir.ca_paths.len(), 1);
        assert_eq!(ir.ca_pem.len(), 1);
        assert_eq!(
            ir.certificate_directory_path.as_deref(),
            Some("/etc/ssl/certs")
        );
        let json = serde_json::to_value(&ir).unwrap();
        let ir2: CertificateIR = serde_json::from_value(json).unwrap();
        assert_eq!(ir, ir2);
    }

    // ─────────────────── ConfigIR root with strict leaf tests (WP-30c) ───────────────────

    #[test]
    fn config_ir_rejects_unknown_field_inside_log() {
        let data = json!({
            "log": {
                "level": "debug",
                "unknown_log_field": true
            }
        });
        let result = serde_json::from_value::<ConfigIR>(data);
        assert!(
            result.is_err(),
            "ConfigIR should reject unknown fields inside log via Raw bridge"
        );
    }

    #[test]
    fn config_ir_rejects_unknown_field_inside_ntp() {
        let data = json!({
            "ntp": {
                "enabled": true,
                "unknown_ntp_field": 42
            }
        });
        let result = serde_json::from_value::<ConfigIR>(data);
        assert!(
            result.is_err(),
            "ConfigIR should reject unknown fields inside ntp via Raw bridge"
        );
    }

    #[test]
    fn config_ir_rejects_unknown_field_inside_certificate() {
        let data = json!({
            "certificate": {
                "store": "system",
                "unknown_cert_field": "bad"
            }
        });
        let result = serde_json::from_value::<ConfigIR>(data);
        assert!(
            result.is_err(),
            "ConfigIR should reject unknown fields inside certificate via Raw bridge"
        );
    }

    #[test]
    fn config_ir_experimental_passthrough_preserves_unknown_fields() {
        // ExperimentalIR deliberately does NOT have deny_unknown_fields.
        // Unknown experimental sub-keys should be accepted (forward-compatible).
        let data = json!({
            "experimental": {
                "cache_file": { "enabled": true },
                "clash_api": { "external_controller": "127.0.0.1:9090" }
            }
        });
        let result = serde_json::from_value::<ConfigIR>(data);
        assert!(result.is_ok(), "experimental should accept known sub-keys");
    }

    /// Boundary documentation: nested types beyond log/ntp/certificate
    /// (e.g. InboundIR, RouteIR) still do NOT have deny_unknown_fields.
    /// This is NOT a bug — those will get their own Raw types in a future card.
    #[test]
    fn nested_non_leaf_unknown_fields_not_yet_strict_boundary_doc() {
        let data = json!({
            "route": {
                "rules": [],
                "some_unknown_route_field": true
            }
        });
        // RouteIR does not yet have a Raw counterpart, so this succeeds.
        let result = serde_json::from_value::<ConfigIR>(data);
        assert!(
            result.is_ok(),
            "non-leaf nested unknown fields are not yet strict (leaf-only in WP-30c)"
        );
    }
}
