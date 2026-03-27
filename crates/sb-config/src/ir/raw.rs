//! Raw (serde-facing) configuration types.
//!
//! ## Purpose
//!
//! This module holds the **Raw** configuration types that map 1:1 to the
//! on-disk JSON/YAML schema. All Raw types derive `Deserialize` with
//! `#[serde(deny_unknown_fields)]` to enforce strict input boundaries.
//!
//! ## Current status (WP-30d)
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
//! ### DNS nested boundary pilot (WP-30d — done)
//!
//! [`RawDnsServerIR`], [`RawDnsRuleIR`], [`RawDnsHostIR`], and [`RawDnsIR`]
//! are now the strict nested Raw boundary for the DNS subtree. `DnsServerIR`,
//! `DnsRuleIR`, `DnsHostIR`, and `DnsIR` no longer derive `Deserialize`
//! directly; each deserializes via its Raw bridge, so unknown DNS nested
//! fields are rejected at parse time.
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
//! `InboundIR`, `OutboundIR`, `RouteIR`, `EndpointIR`, and `ServiceIR` still
//! reuse validated IR directly. Nested Raw types for those remain a separate
//! future effort.
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
use super::{
    DnsHostIR, DnsIR, DnsRuleIR, DnsServerIR, EndpointIR, ExperimentalIR, InboundIR, OutboundIR,
    RouteIR, ServiceIR,
};

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

// ─────────────────── DNS nested Raw types ───────────────────

/// Raw DNS server configuration — strict input boundary for [`DnsServerIR`].
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawDnsServerIR {
    /// Upstream tag (unique)
    pub tag: String,
    /// Address scheme for this upstream.
    pub address: String,
    /// Optional SNI override (for DoT/DoQ/DoH3)
    #[serde(default)]
    pub sni: Option<String>,
    /// EDNS0 Client Subnet override for this upstream
    #[serde(default)]
    pub client_subnet: Option<String>,
    /// Per-upstream additional CA files (PEM)
    #[serde(default)]
    pub ca_paths: Vec<String>,
    /// Per-upstream additional CA PEM blocks
    #[serde(default)]
    pub ca_pem: Vec<String>,
    /// Skip certificate verification (testing only)
    #[serde(default)]
    pub skip_cert_verify: Option<bool>,
    /// Address resolver (server tag for resolving this server's address)
    #[serde(default)]
    pub address_resolver: Option<String>,
    /// Address resolution strategy (prefer_ipv4, prefer_ipv6, ipv4_only, ipv6_only)
    #[serde(default)]
    pub address_strategy: Option<String>,
    /// Address resolution fallback delay (e.g., "300ms")
    #[serde(default)]
    pub address_fallback_delay: Option<String>,
    /// Query strategy for this server (prefer_ipv4, prefer_ipv6, ipv4_only, ipv6_only)
    #[serde(default)]
    pub strategy: Option<String>,
    /// Outbound detour for this server
    #[serde(default)]
    pub detour: Option<String>,
    /// Server type hint from GUI (e.g. "fakeip", "hosts", "local", etc.)
    /// When present, takes priority over address-prefix guessing.
    #[serde(default, rename = "type")]
    pub server_type: Option<String>,
    /// Resolved transport: service tag.
    #[serde(default)]
    pub service: Option<String>,
    /// Resolved transport: accept default resolvers.
    #[serde(default)]
    pub accept_default_resolvers: Option<bool>,
    /// FakeIP: IPv4 range (default "198.18.0.0/15")
    #[serde(default)]
    pub inet4_range: Option<String>,
    /// FakeIP: IPv6 range (default "fc00::/18")
    #[serde(default)]
    pub inet6_range: Option<String>,
    /// Hosts: file paths to load /etc/hosts-format files
    #[serde(default)]
    pub hosts_path: Vec<String>,
    /// Hosts: predefined domain→IP mappings
    #[serde(default)]
    pub predefined: Option<serde_json::Value>,
}

impl From<RawDnsServerIR> for DnsServerIR {
    fn from(raw: RawDnsServerIR) -> Self {
        Self {
            tag: raw.tag,
            address: raw.address,
            sni: raw.sni,
            client_subnet: raw.client_subnet,
            ca_paths: raw.ca_paths,
            ca_pem: raw.ca_pem,
            skip_cert_verify: raw.skip_cert_verify,
            address_resolver: raw.address_resolver,
            address_strategy: raw.address_strategy,
            address_fallback_delay: raw.address_fallback_delay,
            strategy: raw.strategy,
            detour: raw.detour,
            server_type: raw.server_type,
            service: raw.service,
            accept_default_resolvers: raw.accept_default_resolvers,
            inet4_range: raw.inet4_range,
            inet6_range: raw.inet6_range,
            hosts_path: raw.hosts_path,
            predefined: raw.predefined,
        }
    }
}

/// Raw DNS rule configuration — strict input boundary for [`DnsRuleIR`].
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawDnsRuleIR {
    #[serde(default)]
    pub domain_suffix: Vec<String>,
    #[serde(default)]
    pub domain: Vec<String>,
    #[serde(default)]
    pub keyword: Vec<String>,
    #[serde(default)]
    pub server: Option<String>,
    #[serde(default)]
    pub priority: Option<u32>,
    #[serde(default)]
    pub query_type: Vec<String>,
    #[serde(default)]
    pub rule_set: Vec<String>,
    #[serde(default)]
    pub domain_regex: Vec<String>,
    #[serde(default)]
    pub geosite: Vec<String>,
    #[serde(default)]
    pub geoip: Vec<String>,
    #[serde(default)]
    pub source_ip_cidr: Vec<String>,
    #[serde(default)]
    pub ip_cidr: Vec<String>,
    #[serde(default)]
    pub port: Vec<String>,
    #[serde(default)]
    pub source_port: Vec<String>,
    #[serde(default)]
    pub process_name: Vec<String>,
    #[serde(default)]
    pub process_path: Vec<String>,
    #[serde(default)]
    pub package_name: Vec<String>,
    #[serde(default)]
    pub wifi_ssid: Vec<String>,
    #[serde(default)]
    pub wifi_bssid: Vec<String>,
    #[serde(default)]
    pub invert: bool,
    #[serde(default)]
    pub ip_is_private: Option<bool>,
    #[serde(default)]
    pub source_ip_is_private: Option<bool>,
    #[serde(default)]
    pub ip_accept_any: Option<bool>,
    #[serde(default)]
    pub rule_set_ip_cidr_match_source: Option<bool>,
    #[serde(default)]
    pub rule_set_ip_cidr_accept_empty: Option<bool>,
    #[serde(default)]
    pub clash_mode: Option<String>,
    #[serde(default)]
    pub network_is_expensive: Option<bool>,
    #[serde(default)]
    pub network_is_constrained: Option<bool>,
    #[serde(default)]
    pub action: Option<String>,
    #[serde(default)]
    pub rewrite_ttl: Option<u32>,
    #[serde(default)]
    pub client_subnet: Option<String>,
    #[serde(default)]
    pub disable_cache: Option<bool>,
    #[serde(default)]
    pub address_limit: Option<u32>,
    #[serde(default)]
    pub rewrite_ip: Option<Vec<String>>,
    #[serde(default)]
    pub rcode: Option<String>,
    #[serde(default)]
    pub answer: Option<Vec<String>>,
    #[serde(default)]
    pub ns: Option<Vec<String>>,
    #[serde(default)]
    pub extra: Option<Vec<String>>,
}

impl From<RawDnsRuleIR> for DnsRuleIR {
    fn from(raw: RawDnsRuleIR) -> Self {
        Self {
            domain_suffix: raw.domain_suffix,
            domain: raw.domain,
            keyword: raw.keyword,
            server: raw.server,
            priority: raw.priority,
            query_type: raw.query_type,
            rule_set: raw.rule_set,
            domain_regex: raw.domain_regex,
            geosite: raw.geosite,
            geoip: raw.geoip,
            source_ip_cidr: raw.source_ip_cidr,
            ip_cidr: raw.ip_cidr,
            port: raw.port,
            source_port: raw.source_port,
            process_name: raw.process_name,
            process_path: raw.process_path,
            package_name: raw.package_name,
            wifi_ssid: raw.wifi_ssid,
            wifi_bssid: raw.wifi_bssid,
            invert: raw.invert,
            ip_is_private: raw.ip_is_private,
            source_ip_is_private: raw.source_ip_is_private,
            ip_accept_any: raw.ip_accept_any,
            rule_set_ip_cidr_match_source: raw.rule_set_ip_cidr_match_source,
            rule_set_ip_cidr_accept_empty: raw.rule_set_ip_cidr_accept_empty,
            clash_mode: raw.clash_mode,
            network_is_expensive: raw.network_is_expensive,
            network_is_constrained: raw.network_is_constrained,
            action: raw.action,
            rewrite_ttl: raw.rewrite_ttl,
            client_subnet: raw.client_subnet,
            disable_cache: raw.disable_cache,
            address_limit: raw.address_limit,
            rewrite_ip: raw.rewrite_ip,
            rcode: raw.rcode,
            answer: raw.answer,
            ns: raw.ns,
            extra: raw.extra,
        }
    }
}

/// Raw static hosts mapping entry — strict input boundary for [`DnsHostIR`].
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawDnsHostIR {
    /// Domain
    pub domain: String,
    /// IP list (string form)
    #[serde(default)]
    pub ips: Vec<String>,
}

impl From<RawDnsHostIR> for DnsHostIR {
    fn from(raw: RawDnsHostIR) -> Self {
        Self {
            domain: raw.domain,
            ips: raw.ips,
        }
    }
}

/// Raw DNS subtree — strict nested input boundary for [`DnsIR`].
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawDnsIR {
    /// Upstream servers
    #[serde(default)]
    pub servers: Vec<RawDnsServerIR>,
    /// Routing rules
    #[serde(default)]
    pub rules: Vec<RawDnsRuleIR>,
    /// Default upstream tag (fallback)
    #[serde(default)]
    pub default: Option<String>,
    /// Final/fallback server tag (Go parity: "final" field)
    #[serde(default, rename = "final")]
    pub final_server: Option<String>,
    /// Disable caching globally
    #[serde(default)]
    pub disable_cache: Option<bool>,
    /// Global timeout for DNS queries (ms)
    #[serde(default)]
    pub timeout_ms: Option<u64>,
    /// Default/min/max/negative TTLs (seconds)
    #[serde(default)]
    pub ttl_default_s: Option<u64>,
    #[serde(default)]
    pub ttl_min_s: Option<u64>,
    #[serde(default)]
    pub ttl_max_s: Option<u64>,
    #[serde(default)]
    pub ttl_neg_s: Option<u64>,
    /// EDNS0 Client Subnet (ECS) value.
    #[serde(default)]
    pub client_subnet: Option<String>,
    /// Reverse mapping override.
    #[serde(default)]
    pub reverse_mapping: Option<bool>,
    /// Resolution strategy.
    #[serde(default)]
    pub strategy: Option<String>,
    /// Use independent cache for this server/config.
    #[serde(default)]
    pub independent_cache: Option<bool>,
    /// When true, cached DNS entries never expire based on TTL.
    #[serde(default)]
    pub disable_expire: Option<bool>,
    /// FakeIP settings
    #[serde(default)]
    pub fakeip_enabled: Option<bool>,
    #[serde(default)]
    pub fakeip_v4_base: Option<String>,
    #[serde(default)]
    pub fakeip_v4_mask: Option<u8>,
    #[serde(default)]
    pub fakeip_v6_base: Option<String>,
    #[serde(default)]
    pub fakeip_v6_mask: Option<u8>,
    /// Pool/concurrency strategy
    #[serde(default)]
    pub pool_strategy: Option<String>,
    #[serde(default)]
    pub pool_race_window_ms: Option<u64>,
    #[serde(default)]
    pub pool_he_race_ms: Option<u64>,
    #[serde(default)]
    pub pool_he_order: Option<String>,
    #[serde(default)]
    pub pool_max_inflight: Option<u64>,
    #[serde(default)]
    pub pool_per_host_inflight: Option<u64>,
    /// Static hosts mapping and TTL
    #[serde(default)]
    pub hosts: Vec<RawDnsHostIR>,
    #[serde(default)]
    pub hosts_ttl_s: Option<u64>,
}

impl From<RawDnsIR> for DnsIR {
    fn from(raw: RawDnsIR) -> Self {
        Self {
            servers: raw.servers.into_iter().map(Into::into).collect(),
            rules: raw.rules.into_iter().map(Into::into).collect(),
            default: raw.default,
            final_server: raw.final_server,
            disable_cache: raw.disable_cache,
            timeout_ms: raw.timeout_ms,
            ttl_default_s: raw.ttl_default_s,
            ttl_min_s: raw.ttl_min_s,
            ttl_max_s: raw.ttl_max_s,
            ttl_neg_s: raw.ttl_neg_s,
            client_subnet: raw.client_subnet,
            reverse_mapping: raw.reverse_mapping,
            strategy: raw.strategy,
            independent_cache: raw.independent_cache,
            disable_expire: raw.disable_expire,
            fakeip_enabled: raw.fakeip_enabled,
            fakeip_v4_base: raw.fakeip_v4_base,
            fakeip_v4_mask: raw.fakeip_v4_mask,
            fakeip_v6_base: raw.fakeip_v6_base,
            fakeip_v6_mask: raw.fakeip_v6_mask,
            pool_strategy: raw.pool_strategy,
            pool_race_window_ms: raw.pool_race_window_ms,
            pool_he_race_ms: raw.pool_he_race_ms,
            pool_he_order: raw.pool_he_order,
            pool_max_inflight: raw.pool_max_inflight,
            pool_per_host_inflight: raw.pool_per_host_inflight,
            hosts: raw.hosts.into_iter().map(Into::into).collect(),
            hosts_ttl_s: raw.hosts_ttl_s,
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
/// configs are also rejected. `dns` now uses [`RawDnsIR`] and therefore
/// rejects unknown fields across the DNS nested subtree as well.
///
/// Other child types (`InboundIR`, `OutboundIR`, `RouteIR`, `EndpointIR`,
/// `ServiceIR`) still reuse validated IR directly —
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
    /// Optional DNS configuration (strict: rejects unknown fields).
    #[serde(default)]
    pub dns: Option<RawDnsIR>,
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
            dns: raw.dns.map(Into::into),
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

    // ─────────────────── Raw DNS tests (WP-30d) ───────────────────

    #[test]
    fn raw_dns_server_ir_rejects_unknown_field() {
        let data = json!({
            "tag": "dns-1",
            "address": "udp://1.1.1.1",
            "bogus_dns_server_field": true
        });
        let result = serde_json::from_value::<RawDnsServerIR>(data);
        assert!(
            result.is_err(),
            "RawDnsServerIR should reject unknown fields"
        );
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("unknown field") || err.contains("bogus_dns_server_field"),
            "error should mention unknown field, got: {err}"
        );
    }

    #[test]
    fn raw_dns_rule_ir_rejects_unknown_field() {
        let data = json!({
            "server": "dns-1",
            "bogus_dns_rule_field": true
        });
        let result = serde_json::from_value::<RawDnsRuleIR>(data);
        assert!(result.is_err(), "RawDnsRuleIR should reject unknown fields");
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("unknown field") || err.contains("bogus_dns_rule_field"),
            "error should mention unknown field, got: {err}"
        );
    }

    #[test]
    fn raw_dns_host_ir_rejects_unknown_field() {
        let data = json!({
            "domain": "example.com",
            "bogus_dns_host_field": true
        });
        let result = serde_json::from_value::<RawDnsHostIR>(data);
        assert!(result.is_err(), "RawDnsHostIR should reject unknown fields");
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("unknown field") || err.contains("bogus_dns_host_field"),
            "error should mention unknown field, got: {err}"
        );
    }

    #[test]
    fn raw_dns_ir_rejects_unknown_field() {
        let data = json!({
            "servers": [],
            "bogus_dns_field": true
        });
        let result = serde_json::from_value::<RawDnsIR>(data);
        assert!(result.is_err(), "RawDnsIR should reject unknown fields");
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("unknown field") || err.contains("bogus_dns_field"),
            "error should mention unknown field, got: {err}"
        );
    }

    // ─────────────────── ConfigIR root with strict nested tests ───────────────────

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
    fn config_ir_accepts_valid_dns_subtree_via_raw_bridge() {
        let data = json!({
            "dns": {
                "servers": [
                    {
                        "tag": "dns-1",
                        "address": "udp://1.1.1.1",
                        "type": "udp"
                    }
                ],
                "rules": [
                    {
                        "domain_suffix": [".example.com"],
                        "server": "dns-1"
                    }
                ],
                "hosts": [
                    {
                        "domain": "localhost",
                        "ips": ["127.0.0.1"]
                    }
                ],
                "final": "dns-1"
            }
        });
        let ir = serde_json::from_value::<ConfigIR>(data).unwrap();
        let dns = ir.dns.expect("dns should parse through RawDnsIR");
        assert_eq!(dns.servers.len(), 1);
        assert_eq!(dns.rules.len(), 1);
        assert_eq!(dns.hosts.len(), 1);
        assert_eq!(dns.final_server.as_deref(), Some("dns-1"));
    }

    #[test]
    fn config_ir_rejects_unknown_field_inside_dns_subtree() {
        let data = json!({
            "dns": {
                "servers": [],
                "unknown_dns_field": true
            }
        });
        let result = serde_json::from_value::<ConfigIR>(data);
        assert!(
            result.is_err(),
            "ConfigIR should reject unknown fields inside dns via Raw bridge"
        );
    }

    #[test]
    fn config_ir_rejects_unknown_field_inside_dns_server_subtree() {
        let data = json!({
            "dns": {
                "servers": [
                    {
                        "tag": "dns-1",
                        "address": "udp://1.1.1.1",
                        "unknown_dns_server_field": true
                    }
                ]
            }
        });
        let result = serde_json::from_value::<ConfigIR>(data);
        assert!(
            result.is_err(),
            "ConfigIR should reject unknown fields inside dns.servers via Raw bridge"
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

    /// Boundary documentation: route/inbound/outbound/endpoint/service nested
    /// trees still do NOT have nested Raw types. DNS is now strict; these
    /// remaining domains are future work, not regressions from WP-30d.
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
        assert!(result.is_ok(), "route remains outside nested Raw in WP-30d");
    }
}
