//! Raw (serde-facing) configuration types.
//!
//! ## Purpose
//!
//! This module holds the **Raw** configuration types that map 1:1 to the
//! on-disk JSON/YAML schema. All Raw types derive `Deserialize` with
//! `#[serde(deny_unknown_fields)]` to enforce strict input boundaries.
//!
//! ## Current status (WP-30i)
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
//! ### Route nested boundary pilot (WP-30e — done)
//!
//! [`RawRuleIR`], [`RawDomainResolveOptionsIR`], [`RawRuleSetIR`], and
//! [`RawRouteIR`] are the strict nested Raw boundary for the route subtree.
//! `RuleIR`, `DomainResolveOptionsIR`, `RuleSetIR`, and `RouteIR` no longer
//! derive `Deserialize` directly; each deserializes via its Raw bridge, so
//! unknown route nested fields are rejected at parse time.
//!
//! `RuleAction` is intentionally NOT Raw-ified — it stays as the validated
//! enum with kebab-case serde, `as_str()`, and `from_str_opt()` unchanged.
//!
//! ### Endpoint nested boundary pilot (WP-30f — done)
//!
//! [`RawWireGuardPeerIR`] and [`RawEndpointIR`] are the strict nested Raw
//! boundary for the endpoint subtree. `WireGuardPeerIR` and `EndpointIR` no
//! longer derive `Deserialize` directly; each deserializes via its Raw bridge,
//! so unknown endpoint nested fields are rejected at parse time.
//!
//! `EndpointType` is intentionally NOT Raw-ified — it stays as the validated
//! enum with lowercase serde unchanged.
//!
//! ### Service nested boundary pilot (WP-30g — done)
//!
//! [`RawServiceIR`], [`RawInboundTlsOptionsIR`], [`RawDerpStunOptionsIR`],
//! [`RawDerpDomainResolverIR`], [`RawDerpDialOptionsIR`],
//! [`RawDerpVerifyClientUrlIR`], [`RawDerpOutboundTlsOptionsIR`], and
//! [`RawDerpMeshPeerIR`] are the strict nested Raw boundary for the service
//! subtree. `ServiceIR`, `InboundTlsOptionsIR`, `DerpStunOptionsIR`,
//! `DerpDomainResolverIR`, `DerpDialOptionsIR`, `DerpVerifyClientUrlIR`,
//! `DerpOutboundTlsOptionsIR`, and `DerpMeshPeerIR` no longer derive
//! `Deserialize` directly; each deserializes via its Raw bridge, so unknown
//! service nested fields are rejected at parse time.
//!
//! `ServiceType`, `Listable`, and `StringOrObj` are intentionally NOT
//! Raw-ified — they remain as validated generic wrappers.
//!
//! ### Inbound nested boundary pilot (WP-30h — done)
//!
//! [`RawInboundIR`], [`RawTunOptionsIR`], [`RawShadowsocksUserIR`],
//! [`RawVmessUserIR`], [`RawVlessUserIR`], [`RawTrojanUserIR`],
//! [`RawShadowTlsUserIR`], [`RawShadowTlsHandshakeIR`], [`RawAnyTlsUserIR`],
//! [`RawHysteria2UserIR`], [`RawTuicUserIR`], and [`RawHysteriaUserIR`] are the
//! strict nested Raw boundary for the inbound subtree. `InboundIR`,
//! `TunOptionsIR`, and all inbound user types no longer derive `Deserialize`
//! directly; each deserializes via its Raw bridge, so unknown inbound nested
//! fields are rejected at parse time.
//!
//! `InboundType` is intentionally NOT Raw-ified — it stays as the validated
//! enum with lowercase serde unchanged.
//!
//! ### Outbound nested boundary pilot (WP-30i — done)
//!
//! [`RawOutboundIR`], [`RawHeaderEntry`], [`RawCredentials`], [`RawBrutalIR`],
//! and [`RawMultiplexOptionsIR`] are the strict nested Raw boundary for the
//! outbound subtree. `OutboundIR`, `HeaderEntry`, `Credentials`,
//! `MultiplexOptionsIR`, and `BrutalIR` no longer derive `Deserialize`
//! directly; each deserializes via its Raw bridge, so unknown outbound nested
//! fields are rejected at parse time.
//!
//! `OutboundType` is intentionally NOT Raw-ified — it stays as the validated
//! enum with lowercase serde and `ty_str()` unchanged.
//!
//! `Credentials`, `MultiplexOptionsIR`, and `BrutalIR` are bridged because
//! they are direct outbound helpers, not as a broader shared-type cleanup.
//!
//! ### `ExperimentalIR` — intentional passthrough
//!
//! `ExperimentalIR` deliberately does **not** have a Raw counterpart and does
//! **not** carry `deny_unknown_fields`. It uses forward-compatible passthrough
//! semantics so unknown experimental options are preserved, not rejected.
//! This is intentional, not an oversight.
//!
//! ### Masquerade inbound helper Raw boundary (WP-30j — done)
//!
//! [`RawMasqueradeIR`], [`RawMasqueradeFileIR`], [`RawMasqueradeProxyIR`], and
//! [`RawMasqueradeStringIR`] are the strict nested Raw boundary for the
//! Hysteria2 masquerade inbound helper subtree. `MasqueradeIR`, `MasqueradeFileIR`,
//! `MasqueradeProxyIR`, and `MasqueradeStringIR` no longer derive `Deserialize`
//! directly; each deserializes via its Raw bridge, so unknown masquerade nested
//! fields are rejected at parse time. This completes the WP-30 input boundary
//! cleanup for all config-facing strict types.
//!
//! `RawInboundIR.masquerade` now uses `Option<RawMasqueradeIR>` so the
//! inbound/Hysteria2 masquerade subtree also rejects unknown fields.
//!
//! ### What is NOT yet done
//!
//! `planned.rs` / `normalize.rs` remain skeletons. This card is a WP-30
//! input boundary small closure, not a `planned.rs` push.
//!
//! ## Future work
//!
//! - Evaluate `planned.rs` prerequisites before pushing `RuntimePlan` builder
//! - `normalize.rs` IR normalization entry point (skeleton)
//! - The existing `outbound.rs` raw types (the outbound Raw/Validated boundary
//!   pilot completed earlier) remain in their current location

use serde::Deserialize;

use super::inbound::{MasqueradeFileIR, MasqueradeIR, MasqueradeProxyIR, MasqueradeStringIR};
use super::validated::{CertificateIR, ConfigIR, LogIR, NtpIR};
use super::{
    AnyTlsUserIR, BrutalIR, Credentials, DerpDialOptionsIR, DerpDomainResolverIR, DerpMeshPeerIR,
    DerpOutboundTlsOptionsIR, DerpStunOptionsIR, DerpVerifyClientUrlIR, DnsHostIR, DnsIR,
    DnsRuleIR, DnsServerIR, DomainResolveOptionsIR, EndpointIR, EndpointType, ExperimentalIR,
    HeaderEntry, Hysteria2UserIR, HysteriaUserIR, InboundIR, InboundTlsOptionsIR, InboundType,
    Listable, MultiplexOptionsIR, OutboundIR, OutboundType, RouteIR, RuleAction, RuleIR, RuleSetIR,
    ServiceIR, ServiceType, ShadowTlsHandshakeIR, ShadowTlsUserIR, ShadowsocksUserIR, StringOrObj,
    TrojanUserIR, TuicUserIR, TunOptionsIR, VlessUserIR, VmessUserIR, WireGuardPeerIR,
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

// ─────────────────── Route nested Raw types ───────────────────

/// Raw routing rule — strict input boundary for [`RuleIR`].
///
/// Field set is identical to `RuleIR`. All `deserialize_string_or_list` fields
/// are preserved. `RuleAction` is NOT Raw-ified; it stays as the validated enum.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawRuleIR {
    // Positive match conditions
    #[serde(default, deserialize_with = "crate::de::deserialize_string_or_list")]
    pub domain: Vec<String>,
    #[serde(default, deserialize_with = "crate::de::deserialize_string_or_list")]
    pub domain_suffix: Vec<String>,
    #[serde(default, deserialize_with = "crate::de::deserialize_string_or_list")]
    pub domain_keyword: Vec<String>,
    #[serde(default, deserialize_with = "crate::de::deserialize_string_or_list")]
    pub domain_regex: Vec<String>,
    #[serde(default, deserialize_with = "crate::de::deserialize_string_or_list")]
    pub geosite: Vec<String>,
    #[serde(default, deserialize_with = "crate::de::deserialize_string_or_list")]
    pub geoip: Vec<String>,
    #[serde(default, deserialize_with = "crate::de::deserialize_string_or_list")]
    pub ipcidr: Vec<String>,
    #[serde(default, deserialize_with = "crate::de::deserialize_string_or_list")]
    pub port: Vec<String>,
    #[serde(
        default,
        alias = "process",
        deserialize_with = "crate::de::deserialize_string_or_list"
    )]
    pub process_name: Vec<String>,
    #[serde(default, deserialize_with = "crate::de::deserialize_string_or_list")]
    pub process_path: Vec<String>,
    #[serde(default)]
    pub network: Vec<String>,
    #[serde(default)]
    pub protocol: Vec<String>,
    #[serde(default)]
    pub alpn: Vec<String>,
    #[serde(default)]
    pub source: Vec<String>,
    #[serde(default)]
    pub dest: Vec<String>,
    #[serde(default)]
    pub user_agent: Vec<String>,
    #[serde(default, deserialize_with = "crate::de::deserialize_string_or_list")]
    pub wifi_ssid: Vec<String>,
    #[serde(default, deserialize_with = "crate::de::deserialize_string_or_list")]
    pub wifi_bssid: Vec<String>,
    #[serde(default, deserialize_with = "crate::de::deserialize_string_or_list")]
    pub rule_set: Vec<String>,
    #[serde(default, deserialize_with = "crate::de::deserialize_string_or_list")]
    pub rule_set_ipcidr: Vec<String>,
    #[serde(default)]
    pub user_id: Vec<u32>,
    #[serde(
        default,
        alias = "uid",
        deserialize_with = "crate::de::deserialize_string_or_list"
    )]
    pub user: Vec<String>,
    #[serde(default)]
    pub group_id: Vec<u32>,
    #[serde(
        default,
        alias = "gid",
        deserialize_with = "crate::de::deserialize_string_or_list"
    )]
    pub group: Vec<String>,
    // P1 Parity fields
    #[serde(default, deserialize_with = "crate::de::deserialize_string_or_list")]
    pub clash_mode: Vec<String>,
    #[serde(default, deserialize_with = "crate::de::deserialize_string_or_list")]
    pub client: Vec<String>,
    #[serde(default, deserialize_with = "crate::de::deserialize_string_or_list")]
    pub package_name: Vec<String>,
    #[serde(default, deserialize_with = "crate::de::deserialize_string_or_list")]
    pub network_type: Vec<String>,
    #[serde(default)]
    pub network_is_expensive: Option<bool>,
    #[serde(default)]
    pub network_is_constrained: Option<bool>,
    #[serde(default)]
    pub ip_accept_any: Option<bool>,
    #[serde(default)]
    pub outbound_tag: Vec<String>,
    // AdGuard-style rules
    #[serde(default)]
    pub adguard: Vec<String>,
    #[serde(default)]
    pub not_adguard: Vec<String>,
    // Negative match conditions
    #[serde(default, deserialize_with = "crate::de::deserialize_string_or_list")]
    pub not_domain: Vec<String>,
    #[serde(default, deserialize_with = "crate::de::deserialize_string_or_list")]
    pub not_domain_suffix: Vec<String>,
    #[serde(default, deserialize_with = "crate::de::deserialize_string_or_list")]
    pub not_domain_keyword: Vec<String>,
    #[serde(default, deserialize_with = "crate::de::deserialize_string_or_list")]
    pub not_domain_regex: Vec<String>,
    #[serde(default, deserialize_with = "crate::de::deserialize_string_or_list")]
    pub not_geosite: Vec<String>,
    #[serde(default, deserialize_with = "crate::de::deserialize_string_or_list")]
    pub not_geoip: Vec<String>,
    #[serde(default, deserialize_with = "crate::de::deserialize_string_or_list")]
    pub not_ipcidr: Vec<String>,
    #[serde(default, deserialize_with = "crate::de::deserialize_string_or_list")]
    pub not_port: Vec<String>,
    #[serde(
        default,
        alias = "not_process",
        deserialize_with = "crate::de::deserialize_string_or_list"
    )]
    pub not_process_name: Vec<String>,
    #[serde(default, deserialize_with = "crate::de::deserialize_string_or_list")]
    pub not_process_path: Vec<String>,
    #[serde(default, deserialize_with = "crate::de::deserialize_string_or_list")]
    pub not_network: Vec<String>,
    #[serde(default, deserialize_with = "crate::de::deserialize_string_or_list")]
    pub not_protocol: Vec<String>,
    #[serde(default, deserialize_with = "crate::de::deserialize_string_or_list")]
    pub not_alpn: Vec<String>,
    #[serde(default)]
    pub not_source: Vec<String>,
    #[serde(default)]
    pub not_dest: Vec<String>,
    #[serde(default)]
    pub not_user_agent: Vec<String>,
    #[serde(default)]
    pub not_wifi_ssid: Vec<String>,
    #[serde(default)]
    pub not_wifi_bssid: Vec<String>,
    #[serde(default)]
    pub not_rule_set: Vec<String>,
    #[serde(default)]
    pub not_rule_set_ipcidr: Vec<String>,
    #[serde(default)]
    pub not_user_id: Vec<u32>,
    #[serde(default)]
    pub not_user: Vec<String>,
    #[serde(default)]
    pub not_group_id: Vec<u32>,
    #[serde(default)]
    pub not_group: Vec<String>,
    #[serde(default)]
    pub not_clash_mode: Vec<String>,
    #[serde(default)]
    pub not_client: Vec<String>,
    #[serde(default)]
    pub not_package_name: Vec<String>,
    #[serde(default)]
    pub not_network_type: Vec<String>,
    #[serde(default)]
    pub not_outbound_tag: Vec<String>,
    // Logical rule support
    #[serde(default, rename = "type")]
    pub rule_type: Option<String>,
    #[serde(default)]
    pub mode: Option<String>,
    #[serde(default)]
    pub rules: Vec<Box<RawRuleIR>>,
    // Actions — RuleAction stays as validated enum (not Raw-ified)
    #[serde(default)]
    pub action: RuleAction,
    #[serde(default)]
    pub outbound: Option<String>,
    #[serde(default)]
    pub override_address: Option<String>,
    #[serde(default)]
    pub override_port: Option<u16>,
    // DNS specific action fields
    #[serde(default)]
    pub query_type: Vec<String>,
    #[serde(default)]
    pub rewrite_ttl: Option<u32>,
    #[serde(default)]
    pub client_subnet: Option<String>,
    #[serde(default)]
    pub invert: bool,
    // Route Options Action Fields
    #[serde(default)]
    pub override_android_vpn: Option<bool>,
    #[serde(default)]
    pub find_process: Option<bool>,
    #[serde(default)]
    pub auto_detect_interface: Option<bool>,
    #[serde(default)]
    pub mark: Option<u32>,
    #[serde(default)]
    pub network_strategy: Option<String>,
    #[serde(default)]
    pub fallback_network_type: Option<Vec<String>>,
    #[serde(default)]
    pub fallback_delay: Option<String>,
    // Sniff Action Fields
    #[serde(default)]
    pub sniffer: Option<String>,
    #[serde(default)]
    pub sniff_timeout: Option<String>,
}

impl From<RawRuleIR> for RuleIR {
    fn from(raw: RawRuleIR) -> Self {
        Self {
            domain: raw.domain,
            domain_suffix: raw.domain_suffix,
            domain_keyword: raw.domain_keyword,
            domain_regex: raw.domain_regex,
            geosite: raw.geosite,
            geoip: raw.geoip,
            ipcidr: raw.ipcidr,
            port: raw.port,
            process_name: raw.process_name,
            process_path: raw.process_path,
            network: raw.network,
            protocol: raw.protocol,
            alpn: raw.alpn,
            source: raw.source,
            dest: raw.dest,
            user_agent: raw.user_agent,
            wifi_ssid: raw.wifi_ssid,
            wifi_bssid: raw.wifi_bssid,
            rule_set: raw.rule_set,
            rule_set_ipcidr: raw.rule_set_ipcidr,
            user_id: raw.user_id,
            user: raw.user,
            group_id: raw.group_id,
            group: raw.group,
            clash_mode: raw.clash_mode,
            client: raw.client,
            package_name: raw.package_name,
            network_type: raw.network_type,
            network_is_expensive: raw.network_is_expensive,
            network_is_constrained: raw.network_is_constrained,
            ip_accept_any: raw.ip_accept_any,
            outbound_tag: raw.outbound_tag,
            adguard: raw.adguard,
            not_adguard: raw.not_adguard,
            not_domain: raw.not_domain,
            not_domain_suffix: raw.not_domain_suffix,
            not_domain_keyword: raw.not_domain_keyword,
            not_domain_regex: raw.not_domain_regex,
            not_geosite: raw.not_geosite,
            not_geoip: raw.not_geoip,
            not_ipcidr: raw.not_ipcidr,
            not_port: raw.not_port,
            not_process_name: raw.not_process_name,
            not_process_path: raw.not_process_path,
            not_network: raw.not_network,
            not_protocol: raw.not_protocol,
            not_alpn: raw.not_alpn,
            not_source: raw.not_source,
            not_dest: raw.not_dest,
            not_user_agent: raw.not_user_agent,
            not_wifi_ssid: raw.not_wifi_ssid,
            not_wifi_bssid: raw.not_wifi_bssid,
            not_rule_set: raw.not_rule_set,
            not_rule_set_ipcidr: raw.not_rule_set_ipcidr,
            not_user_id: raw.not_user_id,
            not_user: raw.not_user,
            not_group_id: raw.not_group_id,
            not_group: raw.not_group,
            not_clash_mode: raw.not_clash_mode,
            not_client: raw.not_client,
            not_package_name: raw.not_package_name,
            not_network_type: raw.not_network_type,
            not_outbound_tag: raw.not_outbound_tag,
            rule_type: raw.rule_type,
            mode: raw.mode,
            rules: raw
                .rules
                .into_iter()
                .map(|b| Box::new(RuleIR::from(*b)))
                .collect(),
            action: raw.action,
            outbound: raw.outbound,
            override_address: raw.override_address,
            override_port: raw.override_port,
            query_type: raw.query_type,
            rewrite_ttl: raw.rewrite_ttl,
            client_subnet: raw.client_subnet,
            invert: raw.invert,
            override_android_vpn: raw.override_android_vpn,
            find_process: raw.find_process,
            auto_detect_interface: raw.auto_detect_interface,
            mark: raw.mark,
            network_strategy: raw.network_strategy,
            fallback_network_type: raw.fallback_network_type,
            fallback_delay: raw.fallback_delay,
            sniffer: raw.sniffer,
            sniff_timeout: raw.sniff_timeout,
        }
    }
}

/// Raw domain resolution options — strict input boundary for [`DomainResolveOptionsIR`].
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawDomainResolveOptionsIR {
    pub server: String,
    #[serde(default)]
    pub strategy: Option<String>,
    #[serde(default)]
    pub disable_cache: Option<bool>,
    #[serde(default)]
    pub rewrite_ttl: Option<u32>,
    #[serde(default)]
    pub client_subnet: Option<String>,
}

impl From<RawDomainResolveOptionsIR> for DomainResolveOptionsIR {
    fn from(raw: RawDomainResolveOptionsIR) -> Self {
        Self {
            server: raw.server,
            strategy: raw.strategy,
            disable_cache: raw.disable_cache,
            rewrite_ttl: raw.rewrite_ttl,
            client_subnet: raw.client_subnet,
        }
    }
}

/// Raw rule set configuration — strict input boundary for [`RuleSetIR`].
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawRuleSetIR {
    pub tag: String,
    #[serde(rename = "type")]
    pub ty: String,
    #[serde(default)]
    pub format: String,
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default)]
    pub download_detour: Option<String>,
    #[serde(default)]
    pub update_interval: Option<String>,
    #[serde(default)]
    pub rules: Option<Vec<RawRuleIR>>,
    #[serde(default)]
    pub version: Option<u8>,
}

impl From<RawRuleSetIR> for RuleSetIR {
    fn from(raw: RawRuleSetIR) -> Self {
        Self {
            tag: raw.tag,
            ty: raw.ty,
            format: raw.format,
            path: raw.path,
            url: raw.url,
            download_detour: raw.download_detour,
            update_interval: raw.update_interval,
            rules: raw.rules.map(|v| v.into_iter().map(Into::into).collect()),
            version: raw.version,
        }
    }
}

/// Raw route subtree — strict nested input boundary for [`RouteIR`].
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawRouteIR {
    #[serde(default)]
    pub rules: Vec<RawRuleIR>,
    #[serde(default)]
    pub rule_set: Vec<RawRuleSetIR>,
    #[serde(default)]
    pub default: Option<String>,
    #[serde(default, alias = "final")]
    pub final_outbound: Option<String>,
    // GeoIP/Geosite
    #[serde(default)]
    pub geoip_path: Option<String>,
    #[serde(default)]
    pub geoip_download_url: Option<String>,
    #[serde(default)]
    pub geoip_download_detour: Option<String>,
    #[serde(default)]
    pub geosite_path: Option<String>,
    #[serde(default)]
    pub geosite_download_url: Option<String>,
    #[serde(default)]
    pub geosite_download_detour: Option<String>,
    #[serde(default)]
    pub default_rule_set_download_detour: Option<String>,
    // Process and Interface Options
    #[serde(default)]
    pub override_android_vpn: Option<bool>,
    #[serde(default)]
    pub find_process: Option<bool>,
    #[serde(default)]
    pub auto_detect_interface: Option<bool>,
    #[serde(default)]
    pub default_interface: Option<String>,
    // Routing Mark
    #[serde(default)]
    pub mark: Option<u32>,
    // DNS and Network Strategy
    #[serde(default)]
    pub default_domain_resolver: Option<RawDomainResolveOptionsIR>,
    #[serde(default)]
    pub network_strategy: Option<String>,
    #[serde(default)]
    pub default_network_type: Option<Vec<String>>,
    #[serde(default)]
    pub default_fallback_network_type: Option<Vec<String>>,
    #[serde(default)]
    pub default_fallback_delay: Option<String>,
}

impl From<RawRouteIR> for RouteIR {
    fn from(raw: RawRouteIR) -> Self {
        Self {
            rules: raw.rules.into_iter().map(Into::into).collect(),
            rule_set: raw.rule_set.into_iter().map(Into::into).collect(),
            default: raw.default,
            final_outbound: raw.final_outbound,
            geoip_path: raw.geoip_path,
            geoip_download_url: raw.geoip_download_url,
            geoip_download_detour: raw.geoip_download_detour,
            geosite_path: raw.geosite_path,
            geosite_download_url: raw.geosite_download_url,
            geosite_download_detour: raw.geosite_download_detour,
            default_rule_set_download_detour: raw.default_rule_set_download_detour,
            override_android_vpn: raw.override_android_vpn,
            find_process: raw.find_process,
            auto_detect_interface: raw.auto_detect_interface,
            default_interface: raw.default_interface,
            mark: raw.mark,
            default_domain_resolver: raw.default_domain_resolver.map(Into::into),
            network_strategy: raw.network_strategy,
            default_network_type: raw.default_network_type,
            default_fallback_network_type: raw.default_fallback_network_type,
            default_fallback_delay: raw.default_fallback_delay,
        }
    }
}

// ─────────────────── Endpoint nested Raw types ───────────────────

/// Raw WireGuard peer configuration — strict input boundary for [`WireGuardPeerIR`].
///
/// Field set is identical to `WireGuardPeerIR`. Deserialization enters here
/// (with `deny_unknown_fields`), then converts via `From<RawWireGuardPeerIR> for WireGuardPeerIR`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawWireGuardPeerIR {
    /// Peer endpoint address
    #[serde(default)]
    pub address: Option<String>,
    /// Peer endpoint port
    #[serde(default)]
    pub port: Option<u16>,
    /// Peer public key (base64)
    #[serde(default)]
    pub public_key: Option<String>,
    /// Pre-shared key (base64)
    #[serde(default)]
    pub pre_shared_key: Option<String>,
    /// Allowed IPs (CIDR format)
    #[serde(default)]
    pub allowed_ips: Option<Vec<String>>,
    /// Persistent keepalive interval (seconds)
    #[serde(default)]
    pub persistent_keepalive_interval: Option<u16>,
    /// Reserved bytes for connection ID
    #[serde(default)]
    pub reserved: Option<Vec<u8>>,
}

impl From<RawWireGuardPeerIR> for WireGuardPeerIR {
    fn from(raw: RawWireGuardPeerIR) -> Self {
        Self {
            address: raw.address,
            port: raw.port,
            public_key: raw.public_key,
            pre_shared_key: raw.pre_shared_key,
            allowed_ips: raw.allowed_ips,
            persistent_keepalive_interval: raw.persistent_keepalive_interval,
            reserved: raw.reserved,
        }
    }
}

/// Raw endpoint configuration — strict input boundary for [`EndpointIR`].
///
/// Field set is identical to `EndpointIR`. `EndpointType` is intentionally NOT
/// Raw-ified — it stays as the validated enum with lowercase serde. WireGuard
/// peers use [`RawWireGuardPeerIR`] for nested strict boundaries.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawEndpointIR {
    /// Endpoint type.
    #[serde(rename = "type")]
    pub ty: EndpointType,
    /// Unique tag identifier.
    #[serde(default)]
    pub tag: Option<String>,
    /// Network protocols supported (e.g., ["tcp", "udp"]).
    #[serde(default)]
    pub network: Option<Vec<String>>,

    // WireGuard-specific fields
    /// WireGuard: Use system WireGuard interface
    #[serde(default)]
    pub wireguard_system: Option<bool>,
    /// WireGuard: Interface name
    #[serde(default)]
    pub wireguard_name: Option<String>,
    /// WireGuard: MTU size
    #[serde(default)]
    pub wireguard_mtu: Option<u32>,
    /// WireGuard: Local addresses (CIDR format)
    #[serde(default)]
    pub wireguard_address: Option<Vec<String>>,
    /// WireGuard: Private key (base64)
    #[serde(default)]
    pub wireguard_private_key: Option<String>,
    /// WireGuard: Listen port
    #[serde(default)]
    pub wireguard_listen_port: Option<u16>,
    /// WireGuard: Peer configurations (strict: rejects unknown fields)
    #[serde(default)]
    pub wireguard_peers: Option<Vec<RawWireGuardPeerIR>>,
    /// WireGuard: UDP timeout (e.g., "30s")
    #[serde(default)]
    pub wireguard_udp_timeout: Option<String>,
    /// WireGuard: Number of worker threads
    #[serde(default)]
    pub wireguard_workers: Option<i32>,

    // Tailscale-specific fields
    /// Tailscale: State directory path
    #[serde(default)]
    pub tailscale_state_directory: Option<String>,
    /// Tailscale: Authentication key
    #[serde(default)]
    pub tailscale_auth_key: Option<String>,
    /// Tailscale: Control server URL
    #[serde(default)]
    pub tailscale_control_url: Option<String>,
    /// Tailscale: Ephemeral mode
    #[serde(default)]
    pub tailscale_ephemeral: Option<bool>,
    /// Tailscale: Hostname
    #[serde(default)]
    pub tailscale_hostname: Option<String>,
    /// Tailscale: Accept routes from network
    #[serde(default)]
    pub tailscale_accept_routes: Option<bool>,
    /// Tailscale: Exit node address
    #[serde(default)]
    pub tailscale_exit_node: Option<String>,
    /// Tailscale: Allow LAN access when using exit node
    #[serde(default)]
    pub tailscale_exit_node_allow_lan_access: Option<bool>,
    /// Tailscale: Routes to advertise (CIDR format)
    #[serde(default)]
    pub tailscale_advertise_routes: Option<Vec<String>>,
    /// Tailscale: Advertise as exit node
    #[serde(default)]
    pub tailscale_advertise_exit_node: Option<bool>,
    /// Tailscale: UDP timeout (e.g., "30s")
    #[serde(default)]
    pub tailscale_udp_timeout: Option<String>,
}

impl From<RawEndpointIR> for EndpointIR {
    fn from(raw: RawEndpointIR) -> Self {
        Self {
            ty: raw.ty,
            tag: raw.tag,
            network: raw.network,
            wireguard_system: raw.wireguard_system,
            wireguard_name: raw.wireguard_name,
            wireguard_mtu: raw.wireguard_mtu,
            wireguard_address: raw.wireguard_address,
            wireguard_private_key: raw.wireguard_private_key,
            wireguard_listen_port: raw.wireguard_listen_port,
            wireguard_peers: raw
                .wireguard_peers
                .map(|v| v.into_iter().map(Into::into).collect()),
            wireguard_udp_timeout: raw.wireguard_udp_timeout,
            wireguard_workers: raw.wireguard_workers,
            tailscale_state_directory: raw.tailscale_state_directory,
            tailscale_auth_key: raw.tailscale_auth_key,
            tailscale_control_url: raw.tailscale_control_url,
            tailscale_ephemeral: raw.tailscale_ephemeral,
            tailscale_hostname: raw.tailscale_hostname,
            tailscale_accept_routes: raw.tailscale_accept_routes,
            tailscale_exit_node: raw.tailscale_exit_node,
            tailscale_exit_node_allow_lan_access: raw.tailscale_exit_node_allow_lan_access,
            tailscale_advertise_routes: raw.tailscale_advertise_routes,
            tailscale_advertise_exit_node: raw.tailscale_advertise_exit_node,
            tailscale_udp_timeout: raw.tailscale_udp_timeout,
        }
    }
}

// ─────────────────── Service nested Raw types (WP-30g) ───────────────────

/// Raw inbound TLS options (Go parity: `option.InboundTLSOptions`).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawInboundTlsOptionsIR {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub server_name: Option<String>,
    #[serde(default)]
    pub insecure: Option<bool>,
    #[serde(default)]
    pub alpn: Option<Vec<String>>,
    #[serde(default)]
    pub min_version: Option<String>,
    #[serde(default)]
    pub max_version: Option<String>,
    #[serde(default)]
    pub cipher_suites: Option<Vec<String>>,
    #[serde(default)]
    pub certificate: Option<Vec<String>>,
    #[serde(default)]
    pub certificate_path: Option<String>,
    #[serde(default)]
    pub key: Option<Vec<String>>,
    #[serde(default)]
    pub key_path: Option<String>,
}

impl From<RawInboundTlsOptionsIR> for InboundTlsOptionsIR {
    fn from(raw: RawInboundTlsOptionsIR) -> Self {
        Self {
            enabled: raw.enabled,
            server_name: raw.server_name,
            insecure: raw.insecure,
            alpn: raw.alpn,
            min_version: raw.min_version,
            max_version: raw.max_version,
            cipher_suites: raw.cipher_suites,
            certificate: raw.certificate,
            certificate_path: raw.certificate_path,
            key: raw.key,
            key_path: raw.key_path,
        }
    }
}

/// Raw DERP STUN options object form (strict: rejects unknown fields).
#[derive(Debug, Clone, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct RawDerpStunOptionsObj {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub listen: Option<String>,
    #[serde(default)]
    pub listen_port: Option<u16>,
    #[serde(default)]
    pub bind_interface: Option<String>,
    #[serde(default)]
    pub routing_mark: Option<u32>,
    #[serde(default)]
    pub reuse_addr: Option<bool>,
    #[serde(default)]
    pub netns: Option<String>,
}

/// Raw DERP STUN options (bool / port / object untagged).
#[derive(Debug, Clone)]
pub struct RawDerpStunOptionsIR {
    pub enabled: bool,
    pub listen: Option<String>,
    pub listen_port: Option<u16>,
    pub bind_interface: Option<String>,
    pub routing_mark: Option<u32>,
    pub reuse_addr: Option<bool>,
    pub netns: Option<String>,
}

impl<'de> Deserialize<'de> for RawDerpStunOptionsIR {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Repr {
            Bool(bool),
            Port(u16),
            Obj(RawDerpStunOptionsObj),
        }

        match Repr::deserialize(deserializer)? {
            Repr::Bool(enabled) => Ok(Self {
                enabled,
                listen: None,
                listen_port: None,
                bind_interface: None,
                routing_mark: None,
                reuse_addr: None,
                netns: None,
            }),
            Repr::Port(port) => Ok(Self {
                enabled: true,
                listen: None,
                listen_port: Some(port),
                bind_interface: None,
                routing_mark: None,
                reuse_addr: None,
                netns: None,
            }),
            Repr::Obj(v) => Ok(Self {
                enabled: v.enabled,
                listen: v.listen,
                listen_port: v.listen_port,
                bind_interface: v.bind_interface,
                routing_mark: v.routing_mark,
                reuse_addr: v.reuse_addr,
                netns: v.netns,
            }),
        }
    }
}

impl From<RawDerpStunOptionsIR> for DerpStunOptionsIR {
    fn from(raw: RawDerpStunOptionsIR) -> Self {
        Self {
            enabled: raw.enabled,
            listen: raw.listen,
            listen_port: raw.listen_port,
            bind_interface: raw.bind_interface,
            routing_mark: raw.routing_mark,
            reuse_addr: raw.reuse_addr,
            netns: raw.netns,
        }
    }
}

/// Raw DERP domain resolver options (strict: no `extra` BTreeMap).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawDerpDomainResolverIR {
    #[serde(default)]
    pub server: Option<String>,
    #[serde(default)]
    pub strategy: Option<String>,
}

impl From<String> for RawDerpDomainResolverIR {
    fn from(s: String) -> Self {
        Self {
            server: Some(s),
            strategy: None,
        }
    }
}

impl From<RawDerpDomainResolverIR> for DerpDomainResolverIR {
    fn from(raw: RawDerpDomainResolverIR) -> Self {
        Self {
            server: raw.server,
            strategy: raw.strategy,
            extra: Default::default(),
        }
    }
}

/// Raw DERP dial options (strict: no `extra` BTreeMap, no `flatten`).
#[derive(Debug, Clone, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct RawDerpDialOptionsIR {
    #[serde(default)]
    pub detour: Option<String>,
    #[serde(default)]
    pub bind_interface: Option<String>,
    #[serde(default)]
    pub inet4_bind_address: Option<String>,
    #[serde(default)]
    pub inet6_bind_address: Option<String>,
    #[serde(default)]
    pub routing_mark: Option<u32>,
    #[serde(default)]
    pub reuse_addr: Option<bool>,
    #[serde(default)]
    pub netns: Option<String>,
    #[serde(default)]
    pub connect_timeout: Option<String>,
    #[serde(default)]
    pub tcp_fast_open: Option<bool>,
    #[serde(default)]
    pub tcp_multi_path: Option<bool>,
    #[serde(default)]
    pub udp_fragment: Option<bool>,
    #[serde(default)]
    pub domain_resolver: Option<StringOrObj<RawDerpDomainResolverIR>>,
}

impl From<RawDerpDialOptionsIR> for DerpDialOptionsIR {
    fn from(raw: RawDerpDialOptionsIR) -> Self {
        Self {
            detour: raw.detour,
            bind_interface: raw.bind_interface,
            inet4_bind_address: raw.inet4_bind_address,
            inet6_bind_address: raw.inet6_bind_address,
            routing_mark: raw.routing_mark,
            reuse_addr: raw.reuse_addr,
            netns: raw.netns,
            connect_timeout: raw.connect_timeout,
            tcp_fast_open: raw.tcp_fast_open,
            tcp_multi_path: raw.tcp_multi_path,
            udp_fragment: raw.udp_fragment,
            domain_resolver: raw
                .domain_resolver
                .map(|soo| StringOrObj(soo.into_inner().into())),
            extra: Default::default(),
        }
    }
}

/// Raw DERP verify_client_url options (strict: dial fields inlined, no `flatten`).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawDerpVerifyClientUrlIR {
    #[serde(default)]
    pub url: String,
    // Inlined dial fields (no flatten for deny_unknown_fields compat)
    #[serde(default)]
    pub detour: Option<String>,
    #[serde(default)]
    pub bind_interface: Option<String>,
    #[serde(default)]
    pub inet4_bind_address: Option<String>,
    #[serde(default)]
    pub inet6_bind_address: Option<String>,
    #[serde(default)]
    pub routing_mark: Option<u32>,
    #[serde(default)]
    pub reuse_addr: Option<bool>,
    #[serde(default)]
    pub netns: Option<String>,
    #[serde(default)]
    pub connect_timeout: Option<String>,
    #[serde(default)]
    pub tcp_fast_open: Option<bool>,
    #[serde(default)]
    pub tcp_multi_path: Option<bool>,
    #[serde(default)]
    pub udp_fragment: Option<bool>,
    #[serde(default)]
    pub domain_resolver: Option<StringOrObj<RawDerpDomainResolverIR>>,
}

impl From<String> for RawDerpVerifyClientUrlIR {
    fn from(s: String) -> Self {
        Self {
            url: s,
            detour: None,
            bind_interface: None,
            inet4_bind_address: None,
            inet6_bind_address: None,
            routing_mark: None,
            reuse_addr: None,
            netns: None,
            connect_timeout: None,
            tcp_fast_open: None,
            tcp_multi_path: None,
            udp_fragment: None,
            domain_resolver: None,
        }
    }
}

impl From<RawDerpVerifyClientUrlIR> for DerpVerifyClientUrlIR {
    fn from(raw: RawDerpVerifyClientUrlIR) -> Self {
        Self {
            url: raw.url,
            dial: DerpDialOptionsIR {
                detour: raw.detour,
                bind_interface: raw.bind_interface,
                inet4_bind_address: raw.inet4_bind_address,
                inet6_bind_address: raw.inet6_bind_address,
                routing_mark: raw.routing_mark,
                reuse_addr: raw.reuse_addr,
                netns: raw.netns,
                connect_timeout: raw.connect_timeout,
                tcp_fast_open: raw.tcp_fast_open,
                tcp_multi_path: raw.tcp_multi_path,
                udp_fragment: raw.udp_fragment,
                domain_resolver: raw
                    .domain_resolver
                    .map(|soo| StringOrObj(soo.into_inner().into())),
                extra: Default::default(),
            },
        }
    }
}

/// Raw DERP outbound TLS options (strict: rejects unknown fields).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawDerpOutboundTlsOptionsIR {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub server_name: Option<String>,
    #[serde(default)]
    pub insecure: Option<bool>,
    #[serde(default)]
    pub alpn: Option<Vec<String>>,
    #[serde(default)]
    pub ca_paths: Vec<String>,
    #[serde(default)]
    pub ca_pem: Vec<String>,
}

impl From<RawDerpOutboundTlsOptionsIR> for DerpOutboundTlsOptionsIR {
    fn from(raw: RawDerpOutboundTlsOptionsIR) -> Self {
        Self {
            enabled: raw.enabled,
            server_name: raw.server_name,
            insecure: raw.insecure,
            alpn: raw.alpn,
            ca_paths: raw.ca_paths,
            ca_pem: raw.ca_pem,
        }
    }
}

/// Raw DERP mesh peer options (strict: dial fields inlined, no `flatten`).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawDerpMeshPeerIR {
    #[serde(default)]
    pub server: String,
    #[serde(default)]
    pub server_port: Option<u16>,
    #[serde(default)]
    pub host: Option<String>,
    #[serde(default)]
    pub tls: Option<RawDerpOutboundTlsOptionsIR>,
    // Inlined dial fields (no flatten for deny_unknown_fields compat)
    #[serde(default)]
    pub detour: Option<String>,
    #[serde(default)]
    pub bind_interface: Option<String>,
    #[serde(default)]
    pub inet4_bind_address: Option<String>,
    #[serde(default)]
    pub inet6_bind_address: Option<String>,
    #[serde(default)]
    pub routing_mark: Option<u32>,
    #[serde(default)]
    pub reuse_addr: Option<bool>,
    #[serde(default)]
    pub netns: Option<String>,
    #[serde(default)]
    pub connect_timeout: Option<String>,
    #[serde(default)]
    pub tcp_fast_open: Option<bool>,
    #[serde(default)]
    pub tcp_multi_path: Option<bool>,
    #[serde(default)]
    pub udp_fragment: Option<bool>,
    #[serde(default)]
    pub domain_resolver: Option<StringOrObj<RawDerpDomainResolverIR>>,
}

impl From<String> for RawDerpMeshPeerIR {
    fn from(s: String) -> Self {
        // Parse `host:port` shorthand — mirrors DerpMeshPeerIR::From<String>.
        let mut out = Self {
            server: s.clone(),
            server_port: None,
            host: None,
            tls: None,
            detour: None,
            bind_interface: None,
            inet4_bind_address: None,
            inet6_bind_address: None,
            routing_mark: None,
            reuse_addr: None,
            netns: None,
            connect_timeout: None,
            tcp_fast_open: None,
            tcp_multi_path: None,
            udp_fragment: None,
            domain_resolver: None,
        };
        let raw = s.trim();
        if raw.is_empty() {
            return out;
        }
        // Support `[v6]:port` and `host:port`.
        if let Some(rest) = raw.strip_prefix('[') {
            if let Some(end) = rest.find(']') {
                let host = &rest[..end];
                let tail = &rest[end + 1..];
                if let Some(port_str) = tail.strip_prefix(':') {
                    if let Ok(port) = port_str.parse::<u16>() {
                        out.server = host.to_string();
                        out.server_port = Some(port);
                    }
                }
                return out;
            }
        }
        if let Some((host, port_str)) = raw.rsplit_once(':') {
            if let Ok(port) = port_str.parse::<u16>() {
                if !host.is_empty() {
                    out.server = host.to_string();
                    out.server_port = Some(port);
                }
            }
        }
        out
    }
}

impl From<RawDerpMeshPeerIR> for DerpMeshPeerIR {
    fn from(raw: RawDerpMeshPeerIR) -> Self {
        Self {
            server: raw.server,
            server_port: raw.server_port,
            host: raw.host,
            tls: raw.tls.map(Into::into),
            dial: DerpDialOptionsIR {
                detour: raw.detour,
                bind_interface: raw.bind_interface,
                inet4_bind_address: raw.inet4_bind_address,
                inet6_bind_address: raw.inet6_bind_address,
                routing_mark: raw.routing_mark,
                reuse_addr: raw.reuse_addr,
                netns: raw.netns,
                connect_timeout: raw.connect_timeout,
                tcp_fast_open: raw.tcp_fast_open,
                tcp_multi_path: raw.tcp_multi_path,
                udp_fragment: raw.udp_fragment,
                domain_resolver: raw
                    .domain_resolver
                    .map(|soo| StringOrObj(soo.into_inner().into())),
                extra: Default::default(),
            },
        }
    }
}

/// Raw service configuration IR (strict: rejects unknown fields).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawServiceIR {
    #[serde(rename = "type")]
    pub ty: ServiceType,
    #[serde(default)]
    pub tag: Option<String>,
    #[serde(default)]
    pub listen: Option<String>,
    #[serde(default)]
    pub listen_port: Option<u16>,
    #[serde(default)]
    pub bind_interface: Option<String>,
    #[serde(default)]
    pub routing_mark: Option<u32>,
    #[serde(default)]
    pub reuse_addr: Option<bool>,
    #[serde(default)]
    pub netns: Option<String>,
    #[serde(default)]
    pub tcp_fast_open: Option<bool>,
    #[serde(default)]
    pub tcp_multi_path: Option<bool>,
    #[serde(default)]
    pub udp_fragment: Option<bool>,
    #[serde(default)]
    pub udp_timeout: Option<String>,
    #[serde(default)]
    pub detour: Option<String>,
    #[serde(default)]
    pub sniff: Option<bool>,
    #[serde(default)]
    pub sniff_override_destination: Option<bool>,
    #[serde(default)]
    pub sniff_timeout: Option<String>,
    #[serde(default)]
    pub domain_strategy: Option<String>,
    #[serde(default)]
    pub udp_disable_domain_unmapping: Option<bool>,
    #[serde(default)]
    pub tls: Option<RawInboundTlsOptionsIR>,
    #[serde(default)]
    pub servers: Option<std::collections::HashMap<String, String>>,
    #[serde(default)]
    pub cache_path: Option<String>,
    #[serde(default)]
    pub auth_token: Option<String>,
    #[serde(default)]
    pub config_path: Option<String>,
    #[serde(default)]
    pub verify_client_endpoint: Option<Listable<String>>,
    #[serde(default)]
    pub verify_client_url: Option<Listable<StringOrObj<RawDerpVerifyClientUrlIR>>>,
    #[serde(default)]
    pub home: Option<String>,
    #[serde(default)]
    pub mesh_with: Option<Listable<StringOrObj<RawDerpMeshPeerIR>>>,
    #[serde(default)]
    pub mesh_psk: Option<String>,
    #[serde(default)]
    pub mesh_psk_file: Option<String>,
    #[serde(default)]
    pub stun: Option<RawDerpStunOptionsIR>,
}

impl From<RawServiceIR> for ServiceIR {
    fn from(raw: RawServiceIR) -> Self {
        Self {
            ty: raw.ty,
            tag: raw.tag,
            listen: raw.listen,
            listen_port: raw.listen_port,
            bind_interface: raw.bind_interface,
            routing_mark: raw.routing_mark,
            reuse_addr: raw.reuse_addr,
            netns: raw.netns,
            tcp_fast_open: raw.tcp_fast_open,
            tcp_multi_path: raw.tcp_multi_path,
            udp_fragment: raw.udp_fragment,
            udp_timeout: raw.udp_timeout,
            detour: raw.detour,
            sniff: raw.sniff,
            sniff_override_destination: raw.sniff_override_destination,
            sniff_timeout: raw.sniff_timeout,
            domain_strategy: raw.domain_strategy,
            udp_disable_domain_unmapping: raw.udp_disable_domain_unmapping,
            tls: raw.tls.map(Into::into),
            servers: raw.servers,
            cache_path: raw.cache_path,
            auth_token: raw.auth_token,
            config_path: raw.config_path,
            verify_client_endpoint: raw.verify_client_endpoint,
            home: raw.home,
            verify_client_url: raw.verify_client_url.map(|l| Listable {
                items: l
                    .items
                    .into_iter()
                    .map(|soo| StringOrObj(soo.into_inner().into()))
                    .collect(),
            }),
            mesh_with: raw.mesh_with.map(|l| Listable {
                items: l
                    .items
                    .into_iter()
                    .map(|soo| StringOrObj(soo.into_inner().into()))
                    .collect(),
            }),
            mesh_psk: raw.mesh_psk,
            mesh_psk_file: raw.mesh_psk_file,
            stun: raw.stun.map(Into::into),
        }
    }
}

// ─────────────────── Masquerade shared helper Raw types (WP-30j) ───────────────────

/// Raw Hysteria2 Masquerade configuration — strict input boundary for [`MasqueradeIR`].
///
/// All fields mirror `MasqueradeIR`. Deserialization enters here
/// (with `deny_unknown_fields`), then converts via `From<RawMasqueradeIR> for MasqueradeIR`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawMasqueradeIR {
    #[serde(rename = "type")]
    pub type_: String,
    #[serde(default)]
    pub file: Option<RawMasqueradeFileIR>,
    #[serde(default)]
    pub proxy: Option<RawMasqueradeProxyIR>,
    #[serde(default)]
    pub string: Option<RawMasqueradeStringIR>,
}

impl From<RawMasqueradeIR> for MasqueradeIR {
    fn from(raw: RawMasqueradeIR) -> Self {
        Self {
            type_: raw.type_,
            file: raw.file.map(Into::into),
            proxy: raw.proxy.map(Into::into),
            string: raw.string.map(Into::into),
        }
    }
}

/// Raw Masquerade file configuration — strict input boundary for [`MasqueradeFileIR`].
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawMasqueradeFileIR {
    pub directory: String,
}

impl From<RawMasqueradeFileIR> for MasqueradeFileIR {
    fn from(raw: RawMasqueradeFileIR) -> Self {
        Self {
            directory: raw.directory,
        }
    }
}

/// Raw Masquerade proxy configuration — strict input boundary for [`MasqueradeProxyIR`].
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawMasqueradeProxyIR {
    pub url: String,
    #[serde(default)]
    pub rewrite_host: bool,
}

impl From<RawMasqueradeProxyIR> for MasqueradeProxyIR {
    fn from(raw: RawMasqueradeProxyIR) -> Self {
        Self {
            url: raw.url,
            rewrite_host: raw.rewrite_host,
        }
    }
}

/// Raw Masquerade string configuration — strict input boundary for [`MasqueradeStringIR`].
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawMasqueradeStringIR {
    pub content: String,
    #[serde(default)]
    pub headers: Option<std::collections::HashMap<String, String>>,
    #[serde(default)]
    pub status_code: u16,
}

impl From<RawMasqueradeStringIR> for MasqueradeStringIR {
    fn from(raw: RawMasqueradeStringIR) -> Self {
        Self {
            content: raw.content,
            headers: raw.headers,
            status_code: raw.status_code,
        }
    }
}

// ─────────────────── Inbound nested Raw types (WP-30h) ───────────────────

fn default_true() -> bool {
    true
}

/// Raw Shadowsocks user — strict input boundary for [`ShadowsocksUserIR`].
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawShadowsocksUserIR {
    pub name: String,
    pub password: String,
}

impl From<RawShadowsocksUserIR> for ShadowsocksUserIR {
    fn from(raw: RawShadowsocksUserIR) -> Self {
        Self {
            name: raw.name,
            password: raw.password,
        }
    }
}

/// Raw VMess user — strict input boundary for [`VmessUserIR`].
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawVmessUserIR {
    pub name: String,
    pub uuid: String,
    #[serde(default)]
    pub alter_id: u32,
}

impl From<RawVmessUserIR> for VmessUserIR {
    fn from(raw: RawVmessUserIR) -> Self {
        Self {
            name: raw.name,
            uuid: raw.uuid,
            alter_id: raw.alter_id,
        }
    }
}

/// Raw VLESS user — strict input boundary for [`VlessUserIR`].
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawVlessUserIR {
    pub name: String,
    pub uuid: String,
    #[serde(default)]
    pub flow: Option<String>,
    #[serde(default)]
    pub security: Option<String>,
    #[serde(default)]
    pub alter_id: Option<u8>,
    #[serde(default)]
    pub encryption: Option<String>,
}

impl From<RawVlessUserIR> for VlessUserIR {
    fn from(raw: RawVlessUserIR) -> Self {
        Self {
            name: raw.name,
            uuid: raw.uuid,
            flow: raw.flow,
            security: raw.security,
            alter_id: raw.alter_id,
            encryption: raw.encryption,
        }
    }
}

/// Raw Trojan user — strict input boundary for [`TrojanUserIR`].
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawTrojanUserIR {
    pub name: String,
    pub password: String,
}

impl From<RawTrojanUserIR> for TrojanUserIR {
    fn from(raw: RawTrojanUserIR) -> Self {
        Self {
            name: raw.name,
            password: raw.password,
        }
    }
}

/// Raw ShadowTLS user — strict input boundary for [`ShadowTlsUserIR`].
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawShadowTlsUserIR {
    #[serde(default)]
    pub name: String,
    pub password: String,
}

impl From<RawShadowTlsUserIR> for ShadowTlsUserIR {
    fn from(raw: RawShadowTlsUserIR) -> Self {
        Self {
            name: raw.name,
            password: raw.password,
        }
    }
}

/// Raw ShadowTLS handshake — strict input boundary for [`ShadowTlsHandshakeIR`].
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawShadowTlsHandshakeIR {
    pub server: String,
    #[serde(rename = "server_port")]
    pub server_port: u16,
}

impl From<RawShadowTlsHandshakeIR> for ShadowTlsHandshakeIR {
    fn from(raw: RawShadowTlsHandshakeIR) -> Self {
        Self {
            server: raw.server,
            server_port: raw.server_port,
        }
    }
}

/// Raw AnyTLS user — strict input boundary for [`AnyTlsUserIR`].
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawAnyTlsUserIR {
    #[serde(default)]
    pub name: Option<String>,
    pub password: String,
}

impl From<RawAnyTlsUserIR> for AnyTlsUserIR {
    fn from(raw: RawAnyTlsUserIR) -> Self {
        Self {
            name: raw.name,
            password: raw.password,
        }
    }
}

/// Raw Hysteria2 user — strict input boundary for [`Hysteria2UserIR`].
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawHysteria2UserIR {
    pub name: String,
    pub password: String,
}

impl From<RawHysteria2UserIR> for Hysteria2UserIR {
    fn from(raw: RawHysteria2UserIR) -> Self {
        Self {
            name: raw.name,
            password: raw.password,
        }
    }
}

/// Raw TUIC user — strict input boundary for [`TuicUserIR`].
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawTuicUserIR {
    pub uuid: String,
    pub token: String,
}

impl From<RawTuicUserIR> for TuicUserIR {
    fn from(raw: RawTuicUserIR) -> Self {
        Self {
            uuid: raw.uuid,
            token: raw.token,
        }
    }
}

/// Raw Hysteria v1 user — strict input boundary for [`HysteriaUserIR`].
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawHysteriaUserIR {
    pub name: String,
    pub auth: String,
}

impl From<RawHysteriaUserIR> for HysteriaUserIR {
    fn from(raw: RawHysteriaUserIR) -> Self {
        Self {
            name: raw.name,
            auth: raw.auth,
        }
    }
}

/// Raw TUN options — strict input boundary for [`TunOptionsIR`].
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawTunOptionsIR {
    #[serde(default)]
    pub platform: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub mtu: Option<u32>,
    #[serde(default)]
    pub dry_run: Option<bool>,
    #[serde(default)]
    pub user_tag: Option<String>,
    #[serde(default)]
    pub timeout_ms: Option<u64>,
    #[serde(default)]
    pub auto_route: Option<bool>,
    #[serde(default)]
    pub auto_redirect: Option<bool>,
    #[serde(default)]
    pub strict_route: Option<bool>,
    #[serde(default)]
    pub inet4_address: Option<String>,
    #[serde(default)]
    pub inet6_address: Option<String>,
    #[serde(default)]
    pub table_id: Option<u32>,
    #[serde(default)]
    pub fwmark: Option<u32>,
    #[serde(default)]
    pub exclude_routes: Option<Vec<String>>,
    #[serde(default)]
    pub include_routes: Option<Vec<String>>,
    #[serde(default)]
    pub exclude_uids: Option<Vec<u32>>,
    #[serde(default)]
    pub stack: Option<String>,
    #[serde(default)]
    pub endpoint_independent_nat: Option<bool>,
    #[serde(default)]
    pub udp_timeout: Option<String>,
    #[serde(default)]
    pub exclude_processes: Option<Vec<String>>,
}

impl From<RawTunOptionsIR> for TunOptionsIR {
    fn from(raw: RawTunOptionsIR) -> Self {
        Self {
            platform: raw.platform,
            name: raw.name,
            mtu: raw.mtu,
            dry_run: raw.dry_run,
            user_tag: raw.user_tag,
            timeout_ms: raw.timeout_ms,
            auto_route: raw.auto_route,
            auto_redirect: raw.auto_redirect,
            strict_route: raw.strict_route,
            inet4_address: raw.inet4_address,
            inet6_address: raw.inet6_address,
            table_id: raw.table_id,
            fwmark: raw.fwmark,
            exclude_routes: raw.exclude_routes,
            include_routes: raw.include_routes,
            exclude_uids: raw.exclude_uids,
            stack: raw.stack,
            endpoint_independent_nat: raw.endpoint_independent_nat,
            udp_timeout: raw.udp_timeout,
            exclude_processes: raw.exclude_processes,
        }
    }
}

/// Raw inbound configuration — strict input boundary for [`InboundIR`].
///
/// Field set is identical to `InboundIR`. `InboundType` is intentionally NOT
/// Raw-ified — it stays as the validated enum with lowercase serde. User lists
/// and nested types use their corresponding Raw types for strict boundaries.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawInboundIR {
    #[serde(default)]
    pub tag: Option<String>,
    pub ty: InboundType,
    pub listen: String,
    pub port: u16,
    #[serde(default)]
    pub sniff: bool,
    #[serde(default)]
    pub sniff_override_destination: bool,
    #[serde(default)]
    pub udp: bool,
    #[serde(default)]
    pub udp_timeout: Option<String>,
    #[serde(default)]
    pub detour: Option<String>,
    #[serde(default)]
    pub domain_strategy: Option<String>,
    #[serde(default)]
    pub basic_auth: Option<Credentials>,
    #[serde(default)]
    pub users: Option<Vec<Credentials>>,
    #[serde(default)]
    pub override_host: Option<String>,
    #[serde(default)]
    pub override_port: Option<u16>,
    #[serde(default)]
    pub set_system_proxy: bool,
    #[serde(default = "default_true")]
    pub allow_private_network: bool,
    // Shadowsocks
    #[serde(default)]
    pub method: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub users_shadowsocks: Option<Vec<RawShadowsocksUserIR>>,
    #[serde(default)]
    pub network: Option<String>,
    // VMess
    #[serde(default)]
    pub uuid: Option<String>,
    #[serde(default)]
    pub alter_id: Option<u32>,
    #[serde(default)]
    pub users_vmess: Option<Vec<RawVmessUserIR>>,
    #[serde(default)]
    pub security: Option<String>,
    // VLESS
    #[serde(default)]
    pub flow: Option<String>,
    #[serde(default)]
    pub users_vless: Option<Vec<RawVlessUserIR>>,
    // Trojan
    #[serde(default)]
    pub users_trojan: Option<Vec<RawTrojanUserIR>>,
    #[serde(default)]
    pub version: Option<u8>,
    #[serde(default)]
    pub users_shadowtls: Option<Vec<RawShadowTlsUserIR>>,
    #[serde(default)]
    pub shadowtls_handshake: Option<RawShadowTlsHandshakeIR>,
    #[serde(default)]
    pub shadowtls_handshake_for_server_name:
        Option<std::collections::HashMap<String, RawShadowTlsHandshakeIR>>,
    #[serde(default)]
    pub shadowtls_strict_mode: Option<bool>,
    #[serde(default)]
    pub shadowtls_wildcard_sni: Option<String>,
    #[serde(default)]
    pub fallback: Option<String>,
    #[serde(default)]
    pub fallback_for_alpn: Option<std::collections::HashMap<String, String>>,
    // AnyTLS
    #[serde(default)]
    pub users_anytls: Option<Vec<RawAnyTlsUserIR>>,
    #[serde(default)]
    pub anytls_padding: Option<Vec<String>>,
    // Hysteria2
    #[serde(default)]
    pub users_hysteria2: Option<Vec<RawHysteria2UserIR>>,
    #[serde(default)]
    pub congestion_control: Option<String>,
    #[serde(default)]
    pub salamander: Option<String>,
    #[serde(default)]
    pub obfs: Option<String>,
    #[serde(default)]
    pub brutal_up_mbps: Option<u32>,
    #[serde(default)]
    pub brutal_down_mbps: Option<u32>,
    #[serde(default)]
    pub masquerade: Option<RawMasqueradeIR>,
    // TUIC
    #[serde(default)]
    pub users_tuic: Option<Vec<RawTuicUserIR>>,
    // Hysteria v1
    #[serde(default)]
    pub users_hysteria: Option<Vec<RawHysteriaUserIR>>,
    #[serde(default)]
    pub hysteria_protocol: Option<String>,
    #[serde(default)]
    pub hysteria_obfs: Option<String>,
    #[serde(default)]
    pub hysteria_up_mbps: Option<u32>,
    #[serde(default)]
    pub hysteria_down_mbps: Option<u32>,
    #[serde(default)]
    pub hysteria_recv_window_conn: Option<u64>,
    #[serde(default)]
    pub hysteria_recv_window: Option<u64>,
    // Transport and TLS
    #[serde(default)]
    pub transport: Option<Vec<String>>,
    #[serde(default)]
    pub ws_path: Option<String>,
    #[serde(default)]
    pub ws_host: Option<String>,
    #[serde(default)]
    pub h2_path: Option<String>,
    #[serde(default)]
    pub h2_host: Option<String>,
    #[serde(default)]
    pub grpc_service: Option<String>,
    #[serde(default)]
    pub tls_enabled: Option<bool>,
    #[serde(default)]
    pub tls_cert_path: Option<String>,
    #[serde(default)]
    pub tls_key_path: Option<String>,
    #[serde(default)]
    pub tls_cert_pem: Option<String>,
    #[serde(default)]
    pub tls_key_pem: Option<String>,
    #[serde(default)]
    pub tls_server_name: Option<String>,
    pub tls_alpn: Option<Vec<String>>,
    // Multiplex
    #[serde(default)]
    pub multiplex: Option<MultiplexOptionsIR>,
    // TUN
    #[serde(default)]
    pub tun: Option<RawTunOptionsIR>,
    // SSH
    #[serde(default)]
    pub ssh_host_key_path: Option<String>,
}

impl From<RawInboundIR> for InboundIR {
    fn from(raw: RawInboundIR) -> Self {
        Self {
            tag: raw.tag,
            ty: raw.ty,
            listen: raw.listen,
            port: raw.port,
            sniff: raw.sniff,
            sniff_override_destination: raw.sniff_override_destination,
            udp: raw.udp,
            udp_timeout: raw.udp_timeout,
            detour: raw.detour,
            domain_strategy: raw.domain_strategy,
            basic_auth: raw.basic_auth,
            users: raw.users,
            override_host: raw.override_host,
            override_port: raw.override_port,
            set_system_proxy: raw.set_system_proxy,
            allow_private_network: raw.allow_private_network,
            method: raw.method,
            password: raw.password,
            users_shadowsocks: raw
                .users_shadowsocks
                .map(|v| v.into_iter().map(Into::into).collect()),
            network: raw.network,
            uuid: raw.uuid,
            alter_id: raw.alter_id,
            users_vmess: raw
                .users_vmess
                .map(|v| v.into_iter().map(Into::into).collect()),
            security: raw.security,
            flow: raw.flow,
            users_vless: raw
                .users_vless
                .map(|v| v.into_iter().map(Into::into).collect()),
            users_trojan: raw
                .users_trojan
                .map(|v| v.into_iter().map(Into::into).collect()),
            version: raw.version,
            users_shadowtls: raw
                .users_shadowtls
                .map(|v| v.into_iter().map(Into::into).collect()),
            shadowtls_handshake: raw.shadowtls_handshake.map(Into::into),
            shadowtls_handshake_for_server_name: raw
                .shadowtls_handshake_for_server_name
                .map(|m| m.into_iter().map(|(k, v)| (k, v.into())).collect()),
            shadowtls_strict_mode: raw.shadowtls_strict_mode,
            shadowtls_wildcard_sni: raw.shadowtls_wildcard_sni,
            fallback: raw.fallback,
            fallback_for_alpn: raw.fallback_for_alpn,
            users_anytls: raw
                .users_anytls
                .map(|v| v.into_iter().map(Into::into).collect()),
            anytls_padding: raw.anytls_padding,
            users_hysteria2: raw
                .users_hysteria2
                .map(|v| v.into_iter().map(Into::into).collect()),
            congestion_control: raw.congestion_control,
            salamander: raw.salamander,
            obfs: raw.obfs,
            brutal_up_mbps: raw.brutal_up_mbps,
            brutal_down_mbps: raw.brutal_down_mbps,
            masquerade: raw.masquerade.map(Into::into),
            users_tuic: raw
                .users_tuic
                .map(|v| v.into_iter().map(Into::into).collect()),
            users_hysteria: raw
                .users_hysteria
                .map(|v| v.into_iter().map(Into::into).collect()),
            hysteria_protocol: raw.hysteria_protocol,
            hysteria_obfs: raw.hysteria_obfs,
            hysteria_up_mbps: raw.hysteria_up_mbps,
            hysteria_down_mbps: raw.hysteria_down_mbps,
            hysteria_recv_window_conn: raw.hysteria_recv_window_conn,
            hysteria_recv_window: raw.hysteria_recv_window,
            transport: raw.transport,
            ws_path: raw.ws_path,
            ws_host: raw.ws_host,
            h2_path: raw.h2_path,
            h2_host: raw.h2_host,
            grpc_service: raw.grpc_service,
            tls_enabled: raw.tls_enabled,
            tls_cert_path: raw.tls_cert_path,
            tls_key_path: raw.tls_key_path,
            tls_cert_pem: raw.tls_cert_pem,
            tls_key_pem: raw.tls_key_pem,
            tls_server_name: raw.tls_server_name,
            tls_alpn: raw.tls_alpn,
            multiplex: raw.multiplex,
            tun: raw.tun.map(Into::into),
            ssh_host_key_path: raw.ssh_host_key_path,
        }
    }
}

// ─────────────────── Outbound nested Raw types (WP-30i) ───────────────────

/// Raw HTTP header entry — strict input boundary for [`HeaderEntry`].
///
/// Field set is identical to `HeaderEntry`. Deserialization enters here
/// (with `deny_unknown_fields`), then converts via `From<RawHeaderEntry> for HeaderEntry`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawHeaderEntry {
    /// Header key/name.
    pub key: String,
    /// Header value.
    pub value: String,
}

impl From<RawHeaderEntry> for HeaderEntry {
    fn from(raw: RawHeaderEntry) -> Self {
        Self {
            key: raw.key,
            value: raw.value,
        }
    }
}

/// Raw authentication credentials — strict input boundary for [`Credentials`].
///
/// Field set is identical to `Credentials`. Deserialization enters here
/// (with `deny_unknown_fields`), then converts via `From<RawCredentials> for Credentials`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawCredentials {
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

impl From<RawCredentials> for Credentials {
    fn from(raw: RawCredentials) -> Self {
        Self {
            username: raw.username,
            password: raw.password,
            username_env: raw.username_env,
            password_env: raw.password_env,
        }
    }
}

/// Raw brutal congestion control configuration — strict input boundary for [`BrutalIR`].
///
/// Field set is identical to `BrutalIR`. Deserialization enters here
/// (with `deny_unknown_fields`), then converts via `From<RawBrutalIR> for BrutalIR`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawBrutalIR {
    /// Upload bandwidth in Mbps.
    pub up: u64,
    /// Download bandwidth in Mbps.
    pub down: u64,
}

impl From<RawBrutalIR> for BrutalIR {
    fn from(raw: RawBrutalIR) -> Self {
        Self {
            up: raw.up,
            down: raw.down,
        }
    }
}

/// Raw multiplex options — strict input boundary for [`MultiplexOptionsIR`].
///
/// Field set is identical to `MultiplexOptionsIR` except `brutal` uses
/// [`RawBrutalIR`]. Deserialization enters here (with `deny_unknown_fields`),
/// then converts via `From<RawMultiplexOptionsIR> for MultiplexOptionsIR`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawMultiplexOptionsIR {
    /// Enable multiplex support.
    #[serde(default)]
    pub enabled: bool,
    /// Protocol (typically "yamux" or "h2mux").
    #[serde(default)]
    pub protocol: Option<String>,
    /// Maximum number of concurrent connections in pool.
    #[serde(default)]
    pub max_connections: Option<usize>,
    /// Minimum number of streams per connection.
    #[serde(default)]
    pub min_streams: Option<usize>,
    /// Maximum number of streams per connection.
    #[serde(default)]
    pub max_streams: Option<usize>,
    /// Enable padding.
    #[serde(default)]
    pub padding: Option<bool>,
    /// Brutal congestion control configuration.
    #[serde(default)]
    pub brutal: Option<RawBrutalIR>,
    /// Initial stream window size.
    #[serde(default)]
    pub initial_stream_window: Option<u32>,
    /// Maximum stream window size.
    #[serde(default)]
    pub max_stream_window: Option<u32>,
    /// Enable keepalive.
    #[serde(default)]
    pub enable_keepalive: Option<bool>,
    /// Keepalive interval in seconds.
    #[serde(default)]
    pub keepalive_interval: Option<u64>,
}

impl From<RawMultiplexOptionsIR> for MultiplexOptionsIR {
    fn from(raw: RawMultiplexOptionsIR) -> Self {
        Self {
            enabled: raw.enabled,
            protocol: raw.protocol,
            max_connections: raw.max_connections,
            min_streams: raw.min_streams,
            max_streams: raw.max_streams,
            padding: raw.padding,
            brutal: raw.brutal.map(Into::into),
            initial_stream_window: raw.initial_stream_window,
            max_stream_window: raw.max_stream_window,
            enable_keepalive: raw.enable_keepalive,
            keepalive_interval: raw.keepalive_interval,
        }
    }
}

/// Raw outbound proxy configuration — strict input boundary for [`OutboundIR`].
///
/// Field set is identical to `OutboundIR` except nested types use their Raw
/// counterparts (`RawCredentials`, `RawMultiplexOptionsIR`, `RawHeaderEntry`).
/// `OutboundType` is intentionally reused as the validated enum — it is NOT
/// Raw-ified (WP-30i design decision, same pattern as `InboundType`/`EndpointType`).
///
/// Deserialization enters here (with `deny_unknown_fields`), then converts
/// via `From<RawOutboundIR> for OutboundIR`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawOutboundIR {
    pub ty: OutboundType,
    #[serde(default)]
    pub server: Option<String>,
    #[serde(default)]
    pub port: Option<u16>,
    #[serde(default)]
    pub udp: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub members: Option<Vec<String>>,
    #[serde(default)]
    pub default_member: Option<String>,
    #[serde(default)]
    pub method: Option<String>,
    #[serde(default)]
    pub credentials: Option<RawCredentials>,
    #[serde(default)]
    pub detour: Option<String>,
    #[serde(default)]
    pub uuid: Option<String>,
    #[serde(default)]
    pub flow: Option<String>,
    #[serde(default)]
    pub encryption: Option<String>,
    #[serde(default)]
    pub bind_interface: Option<String>,
    #[serde(default)]
    pub inet4_bind_address: Option<String>,
    #[serde(default)]
    pub inet6_bind_address: Option<String>,
    #[serde(default)]
    pub routing_mark: Option<u32>,
    #[serde(default)]
    pub reuse_addr: Option<bool>,
    #[serde(default)]
    pub connect_timeout: Option<String>,
    #[serde(default)]
    pub tcp_fast_open: Option<bool>,
    #[serde(default)]
    pub tcp_multi_path: Option<bool>,
    #[serde(default)]
    pub udp_fragment: Option<bool>,
    #[serde(default)]
    pub domain_strategy: Option<String>,
    #[serde(default)]
    pub multiplex: Option<RawMultiplexOptionsIR>,
    #[serde(default)]
    pub mux_max_streams: Option<usize>,
    #[serde(default)]
    pub mux_window_size: Option<u32>,
    #[serde(default)]
    pub mux_padding: Option<bool>,
    #[serde(default)]
    pub mux_reuse_timeout: Option<u64>,
    #[serde(default)]
    pub security: Option<String>,
    #[serde(default)]
    pub alter_id: Option<u8>,
    #[serde(default)]
    pub network: Option<String>,
    #[serde(default)]
    pub packet_encoding: Option<String>,
    #[serde(default)]
    pub transport: Option<Vec<String>>,
    #[serde(default)]
    pub congestion_control: Option<String>,
    #[serde(default)]
    pub token: Option<String>,
    #[serde(default)]
    pub ws_path: Option<String>,
    #[serde(default)]
    pub ws_host: Option<String>,
    #[serde(default)]
    pub h2_path: Option<String>,
    #[serde(default)]
    pub h2_host: Option<String>,
    #[serde(default)]
    pub grpc_service: Option<String>,
    #[serde(default)]
    pub grpc_method: Option<String>,
    #[serde(default)]
    pub grpc_authority: Option<String>,
    #[serde(default)]
    pub grpc_metadata: Vec<RawHeaderEntry>,
    #[serde(default)]
    pub http_upgrade_path: Option<String>,
    #[serde(default)]
    pub http_upgrade_headers: Vec<RawHeaderEntry>,
    #[serde(default)]
    pub tls_sni: Option<String>,
    #[serde(default)]
    pub tls_alpn: Option<Vec<String>>,
    #[serde(default)]
    pub dns_transport: Option<String>,
    #[serde(default)]
    pub dns_tls_server_name: Option<String>,
    #[serde(default)]
    pub dns_timeout_ms: Option<u64>,
    #[serde(default)]
    pub dns_query_timeout_ms: Option<u64>,
    #[serde(default)]
    pub dns_enable_edns0: Option<bool>,
    #[serde(default)]
    pub dns_edns0_buffer_size: Option<u16>,
    #[serde(default)]
    pub dns_doh_url: Option<String>,
    #[serde(default)]
    pub tls_ca_paths: Vec<String>,
    #[serde(default)]
    pub tls_ca_pem: Vec<String>,
    #[serde(default)]
    pub tls_client_cert_path: Option<String>,
    #[serde(default)]
    pub tls_client_key_path: Option<String>,
    #[serde(default)]
    pub tls_client_cert_pem: Option<String>,
    #[serde(default)]
    pub tls_client_key_pem: Option<String>,
    #[serde(default)]
    pub alpn: Option<String>,
    #[serde(default)]
    pub skip_cert_verify: Option<bool>,
    #[serde(default)]
    pub udp_relay_mode: Option<String>,
    #[serde(default)]
    pub udp_over_tcp: Option<bool>,
    #[serde(default)]
    pub udp_over_tcp_version: Option<u8>,
    #[serde(default)]
    pub utls_fingerprint: Option<String>,
    #[serde(default)]
    pub obfs_param: Option<String>,
    #[serde(default)]
    pub protocol: Option<String>,
    #[serde(default)]
    pub protocol_param: Option<String>,
    #[serde(default)]
    pub tor_executable_path: Option<String>,
    #[serde(default)]
    pub tor_extra_args: Vec<String>,
    #[serde(default)]
    pub tor_data_directory: Option<String>,
    #[serde(default)]
    pub udp_over_stream: Option<bool>,
    #[serde(default)]
    pub zero_rtt_handshake: Option<bool>,
    #[serde(default)]
    pub up_mbps: Option<u32>,
    #[serde(default)]
    pub down_mbps: Option<u32>,
    #[serde(default)]
    pub obfs: Option<String>,
    #[serde(default)]
    pub salamander: Option<String>,
    #[serde(default)]
    pub brutal_up_mbps: Option<u32>,
    #[serde(default)]
    pub brutal_down_mbps: Option<u32>,
    #[serde(default)]
    pub hysteria_protocol: Option<String>,
    #[serde(default)]
    pub hysteria_auth: Option<String>,
    #[serde(default)]
    pub hysteria_recv_window_conn: Option<u64>,
    #[serde(default)]
    pub hysteria_recv_window: Option<u64>,
    #[serde(default)]
    pub reality_enabled: Option<bool>,
    #[serde(default)]
    pub reality_public_key: Option<String>,
    #[serde(default)]
    pub reality_short_id: Option<String>,
    #[serde(default)]
    pub reality_server_name: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub version: Option<u8>,
    #[serde(default)]
    pub plugin: Option<String>,
    #[serde(default)]
    pub plugin_opts: Option<String>,
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
    #[serde(default)]
    pub wireguard_system_interface: Option<bool>,
    #[serde(default)]
    pub wireguard_interface: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub wireguard_local_address: Vec<String>,
    #[serde(default)]
    pub wireguard_source_v4: Option<String>,
    #[serde(default)]
    pub wireguard_source_v6: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub wireguard_allowed_ips: Vec<String>,
    #[serde(default)]
    pub wireguard_private_key: Option<String>,
    #[serde(default)]
    pub wireguard_peer_public_key: Option<String>,
    #[serde(default)]
    pub wireguard_pre_shared_key: Option<String>,
    #[serde(default)]
    pub wireguard_persistent_keepalive: Option<u16>,
    #[serde(default)]
    pub tor_proxy_addr: Option<String>,
    #[serde(default)]
    pub tor_options: Option<std::collections::HashMap<String, String>>,
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
    #[serde(default)]
    pub anytls_padding: Option<Vec<String>>,
}

impl From<RawOutboundIR> for OutboundIR {
    fn from(raw: RawOutboundIR) -> Self {
        Self {
            ty: raw.ty,
            server: raw.server,
            port: raw.port,
            udp: raw.udp,
            name: raw.name,
            members: raw.members,
            default_member: raw.default_member,
            method: raw.method,
            credentials: raw.credentials.map(Into::into),
            detour: raw.detour,
            uuid: raw.uuid,
            flow: raw.flow,
            encryption: raw.encryption,
            bind_interface: raw.bind_interface,
            inet4_bind_address: raw.inet4_bind_address,
            inet6_bind_address: raw.inet6_bind_address,
            routing_mark: raw.routing_mark,
            reuse_addr: raw.reuse_addr,
            connect_timeout: raw.connect_timeout,
            tcp_fast_open: raw.tcp_fast_open,
            tcp_multi_path: raw.tcp_multi_path,
            udp_fragment: raw.udp_fragment,
            domain_strategy: raw.domain_strategy,
            multiplex: raw.multiplex.map(Into::into),
            mux_max_streams: raw.mux_max_streams,
            mux_window_size: raw.mux_window_size,
            mux_padding: raw.mux_padding,
            mux_reuse_timeout: raw.mux_reuse_timeout,
            security: raw.security,
            alter_id: raw.alter_id,
            network: raw.network,
            packet_encoding: raw.packet_encoding,
            transport: raw.transport,
            congestion_control: raw.congestion_control,
            token: raw.token,
            ws_path: raw.ws_path,
            ws_host: raw.ws_host,
            h2_path: raw.h2_path,
            h2_host: raw.h2_host,
            grpc_service: raw.grpc_service,
            grpc_method: raw.grpc_method,
            grpc_authority: raw.grpc_authority,
            grpc_metadata: raw.grpc_metadata.into_iter().map(Into::into).collect(),
            http_upgrade_path: raw.http_upgrade_path,
            http_upgrade_headers: raw
                .http_upgrade_headers
                .into_iter()
                .map(Into::into)
                .collect(),
            tls_sni: raw.tls_sni,
            tls_alpn: raw.tls_alpn,
            dns_transport: raw.dns_transport,
            dns_tls_server_name: raw.dns_tls_server_name,
            dns_timeout_ms: raw.dns_timeout_ms,
            dns_query_timeout_ms: raw.dns_query_timeout_ms,
            dns_enable_edns0: raw.dns_enable_edns0,
            dns_edns0_buffer_size: raw.dns_edns0_buffer_size,
            dns_doh_url: raw.dns_doh_url,
            tls_ca_paths: raw.tls_ca_paths,
            tls_ca_pem: raw.tls_ca_pem,
            tls_client_cert_path: raw.tls_client_cert_path,
            tls_client_key_path: raw.tls_client_key_path,
            tls_client_cert_pem: raw.tls_client_cert_pem,
            tls_client_key_pem: raw.tls_client_key_pem,
            alpn: raw.alpn,
            skip_cert_verify: raw.skip_cert_verify,
            udp_relay_mode: raw.udp_relay_mode,
            udp_over_tcp: raw.udp_over_tcp,
            udp_over_tcp_version: raw.udp_over_tcp_version,
            utls_fingerprint: raw.utls_fingerprint,
            obfs_param: raw.obfs_param,
            protocol: raw.protocol,
            protocol_param: raw.protocol_param,
            tor_executable_path: raw.tor_executable_path,
            tor_extra_args: raw.tor_extra_args,
            tor_data_directory: raw.tor_data_directory,
            udp_over_stream: raw.udp_over_stream,
            zero_rtt_handshake: raw.zero_rtt_handshake,
            up_mbps: raw.up_mbps,
            down_mbps: raw.down_mbps,
            obfs: raw.obfs,
            salamander: raw.salamander,
            brutal_up_mbps: raw.brutal_up_mbps,
            brutal_down_mbps: raw.brutal_down_mbps,
            hysteria_protocol: raw.hysteria_protocol,
            hysteria_auth: raw.hysteria_auth,
            hysteria_recv_window_conn: raw.hysteria_recv_window_conn,
            hysteria_recv_window: raw.hysteria_recv_window,
            reality_enabled: raw.reality_enabled,
            reality_public_key: raw.reality_public_key,
            reality_short_id: raw.reality_short_id,
            reality_server_name: raw.reality_server_name,
            password: raw.password,
            version: raw.version,
            plugin: raw.plugin,
            plugin_opts: raw.plugin_opts,
            ssh_private_key: raw.ssh_private_key,
            ssh_private_key_path: raw.ssh_private_key_path,
            ssh_private_key_passphrase: raw.ssh_private_key_passphrase,
            ssh_host_key_verification: raw.ssh_host_key_verification,
            ssh_known_hosts_path: raw.ssh_known_hosts_path,
            ssh_connection_pool_size: raw.ssh_connection_pool_size,
            ssh_compression: raw.ssh_compression,
            ssh_keepalive_interval: raw.ssh_keepalive_interval,
            connect_timeout_sec: raw.connect_timeout_sec,
            wireguard_system_interface: raw.wireguard_system_interface,
            wireguard_interface: raw.wireguard_interface,
            wireguard_local_address: raw.wireguard_local_address,
            wireguard_source_v4: raw.wireguard_source_v4,
            wireguard_source_v6: raw.wireguard_source_v6,
            wireguard_allowed_ips: raw.wireguard_allowed_ips,
            wireguard_private_key: raw.wireguard_private_key,
            wireguard_peer_public_key: raw.wireguard_peer_public_key,
            wireguard_pre_shared_key: raw.wireguard_pre_shared_key,
            wireguard_persistent_keepalive: raw.wireguard_persistent_keepalive,
            tor_proxy_addr: raw.tor_proxy_addr,
            tor_options: raw.tor_options,
            test_url: raw.test_url,
            test_interval_ms: raw.test_interval_ms,
            test_timeout_ms: raw.test_timeout_ms,
            test_tolerance_ms: raw.test_tolerance_ms,
            interrupt_exist_connections: raw.interrupt_exist_connections,
            anytls_padding: raw.anytls_padding,
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
/// configs are also rejected. `dns` uses [`RawDnsIR`], `route` uses
/// [`RawRouteIR`], and `endpoints` uses [`RawEndpointIR`], so unknown
/// fields across the DNS, route, and endpoint nested subtrees are also
/// rejected.
///
/// `outbounds` uses [`RawOutboundIR`] so unknown outbound fields are rejected (WP-30i).
/// `inbounds` uses [`RawInboundIR`] so unknown inbound fields are rejected (WP-30h).
/// `services` uses [`RawServiceIR`] so unknown service fields are rejected.
///
/// `ExperimentalIR` intentionally does NOT have a Raw counterpart;
/// it uses forward-compatible passthrough semantics.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawConfigRoot {
    /// Inbound listeners (strict: rejects unknown fields).
    #[serde(default)]
    pub inbounds: Vec<RawInboundIR>,
    /// Outbound proxies (strict: rejects unknown fields, WP-30i).
    #[serde(default)]
    pub outbounds: Vec<RawOutboundIR>,
    /// Routing configuration (strict: rejects unknown fields).
    #[serde(default)]
    pub route: RawRouteIR,
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
    /// Endpoint configurations (strict: rejects unknown fields).
    #[serde(default)]
    pub endpoints: Vec<RawEndpointIR>,
    /// Service configurations (Resolved, DERP, SSM, etc.).
    #[serde(default)]
    pub services: Vec<RawServiceIR>,
    /// Optional experimental configuration blob (schema v2 passthrough).
    #[serde(default)]
    pub experimental: Option<ExperimentalIR>,
}

impl From<RawConfigRoot> for ConfigIR {
    fn from(raw: RawConfigRoot) -> Self {
        Self {
            inbounds: raw.inbounds.into_iter().map(Into::into).collect(),
            outbounds: raw.outbounds.into_iter().map(Into::into).collect(),
            route: raw.route.into(),
            log: raw.log.map(Into::into),
            ntp: raw.ntp.map(Into::into),
            certificate: raw.certificate.map(Into::into),
            dns: raw.dns.map(Into::into),
            endpoints: raw.endpoints.into_iter().map(Into::into).collect(),
            services: raw.services.into_iter().map(Into::into).collect(),
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

    // ─────────────────── Raw Route tests (WP-30e) ───────────────────

    #[test]
    fn raw_rule_ir_rejects_unknown_field() {
        let data = json!({
            "domain": ["example.com"],
            "outbound": "proxy",
            "bogus_rule_field": true
        });
        let result = serde_json::from_value::<RawRuleIR>(data);
        assert!(result.is_err(), "RawRuleIR should reject unknown fields");
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("unknown field") || err.contains("bogus_rule_field"),
            "error should mention unknown field, got: {err}"
        );
    }

    #[test]
    fn raw_domain_resolve_options_ir_rejects_unknown_field() {
        let data = json!({
            "server": "dns-local",
            "bogus_resolve_field": true
        });
        let result = serde_json::from_value::<RawDomainResolveOptionsIR>(data);
        assert!(
            result.is_err(),
            "RawDomainResolveOptionsIR should reject unknown fields"
        );
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("unknown field") || err.contains("bogus_resolve_field"),
            "error should mention unknown field, got: {err}"
        );
    }

    #[test]
    fn raw_rule_set_ir_rejects_unknown_field() {
        let data = json!({
            "tag": "my-set",
            "type": "local",
            "bogus_ruleset_field": true
        });
        let result = serde_json::from_value::<RawRuleSetIR>(data);
        assert!(result.is_err(), "RawRuleSetIR should reject unknown fields");
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("unknown field") || err.contains("bogus_ruleset_field"),
            "error should mention unknown field, got: {err}"
        );
    }

    #[test]
    fn raw_route_ir_rejects_unknown_field() {
        let data = json!({
            "rules": [],
            "bogus_route_field": true
        });
        let result = serde_json::from_value::<RawRouteIR>(data);
        assert!(result.is_err(), "RawRouteIR should reject unknown fields");
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("unknown field") || err.contains("bogus_route_field"),
            "error should mention unknown field, got: {err}"
        );
    }

    #[test]
    fn rule_ir_rejects_unknown_field_via_raw_bridge() {
        use super::super::RuleIR;
        let data = json!({
            "domain": ["example.com"],
            "bogus_rule_field": "bad"
        });
        let result = serde_json::from_value::<RuleIR>(data);
        assert!(
            result.is_err(),
            "RuleIR should reject unknown fields via Raw bridge"
        );
    }

    #[test]
    fn domain_resolve_options_ir_rejects_unknown_field_via_raw_bridge() {
        use super::super::DomainResolveOptionsIR;
        let data = json!({
            "server": "dns-local",
            "bogus_resolve_field": 42
        });
        let result = serde_json::from_value::<DomainResolveOptionsIR>(data);
        assert!(
            result.is_err(),
            "DomainResolveOptionsIR should reject unknown fields via Raw bridge"
        );
    }

    #[test]
    fn rule_set_ir_rejects_unknown_field_via_raw_bridge() {
        use super::super::RuleSetIR;
        let data = json!({
            "tag": "my-set",
            "type": "local",
            "bogus_ruleset_field": "bad"
        });
        let result = serde_json::from_value::<RuleSetIR>(data);
        assert!(
            result.is_err(),
            "RuleSetIR should reject unknown fields via Raw bridge"
        );
    }

    #[test]
    fn route_ir_rejects_unknown_field_via_raw_bridge() {
        use super::super::RouteIR;
        let data = json!({
            "rules": [],
            "bogus_route_field": "bad"
        });
        let result = serde_json::from_value::<RouteIR>(data);
        assert!(
            result.is_err(),
            "RouteIR should reject unknown fields via Raw bridge"
        );
    }

    #[test]
    fn rule_ir_valid_roundtrip() {
        use super::super::RuleIR;
        let data = json!({
            "domain": ["example.com", "test.org"],
            "domain_suffix": [".cn"],
            "geoip": ["CN"],
            "port": ["80", "443"],
            "action": "route",
            "outbound": "proxy"
        });
        let ir: RuleIR = serde_json::from_value(data).unwrap();
        assert_eq!(ir.domain, vec!["example.com", "test.org"]);
        assert_eq!(ir.geoip, vec!["CN"]);
        assert_eq!(ir.action, super::super::RuleAction::Route);
        // roundtrip
        let json = serde_json::to_value(&ir).unwrap();
        let ir2: RuleIR = serde_json::from_value(json).unwrap();
        assert_eq!(ir, ir2);
    }

    #[test]
    fn domain_resolve_options_ir_valid_roundtrip() {
        use super::super::DomainResolveOptionsIR;
        let data = json!({
            "server": "dns-local",
            "strategy": "prefer_ipv4",
            "disable_cache": true,
            "rewrite_ttl": 120,
            "client_subnet": "10.0.0.0/24"
        });
        let ir: DomainResolveOptionsIR = serde_json::from_value(data).unwrap();
        assert_eq!(ir.server, "dns-local");
        assert_eq!(ir.strategy.as_deref(), Some("prefer_ipv4"));
        let json = serde_json::to_value(&ir).unwrap();
        let ir2: DomainResolveOptionsIR = serde_json::from_value(json).unwrap();
        assert_eq!(ir, ir2);
    }

    #[test]
    fn rule_set_ir_valid_roundtrip() {
        use super::super::RuleSetIR;
        let data = json!({
            "tag": "geosite-cn",
            "type": "remote",
            "format": "binary",
            "url": "https://example.com/geosite-cn.srs",
            "update_interval": "24h"
        });
        let ir: RuleSetIR = serde_json::from_value(data).unwrap();
        assert_eq!(ir.tag, "geosite-cn");
        assert_eq!(ir.ty, "remote");
        let json = serde_json::to_value(&ir).unwrap();
        let ir2: RuleSetIR = serde_json::from_value(json).unwrap();
        assert_eq!(ir, ir2);
    }

    #[test]
    fn route_ir_valid_roundtrip() {
        use super::super::RouteIR;
        let data = json!({
            "rules": [
                {"domain_suffix": [".cn"], "outbound": "direct"}
            ],
            "rule_set": [
                {"tag": "geosite-cn", "type": "remote", "format": "binary",
                 "url": "https://example.com/geosite-cn.srs"}
            ],
            "default": "proxy",
            "final": "direct",
            "find_process": true,
            "mark": 100,
            "default_domain_resolver": {"server": "local-dns"},
            "network_strategy": "prefer_ipv4"
        });
        let ir: RouteIR = serde_json::from_value(data).unwrap();
        assert_eq!(ir.rules.len(), 1);
        assert_eq!(ir.rule_set.len(), 1);
        assert_eq!(ir.default.as_deref(), Some("proxy"));
        assert_eq!(ir.final_outbound.as_deref(), Some("direct"));
        assert_eq!(ir.mark, Some(100));
        // roundtrip
        let json = serde_json::to_value(&ir).unwrap();
        let ir2: RouteIR = serde_json::from_value(json).unwrap();
        assert_eq!(ir.rules.len(), ir2.rules.len());
        assert_eq!(ir.default, ir2.default);
    }

    #[test]
    fn rule_action_serde_unchanged_after_route_raw() {
        use super::super::RuleAction;
        // Verify RuleAction kebab-case serde still works
        let parsed: RuleAction = serde_json::from_str("\"reject-drop\"").unwrap();
        assert_eq!(parsed, RuleAction::RejectDrop);
        assert_eq!(parsed.as_str(), "reject-drop");
        assert_eq!(
            RuleAction::from_str_opt("hijack_dns"),
            Some(RuleAction::HijackDns)
        );
    }

    #[test]
    fn config_ir_accepts_valid_route_subtree_via_raw_bridge() {
        let data = json!({
            "route": {
                "rules": [
                    {"domain_suffix": [".cn"], "outbound": "direct"},
                    {"geoip": ["US"], "outbound": "proxy"}
                ],
                "rule_set": [
                    {"tag": "geosite-cn", "type": "remote", "format": "binary",
                     "url": "https://example.com/geosite-cn.srs"}
                ],
                "final": "direct",
                "find_process": true,
                "default_domain_resolver": {"server": "local-dns"}
            }
        });
        let ir = serde_json::from_value::<ConfigIR>(data).unwrap();
        assert_eq!(ir.route.rules.len(), 2);
        assert_eq!(ir.route.rule_set.len(), 1);
        assert_eq!(ir.route.final_outbound.as_deref(), Some("direct"));
        assert!(ir.route.default_domain_resolver.is_some());
    }

    #[test]
    fn config_ir_rejects_unknown_field_inside_route_subtree() {
        let data = json!({
            "route": {
                "rules": [],
                "unknown_route_field": true
            }
        });
        let result = serde_json::from_value::<ConfigIR>(data);
        assert!(
            result.is_err(),
            "ConfigIR should reject unknown fields inside route via Raw bridge"
        );
    }

    #[test]
    fn config_ir_rejects_unknown_field_inside_route_rule() {
        let data = json!({
            "route": {
                "rules": [
                    {
                        "domain": ["example.com"],
                        "outbound": "proxy",
                        "unknown_rule_field": true
                    }
                ]
            }
        });
        let result = serde_json::from_value::<ConfigIR>(data);
        assert!(
            result.is_err(),
            "ConfigIR should reject unknown fields inside route.rules via Raw bridge"
        );
    }

    // ─────────────────── Raw Endpoint tests (WP-30f) ───────────────────

    #[test]
    fn raw_wireguard_peer_ir_rejects_unknown_field() {
        let data = json!({
            "address": "192.168.1.1",
            "port": 51820,
            "bogus_peer_field": true
        });
        let result = serde_json::from_value::<RawWireGuardPeerIR>(data);
        assert!(
            result.is_err(),
            "RawWireGuardPeerIR should reject unknown fields"
        );
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("unknown field") || err.contains("bogus_peer_field"),
            "error should mention unknown field, got: {err}"
        );
    }

    #[test]
    fn raw_endpoint_ir_rejects_unknown_field() {
        let data = json!({
            "type": "wireguard",
            "tag": "wg0",
            "bogus_endpoint_field": true
        });
        let result = serde_json::from_value::<RawEndpointIR>(data);
        assert!(
            result.is_err(),
            "RawEndpointIR should reject unknown fields"
        );
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("unknown field") || err.contains("bogus_endpoint_field"),
            "error should mention unknown field, got: {err}"
        );
    }

    #[test]
    fn wireguard_peer_ir_rejects_unknown_field_via_raw_bridge() {
        use super::super::WireGuardPeerIR;
        let data = json!({
            "address": "10.0.0.1",
            "bogus_peer_field": "bad"
        });
        let result = serde_json::from_value::<WireGuardPeerIR>(data);
        assert!(
            result.is_err(),
            "WireGuardPeerIR should reject unknown fields via Raw bridge"
        );
    }

    #[test]
    fn endpoint_ir_rejects_unknown_field_via_raw_bridge() {
        use super::super::EndpointIR;
        let data = json!({
            "type": "wireguard",
            "tag": "wg0",
            "bogus_endpoint_field": 42
        });
        let result = serde_json::from_value::<EndpointIR>(data);
        assert!(
            result.is_err(),
            "EndpointIR should reject unknown fields via Raw bridge"
        );
    }

    #[test]
    fn wireguard_peer_ir_valid_roundtrip() {
        use super::super::WireGuardPeerIR;
        let data = json!({
            "address": "192.168.1.1",
            "port": 51820,
            "public_key": "peer-pubkey-base64",
            "pre_shared_key": "psk-base64",
            "allowed_ips": ["0.0.0.0/0", "::/0"],
            "persistent_keepalive_interval": 25,
            "reserved": [1, 2, 3]
        });
        let ir: WireGuardPeerIR = serde_json::from_value(data).unwrap();
        assert_eq!(ir.address.as_deref(), Some("192.168.1.1"));
        assert_eq!(ir.port, Some(51820));
        assert_eq!(ir.public_key.as_deref(), Some("peer-pubkey-base64"));
        assert_eq!(ir.pre_shared_key.as_deref(), Some("psk-base64"));
        assert_eq!(
            ir.allowed_ips,
            Some(vec!["0.0.0.0/0".to_string(), "::/0".to_string()])
        );
        assert_eq!(ir.persistent_keepalive_interval, Some(25));
        assert_eq!(ir.reserved, Some(vec![1, 2, 3]));
        // roundtrip
        let json = serde_json::to_value(&ir).unwrap();
        let ir2: WireGuardPeerIR = serde_json::from_value(json).unwrap();
        assert_eq!(ir, ir2);
    }

    #[test]
    fn endpoint_ir_wireguard_valid_roundtrip() {
        use super::super::EndpointIR;
        let data = json!({
            "type": "wireguard",
            "tag": "wg0",
            "network": ["tcp", "udp"],
            "wireguard_private_key": "priv-key-base64",
            "wireguard_address": ["10.0.0.1/24"],
            "wireguard_mtu": 1420,
            "wireguard_listen_port": 51820,
            "wireguard_peers": [
                {
                    "address": "192.168.1.1",
                    "port": 51820,
                    "public_key": "peer-pubkey",
                    "allowed_ips": ["0.0.0.0/0"]
                }
            ],
            "wireguard_udp_timeout": "30s",
            "wireguard_workers": 4
        });
        let ir: EndpointIR = serde_json::from_value(data).unwrap();
        assert_eq!(ir.ty, super::super::EndpointType::Wireguard);
        assert_eq!(ir.tag.as_deref(), Some("wg0"));
        assert_eq!(ir.wireguard_private_key.as_deref(), Some("priv-key-base64"));
        assert_eq!(ir.wireguard_peers.as_ref().unwrap().len(), 1);
        // roundtrip
        let json = serde_json::to_value(&ir).unwrap();
        let ir2: EndpointIR = serde_json::from_value(json).unwrap();
        assert_eq!(ir, ir2);
    }

    #[test]
    fn endpoint_ir_tailscale_valid_roundtrip() {
        use super::super::EndpointIR;
        let data = json!({
            "type": "tailscale",
            "tag": "ts0",
            "tailscale_auth_key": "tskey-xyz",
            "tailscale_hostname": "my-node",
            "tailscale_control_url": "https://controlplane.tailscale.com",
            "tailscale_ephemeral": true,
            "tailscale_accept_routes": true,
            "tailscale_exit_node": "100.64.0.1",
            "tailscale_exit_node_allow_lan_access": true,
            "tailscale_advertise_routes": ["192.168.0.0/24"],
            "tailscale_advertise_exit_node": false,
            "tailscale_udp_timeout": "60s",
            "tailscale_state_directory": "/var/lib/tailscale"
        });
        let ir: EndpointIR = serde_json::from_value(data).unwrap();
        assert_eq!(ir.ty, super::super::EndpointType::Tailscale);
        assert_eq!(ir.tag.as_deref(), Some("ts0"));
        assert_eq!(ir.tailscale_auth_key.as_deref(), Some("tskey-xyz"));
        assert_eq!(ir.tailscale_hostname.as_deref(), Some("my-node"));
        assert_eq!(ir.tailscale_ephemeral, Some(true));
        // roundtrip
        let json = serde_json::to_value(&ir).unwrap();
        let ir2: EndpointIR = serde_json::from_value(json).unwrap();
        assert_eq!(ir, ir2);
    }

    #[test]
    fn endpoint_type_lowercase_serde_unchanged() {
        use super::super::EndpointType;
        let wg: EndpointType = serde_json::from_str("\"wireguard\"").unwrap();
        assert_eq!(wg, EndpointType::Wireguard);
        let ts: EndpointType = serde_json::from_str("\"tailscale\"").unwrap();
        assert_eq!(ts, EndpointType::Tailscale);
        // Serialize back
        assert_eq!(serde_json::to_string(&wg).unwrap(), "\"wireguard\"");
        assert_eq!(serde_json::to_string(&ts).unwrap(), "\"tailscale\"");
    }

    #[test]
    fn config_ir_accepts_valid_endpoint_subtree_via_raw_bridge() {
        let data = json!({
            "endpoints": [
                {
                    "type": "wireguard",
                    "tag": "wg0",
                    "wireguard_private_key": "key123",
                    "wireguard_address": ["10.0.0.1/24"],
                    "wireguard_peers": [
                        {
                            "address": "1.2.3.4",
                            "port": 51820,
                            "public_key": "peer-pub",
                            "allowed_ips": ["0.0.0.0/0"]
                        }
                    ]
                },
                {
                    "type": "tailscale",
                    "tag": "ts0",
                    "tailscale_auth_key": "tskey-abc"
                }
            ]
        });
        let ir = serde_json::from_value::<ConfigIR>(data).unwrap();
        assert_eq!(ir.endpoints.len(), 2);
        assert_eq!(ir.endpoints[0].ty, super::super::EndpointType::Wireguard);
        assert_eq!(ir.endpoints[1].ty, super::super::EndpointType::Tailscale);
        assert_eq!(ir.endpoints[0].wireguard_peers.as_ref().unwrap().len(), 1);
    }

    #[test]
    fn config_ir_rejects_unknown_field_inside_endpoint_subtree() {
        let data = json!({
            "endpoints": [{
                "type": "wireguard",
                "tag": "wg0",
                "unknown_endpoint_field": true
            }]
        });
        let result = serde_json::from_value::<ConfigIR>(data);
        assert!(
            result.is_err(),
            "ConfigIR should reject unknown fields inside endpoints via Raw bridge"
        );
    }

    #[test]
    fn config_ir_rejects_unknown_field_inside_endpoint_peer() {
        let data = json!({
            "endpoints": [{
                "type": "wireguard",
                "tag": "wg0",
                "wireguard_peers": [{
                    "address": "1.2.3.4",
                    "unknown_peer_field": true
                }]
            }]
        });
        let result = serde_json::from_value::<ConfigIR>(data);
        assert!(
            result.is_err(),
            "ConfigIR should reject unknown fields inside endpoint peers via Raw bridge"
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

    /// Boundary documentation: inbound/outbound/service nested trees still
    /// do NOT have nested Raw types. DNS, route, and endpoint are now strict;
    /// these remaining domains are future work, not regressions from WP-30f.
    #[test]
    fn nested_non_leaf_unknown_fields_not_yet_strict_boundary_doc() {
        // Route is now strict (WP-30e): unknown route fields are rejected.
        let data = json!({
            "route": {
                "rules": [],
                "some_unknown_route_field": true
            }
        });
        let result = serde_json::from_value::<ConfigIR>(data);
        assert!(
            result.is_err(),
            "route nested unknown fields should be rejected after WP-30e"
        );

        // Endpoint is now strict (WP-30f): unknown endpoint fields are rejected.
        let data = json!({
            "endpoints": [{
                "type": "wireguard",
                "bogus_endpoint_field": true
            }]
        });
        let result = serde_json::from_value::<ConfigIR>(data);
        assert!(
            result.is_err(),
            "endpoint nested unknown fields should be rejected after WP-30f"
        );

        // Service is now strict (WP-30g): unknown service fields are rejected.
        let data = json!({
            "services": [{
                "type": "resolved",
                "bogus_service_field": true
            }]
        });
        let result = serde_json::from_value::<ConfigIR>(data);
        assert!(
            result.is_err(),
            "service nested unknown fields should be rejected after WP-30g"
        );

        // Inbound/outbound remain non-strict (future work).
    }

    // ─────────────────── Service Raw boundary tests (WP-30g) ───────────────────

    #[test]
    fn raw_service_ir_rejects_unknown_field() {
        let data = json!({
            "type": "resolved",
            "tag": "dns-svc",
            "bogus_service_field": true
        });
        let result = serde_json::from_value::<RawServiceIR>(data);
        assert!(result.is_err(), "RawServiceIR should reject unknown fields");
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("unknown field") || err.contains("bogus_service_field"),
            "error should mention unknown field, got: {err}"
        );
    }

    #[test]
    fn service_ir_rejects_unknown_field_via_raw_bridge() {
        let data = json!({
            "type": "resolved",
            "tag": "dns-svc",
            "bogus_service_field": 42
        });
        let result = serde_json::from_value::<ServiceIR>(data);
        assert!(
            result.is_err(),
            "ServiceIR should reject unknown fields via Raw bridge"
        );
    }

    #[test]
    fn raw_service_ir_parses_resolved_service() {
        let data = json!({
            "type": "resolved",
            "tag": "dns-svc",
            "listen": "127.0.0.53",
            "listen_port": 53
        });
        let raw: RawServiceIR = serde_json::from_value(data).unwrap();
        assert_eq!(raw.ty, ServiceType::Resolved);
        assert_eq!(raw.tag, Some("dns-svc".to_string()));
        let ir: ServiceIR = raw.into();
        assert_eq!(ir.listen, Some("127.0.0.53".to_string()));
        assert_eq!(ir.listen_port, Some(53));
    }

    #[test]
    fn raw_service_ir_parses_ssmapi_service() {
        let data = json!({
            "type": "ssm-api",
            "tag": "ssm",
            "listen": "127.0.0.1",
            "listen_port": 6001,
            "servers": { "/": "ss-in" },
            "auth_token": "secret"
        });
        let raw: RawServiceIR = serde_json::from_value(data).unwrap();
        assert_eq!(raw.ty, ServiceType::Ssmapi);
        let ir: ServiceIR = raw.into();
        assert_eq!(ir.auth_token.as_deref(), Some("secret"));
        assert!(ir.servers.is_some());
    }

    #[test]
    fn raw_service_ir_parses_derp_with_tls_and_stun() {
        let data = json!({
            "type": "derp",
            "tag": "derp-relay",
            "listen": "0.0.0.0",
            "listen_port": 3478,
            "config_path": "derper.key",
            "tls": {
                "enabled": true,
                "certificate_path": "c.pem",
                "key_path": "k.pem"
            },
            "stun": { "enabled": true, "listen_port": 3479 }
        });
        let raw: RawServiceIR = serde_json::from_value(data).unwrap();
        assert_eq!(raw.ty, ServiceType::Derp);
        let ir: ServiceIR = raw.into();
        let tls = ir.tls.as_ref().unwrap();
        assert!(tls.enabled);
        assert_eq!(tls.certificate_path.as_deref(), Some("c.pem"));
        let stun = ir.stun.as_ref().unwrap();
        assert!(stun.enabled);
        assert_eq!(stun.listen_port, Some(3479));
    }

    #[test]
    fn raw_inbound_tls_options_rejects_unknown_field() {
        let data = json!({
            "enabled": true,
            "server_name": "example.com",
            "bogus_tls_field": true
        });
        let result = serde_json::from_value::<RawInboundTlsOptionsIR>(data);
        assert!(
            result.is_err(),
            "RawInboundTlsOptionsIR should reject unknown fields"
        );
    }

    #[test]
    fn inbound_tls_options_rejects_unknown_via_raw_bridge() {
        let data = json!({
            "enabled": true,
            "bogus_tls_field": true
        });
        let result = serde_json::from_value::<super::InboundTlsOptionsIR>(data);
        assert!(
            result.is_err(),
            "InboundTlsOptionsIR should reject unknown fields via Raw bridge"
        );
    }

    #[test]
    fn raw_derp_stun_bool_port_object() {
        // Bool form
        let raw: RawDerpStunOptionsIR = serde_json::from_value(json!(true)).unwrap();
        assert!(raw.enabled);
        assert!(raw.listen_port.is_none());

        // Port form
        let raw: RawDerpStunOptionsIR = serde_json::from_value(json!(3479)).unwrap();
        assert!(raw.enabled);
        assert_eq!(raw.listen_port, Some(3479));

        // Object form
        let raw: RawDerpStunOptionsIR = serde_json::from_value(json!({
            "enabled": false,
            "listen": "::",
            "listen_port": 3478
        }))
        .unwrap();
        assert!(!raw.enabled);
        assert_eq!(raw.listen.as_deref(), Some("::"));

        // Object form rejects unknown fields
        let result = serde_json::from_value::<RawDerpStunOptionsIR>(json!({
            "enabled": true,
            "bogus_stun_field": true
        }));
        assert!(
            result.is_err(),
            "RawDerpStunOptionsObj should reject unknown fields"
        );
    }

    #[test]
    fn raw_derp_domain_resolver_rejects_unknown_field() {
        let data = json!({
            "server": "dns-out",
            "strategy": "ipv4_only",
            "bogus_resolver_field": true
        });
        let result = serde_json::from_value::<RawDerpDomainResolverIR>(data);
        assert!(
            result.is_err(),
            "RawDerpDomainResolverIR should reject unknown fields"
        );
    }

    #[test]
    fn raw_derp_dial_options_rejects_unknown_field() {
        let data = json!({
            "detour": "d1",
            "bogus_dial_field": true
        });
        let result = serde_json::from_value::<RawDerpDialOptionsIR>(data);
        assert!(
            result.is_err(),
            "RawDerpDialOptionsIR should reject unknown fields"
        );
    }

    #[test]
    fn raw_derp_verify_client_url_rejects_unknown_field() {
        let data = json!({
            "url": "https://example.com/verify",
            "detour": "d1",
            "bogus_verify_field": true
        });
        let result = serde_json::from_value::<RawDerpVerifyClientUrlIR>(data);
        assert!(
            result.is_err(),
            "RawDerpVerifyClientUrlIR should reject unknown fields"
        );
    }

    #[test]
    fn raw_derp_verify_client_url_inlines_dial_fields() {
        let data = json!({
            "url": "https://example.com/verify",
            "detour": "d1",
            "routing_mark": 123,
            "reuse_addr": true,
            "connect_timeout": "3s"
        });
        let raw: RawDerpVerifyClientUrlIR = serde_json::from_value(data).unwrap();
        let ir: DerpVerifyClientUrlIR = raw.into();
        assert_eq!(ir.url, "https://example.com/verify");
        assert_eq!(ir.dial.detour.as_deref(), Some("d1"));
        assert_eq!(ir.dial.routing_mark, Some(123));
        assert_eq!(ir.dial.reuse_addr, Some(true));
        assert_eq!(ir.dial.connect_timeout.as_deref(), Some("3s"));
    }

    #[test]
    fn raw_derp_outbound_tls_rejects_unknown_field() {
        let data = json!({
            "enabled": true,
            "server_name": "derp.example.com",
            "bogus_outbound_tls_field": true
        });
        let result = serde_json::from_value::<RawDerpOutboundTlsOptionsIR>(data);
        assert!(
            result.is_err(),
            "RawDerpOutboundTlsOptionsIR should reject unknown fields"
        );
    }

    #[test]
    fn raw_derp_mesh_peer_rejects_unknown_field() {
        let data = json!({
            "server": "10.0.0.2",
            "server_port": 443,
            "bogus_mesh_field": true
        });
        let result = serde_json::from_value::<RawDerpMeshPeerIR>(data);
        assert!(
            result.is_err(),
            "RawDerpMeshPeerIR should reject unknown fields"
        );
    }

    #[test]
    fn raw_derp_mesh_peer_inlines_dial_fields() {
        let data = json!({
            "server": "10.0.0.2",
            "server_port": 443,
            "host": "derp.example.com",
            "tls": { "enabled": true, "server_name": "derp.example.com", "insecure": true, "alpn": ["h2"] },
            "detour": "d2"
        });
        let raw: RawDerpMeshPeerIR = serde_json::from_value(data).unwrap();
        let ir: DerpMeshPeerIR = raw.into();
        assert_eq!(ir.server, "10.0.0.2");
        assert_eq!(ir.server_port, Some(443));
        assert_eq!(ir.host.as_deref(), Some("derp.example.com"));
        let tls = ir.tls.as_ref().unwrap();
        assert!(tls.enabled);
        assert_eq!(tls.insecure, Some(true));
        assert_eq!(ir.dial.detour.as_deref(), Some("d2"));
    }

    #[test]
    fn raw_derp_mesh_peer_from_string_host_port() {
        let raw = RawDerpMeshPeerIR::from("peer.example.com:443".to_string());
        assert_eq!(raw.server, "peer.example.com");
        assert_eq!(raw.server_port, Some(443));
    }

    #[test]
    fn raw_service_verify_client_url_listable_string_or_object() {
        let data = json!({
            "type": "derp",
            "config_path": "derper.key",
            "tls": { "enabled": true, "certificate_path": "c.pem", "key_path": "k.pem" },
            "verify_client_url": [
                "https://a/verify",
                { "url": "http://b/verify", "detour": "d1", "routing_mark": 123 }
            ]
        });
        let ir: ServiceIR = serde_json::from_value(data).unwrap();
        let list = ir.verify_client_url.expect("verify_client_url");
        assert_eq!(list.items.len(), 2);
        let a = list.items[0].clone().into_inner();
        assert_eq!(a.url, "https://a/verify");
        let b = list.items[1].clone().into_inner();
        assert_eq!(b.url, "http://b/verify");
        assert_eq!(b.dial.detour.as_deref(), Some("d1"));
        assert_eq!(b.dial.routing_mark, Some(123));
    }

    #[test]
    fn raw_service_mesh_with_string_or_object() {
        let data = json!({
            "type": "derp",
            "config_path": "derper.key",
            "tls": { "enabled": true, "certificate_path": "c.pem", "key_path": "k.pem" },
            "mesh_with": [
                "peer.example.com:443",
                {
                    "server": "10.0.0.2",
                    "server_port": 443,
                    "tls": { "enabled": true, "server_name": "derp.example.com" },
                    "detour": "d2"
                }
            ]
        });
        let ir: ServiceIR = serde_json::from_value(data).unwrap();
        let mesh = ir.mesh_with.expect("mesh_with");
        assert_eq!(mesh.items.len(), 2);
        let p0 = mesh.items[0].clone().into_inner();
        assert_eq!(p0.server, "peer.example.com");
        assert_eq!(p0.server_port, Some(443));
        let p1 = mesh.items[1].clone().into_inner();
        assert_eq!(p1.server, "10.0.0.2");
        assert_eq!(p1.dial.detour.as_deref(), Some("d2"));
    }

    #[test]
    fn raw_config_root_service_unknown_field_rejected() {
        let data = json!({
            "services": [{
                "type": "resolved",
                "tag": "dns",
                "bogus_field": true
            }]
        });
        let result = serde_json::from_value::<RawConfigRoot>(data);
        assert!(
            result.is_err(),
            "RawConfigRoot should reject unknown service fields via RawServiceIR"
        );
    }

    #[test]
    fn raw_config_root_service_tls_unknown_field_rejected() {
        let data = json!({
            "services": [{
                "type": "derp",
                "config_path": "k",
                "tls": { "enabled": true, "bogus_tls_nested": true }
            }]
        });
        let result = serde_json::from_value::<RawConfigRoot>(data);
        assert!(
            result.is_err(),
            "RawConfigRoot should reject unknown nested TLS fields in services"
        );
    }

    #[test]
    fn raw_config_root_service_stun_unknown_field_rejected() {
        let data = json!({
            "services": [{
                "type": "derp",
                "config_path": "k",
                "tls": { "enabled": true, "certificate_path": "c", "key_path": "k" },
                "stun": { "enabled": true, "bogus_stun_nested": true }
            }]
        });
        let result = serde_json::from_value::<RawConfigRoot>(data);
        assert!(
            result.is_err(),
            "RawConfigRoot should reject unknown nested STUN fields in services"
        );
    }

    // ─────────────────── Raw Inbound tests (WP-30h) ───────────────────

    #[test]
    fn raw_tun_options_ir_rejects_unknown_field() {
        let data = json!({
            "name": "tun0",
            "mtu": 1500,
            "bogus_tun_field": true
        });
        let result = serde_json::from_value::<RawTunOptionsIR>(data);
        assert!(
            result.is_err(),
            "RawTunOptionsIR should reject unknown fields"
        );
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("unknown field") || err.contains("bogus_tun_field"),
            "error should mention unknown field, got: {err}"
        );
    }

    #[test]
    fn raw_inbound_ir_rejects_unknown_field() {
        let data = json!({
            "ty": "socks",
            "listen": "0.0.0.0",
            "port": 1080,
            "bogus_inbound_field": true
        });
        let result = serde_json::from_value::<RawInboundIR>(data);
        assert!(result.is_err(), "RawInboundIR should reject unknown fields");
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("unknown field") || err.contains("bogus_inbound_field"),
            "error should mention unknown field, got: {err}"
        );
    }

    #[test]
    fn raw_shadowsocks_user_ir_rejects_unknown_field() {
        let data = json!({
            "name": "alice",
            "password": "pw",
            "bogus_ss_user_field": true
        });
        let result = serde_json::from_value::<RawShadowsocksUserIR>(data);
        assert!(
            result.is_err(),
            "RawShadowsocksUserIR should reject unknown fields"
        );
    }

    #[test]
    fn raw_vmess_user_ir_rejects_unknown_field() {
        let data = json!({
            "name": "alice",
            "uuid": "aaaa-bbbb",
            "bogus_vmess_user_field": true
        });
        let result = serde_json::from_value::<RawVmessUserIR>(data);
        assert!(
            result.is_err(),
            "RawVmessUserIR should reject unknown fields"
        );
    }

    #[test]
    fn raw_vless_user_ir_rejects_unknown_field() {
        let data = json!({
            "name": "alice",
            "uuid": "aaaa-bbbb",
            "bogus_vless_user_field": true
        });
        let result = serde_json::from_value::<RawVlessUserIR>(data);
        assert!(
            result.is_err(),
            "RawVlessUserIR should reject unknown fields"
        );
    }

    #[test]
    fn raw_trojan_user_ir_rejects_unknown_field() {
        let data = json!({
            "name": "alice",
            "password": "pw",
            "bogus_trojan_user_field": true
        });
        let result = serde_json::from_value::<RawTrojanUserIR>(data);
        assert!(
            result.is_err(),
            "RawTrojanUserIR should reject unknown fields"
        );
    }

    #[test]
    fn raw_shadowtls_user_ir_rejects_unknown_field() {
        let data = json!({
            "password": "pw",
            "bogus_stls_user_field": true
        });
        let result = serde_json::from_value::<RawShadowTlsUserIR>(data);
        assert!(
            result.is_err(),
            "RawShadowTlsUserIR should reject unknown fields"
        );
    }

    #[test]
    fn raw_shadowtls_handshake_ir_rejects_unknown_field() {
        let data = json!({
            "server": "example.com",
            "server_port": 443,
            "bogus_hs_field": true
        });
        let result = serde_json::from_value::<RawShadowTlsHandshakeIR>(data);
        assert!(
            result.is_err(),
            "RawShadowTlsHandshakeIR should reject unknown fields"
        );
    }

    #[test]
    fn raw_anytls_user_ir_rejects_unknown_field() {
        let data = json!({
            "password": "pw",
            "bogus_anytls_user_field": true
        });
        let result = serde_json::from_value::<RawAnyTlsUserIR>(data);
        assert!(
            result.is_err(),
            "RawAnyTlsUserIR should reject unknown fields"
        );
    }

    #[test]
    fn raw_hysteria2_user_ir_rejects_unknown_field() {
        let data = json!({
            "name": "alice",
            "password": "pw",
            "bogus_hy2_user_field": true
        });
        let result = serde_json::from_value::<RawHysteria2UserIR>(data);
        assert!(
            result.is_err(),
            "RawHysteria2UserIR should reject unknown fields"
        );
    }

    #[test]
    fn raw_tuic_user_ir_rejects_unknown_field() {
        let data = json!({
            "uuid": "aaaa",
            "token": "tok",
            "bogus_tuic_user_field": true
        });
        let result = serde_json::from_value::<RawTuicUserIR>(data);
        assert!(
            result.is_err(),
            "RawTuicUserIR should reject unknown fields"
        );
    }

    #[test]
    fn raw_hysteria_user_ir_rejects_unknown_field() {
        let data = json!({
            "name": "alice",
            "auth": "authstr",
            "bogus_hy1_user_field": true
        });
        let result = serde_json::from_value::<RawHysteriaUserIR>(data);
        assert!(
            result.is_err(),
            "RawHysteriaUserIR should reject unknown fields"
        );
    }

    // ── Validated inbound types reject unknown fields via Raw bridge ──

    #[test]
    fn tun_options_ir_rejects_unknown_field_via_raw_bridge() {
        use super::super::TunOptionsIR;
        let data = json!({
            "name": "tun0",
            "bogus_tun_field": "bad"
        });
        let result = serde_json::from_value::<TunOptionsIR>(data);
        assert!(
            result.is_err(),
            "TunOptionsIR should reject unknown fields via Raw bridge"
        );
    }

    #[test]
    fn inbound_ir_rejects_unknown_field_via_raw_bridge() {
        use super::super::InboundIR;
        let data = json!({
            "ty": "socks",
            "listen": "0.0.0.0",
            "port": 1080,
            "bogus_inbound_field": 42
        });
        let result = serde_json::from_value::<InboundIR>(data);
        assert!(
            result.is_err(),
            "InboundIR should reject unknown fields via Raw bridge"
        );
    }

    #[test]
    fn shadowsocks_user_ir_rejects_unknown_field_via_raw_bridge() {
        use super::super::ShadowsocksUserIR;
        let data = json!({
            "name": "alice",
            "password": "pw",
            "bogus_field": true
        });
        let result = serde_json::from_value::<ShadowsocksUserIR>(data);
        assert!(
            result.is_err(),
            "ShadowsocksUserIR should reject unknown fields via Raw bridge"
        );
    }

    #[test]
    fn vmess_user_ir_rejects_unknown_field_via_raw_bridge() {
        use super::super::VmessUserIR;
        let data = json!({
            "name": "alice",
            "uuid": "aaaa",
            "bogus_field": true
        });
        let result = serde_json::from_value::<VmessUserIR>(data);
        assert!(
            result.is_err(),
            "VmessUserIR should reject unknown fields via Raw bridge"
        );
    }

    #[test]
    fn trojan_user_ir_rejects_unknown_field_via_raw_bridge() {
        use super::super::TrojanUserIR;
        let data = json!({
            "name": "alice",
            "password": "pw",
            "bogus_field": true
        });
        let result = serde_json::from_value::<TrojanUserIR>(data);
        assert!(
            result.is_err(),
            "TrojanUserIR should reject unknown fields via Raw bridge"
        );
    }

    #[test]
    fn hysteria2_user_ir_rejects_unknown_field_via_raw_bridge() {
        use super::super::Hysteria2UserIR;
        let data = json!({
            "name": "alice",
            "password": "pw",
            "bogus_field": true
        });
        let result = serde_json::from_value::<Hysteria2UserIR>(data);
        assert!(
            result.is_err(),
            "Hysteria2UserIR should reject unknown fields via Raw bridge"
        );
    }

    // ── Valid roundtrip tests ──

    #[test]
    fn tun_options_ir_valid_roundtrip() {
        use super::super::TunOptionsIR;
        let data = json!({
            "name": "tun0",
            "mtu": 1500,
            "auto_route": true,
            "strict_route": true,
            "inet4_address": "172.19.0.1/30",
            "stack": "gvisor"
        });
        let ir: TunOptionsIR = serde_json::from_value(data).unwrap();
        assert_eq!(ir.name.as_deref(), Some("tun0"));
        assert_eq!(ir.mtu, Some(1500));
        assert_eq!(ir.auto_route, Some(true));
        let json = serde_json::to_value(&ir).unwrap();
        let ir2: TunOptionsIR = serde_json::from_value(json).unwrap();
        assert_eq!(ir, ir2);
    }

    #[test]
    fn inbound_ir_basic_roundtrip_via_raw() {
        use super::super::InboundIR;
        let data = json!({
            "ty": "http",
            "listen": "127.0.0.1",
            "port": 8080,
            "sniff": true,
            "tag": "http-in"
        });
        let ir: InboundIR = serde_json::from_value(data).unwrap();
        assert_eq!(ir.ty, super::super::InboundType::Http);
        assert_eq!(ir.listen, "127.0.0.1");
        assert_eq!(ir.port, 8080);
        assert!(ir.sniff);
        // allow_private_network defaults to true via Raw bridge
        assert!(ir.allow_private_network);
        let json = serde_json::to_value(&ir).unwrap();
        let ir2: InboundIR = serde_json::from_value(json).unwrap();
        assert_eq!(ir.ty, ir2.ty);
        assert_eq!(ir.listen, ir2.listen);
        assert_eq!(ir.tag, ir2.tag);
    }

    #[test]
    fn inbound_ir_shadowtls_roundtrip_via_raw() {
        use super::super::InboundIR;
        let data = json!({
            "ty": "shadowtls",
            "listen": "0.0.0.0",
            "port": 443,
            "version": 3,
            "users_shadowtls": [
                {"name": "user1", "password": "stlspass"}
            ],
            "shadowtls_handshake": {
                "server": "www.example.com",
                "server_port": 443
            },
            "shadowtls_handshake_for_server_name": {
                "alt.example.com": {
                    "server": "alt.example.com",
                    "server_port": 443
                }
            },
            "shadowtls_strict_mode": true
        });
        let ir: InboundIR = serde_json::from_value(data).unwrap();
        assert_eq!(ir.version, Some(3));
        let users = ir.users_shadowtls.as_ref().unwrap();
        assert_eq!(users[0].name, "user1");
        let hs = ir.shadowtls_handshake.as_ref().unwrap();
        assert_eq!(hs.server, "www.example.com");
        assert_eq!(hs.server_port, 443);
        let hs_map = ir.shadowtls_handshake_for_server_name.as_ref().unwrap();
        assert!(hs_map.contains_key("alt.example.com"));
        let json = serde_json::to_value(&ir).unwrap();
        let ir2: InboundIR = serde_json::from_value(json).unwrap();
        assert_eq!(ir2.version, ir.version);
    }

    #[test]
    fn inbound_ir_tun_roundtrip_via_raw() {
        use super::super::InboundIR;
        let data = json!({
            "ty": "tun",
            "listen": "0.0.0.0",
            "port": 0,
            "tun": {
                "name": "utun5",
                "mtu": 9000,
                "auto_route": true,
                "stack": "gvisor"
            }
        });
        let ir: InboundIR = serde_json::from_value(data).unwrap();
        let tun = ir.tun.as_ref().unwrap();
        assert_eq!(tun.name.as_deref(), Some("utun5"));
        assert_eq!(tun.mtu, Some(9000));
        let json = serde_json::to_value(&ir).unwrap();
        let ir2: InboundIR = serde_json::from_value(json).unwrap();
        assert_eq!(ir2.tun.as_ref().unwrap().name, tun.name);
    }

    #[test]
    fn inbound_ir_multi_user_shadowsocks_roundtrip_via_raw() {
        use super::super::InboundIR;
        let data = json!({
            "ty": "shadowsocks",
            "listen": "0.0.0.0",
            "port": 8388,
            "method": "aes-256-gcm",
            "users_shadowsocks": [
                {"name": "alice", "password": "pw1"},
                {"name": "bob", "password": "pw2"}
            ]
        });
        let ir: InboundIR = serde_json::from_value(data).unwrap();
        let users = ir.users_shadowsocks.as_ref().unwrap();
        assert_eq!(users.len(), 2);
        assert_eq!(users[0].name, "alice");
        let json = serde_json::to_value(&ir).unwrap();
        let ir2: InboundIR = serde_json::from_value(json).unwrap();
        assert_eq!(ir2.users_shadowsocks.as_ref().unwrap().len(), 2);
    }

    #[test]
    fn inbound_type_serde_unchanged_after_inbound_raw() {
        use super::super::InboundType;
        let parsed: InboundType = serde_json::from_str("\"shadowtls\"").unwrap();
        assert_eq!(parsed, InboundType::Shadowtls);
        assert_eq!(parsed.ty_str(), "shadowtls");
    }

    #[test]
    fn config_ir_accepts_valid_inbound_subtree_via_raw_bridge() {
        let data = json!({
            "inbounds": [
                {
                    "ty": "socks",
                    "listen": "0.0.0.0",
                    "port": 1080,
                    "udp": true
                },
                {
                    "ty": "http",
                    "listen": "127.0.0.1",
                    "port": 8080
                }
            ]
        });
        let ir = serde_json::from_value::<ConfigIR>(data).unwrap();
        assert_eq!(ir.inbounds.len(), 2);
        assert_eq!(ir.inbounds[0].ty, super::super::InboundType::Socks);
        assert_eq!(ir.inbounds[1].ty, super::super::InboundType::Http);
    }

    #[test]
    fn config_ir_rejects_unknown_field_inside_inbound_subtree() {
        let data = json!({
            "inbounds": [
                {
                    "ty": "socks",
                    "listen": "0.0.0.0",
                    "port": 1080,
                    "unknown_inbound_field": true
                }
            ]
        });
        let result = serde_json::from_value::<ConfigIR>(data);
        assert!(
            result.is_err(),
            "ConfigIR should reject unknown fields inside inbound via Raw bridge"
        );
    }

    #[test]
    fn config_ir_rejects_unknown_field_in_nested_tun() {
        let data = json!({
            "inbounds": [{
                "ty": "tun",
                "listen": "0.0.0.0",
                "port": 0,
                "tun": {
                    "name": "utun0",
                    "bogus_nested_tun_field": true
                }
            }]
        });
        let result = serde_json::from_value::<ConfigIR>(data);
        assert!(
            result.is_err(),
            "ConfigIR should reject unknown fields in nested tun via inbound Raw bridge"
        );
    }

    #[test]
    fn config_ir_rejects_unknown_field_in_inbound_user() {
        let data = json!({
            "inbounds": [{
                "ty": "shadowsocks",
                "listen": "0.0.0.0",
                "port": 8388,
                "users_shadowsocks": [{
                    "name": "alice",
                    "password": "pw",
                    "bogus_user_field": true
                }]
            }]
        });
        let result = serde_json::from_value::<ConfigIR>(data);
        assert!(
            result.is_err(),
            "ConfigIR should reject unknown fields in inbound user types via Raw bridge"
        );
    }

    // ─────────────────── Outbound nested Raw boundary tests (WP-30i) ───────────────────

    // ── Raw types reject unknown fields ──

    #[test]
    fn raw_header_entry_rejects_unknown_field() {
        let data = json!({"key": "Host", "value": "example.com", "bogus": true});
        let result = serde_json::from_value::<RawHeaderEntry>(data);
        assert!(
            result.is_err(),
            "RawHeaderEntry should reject unknown field"
        );
    }

    #[test]
    fn raw_credentials_rejects_unknown_field() {
        let data = json!({"username": "user", "password": "pass", "extra": "nope"});
        let result = serde_json::from_value::<RawCredentials>(data);
        assert!(
            result.is_err(),
            "RawCredentials should reject unknown field"
        );
    }

    #[test]
    fn raw_brutal_ir_rejects_unknown_field() {
        let data = json!({"up": 100, "down": 200, "mystery": 42});
        let result = serde_json::from_value::<RawBrutalIR>(data);
        assert!(result.is_err(), "RawBrutalIR should reject unknown field");
    }

    #[test]
    fn raw_multiplex_options_ir_rejects_unknown_field() {
        let data = json!({"enabled": true, "protocol": "yamux", "fake_knob": 99});
        let result = serde_json::from_value::<RawMultiplexOptionsIR>(data);
        assert!(
            result.is_err(),
            "RawMultiplexOptionsIR should reject unknown field"
        );
    }

    #[test]
    fn raw_outbound_ir_rejects_unknown_field() {
        let data = json!({"ty": "direct", "bogus_outbound_field": true});
        let result = serde_json::from_value::<RawOutboundIR>(data);
        assert!(result.is_err(), "RawOutboundIR should reject unknown field");
    }

    // ── Validated types reject unknown fields via Raw bridge ──

    #[test]
    fn header_entry_rejects_unknown_field_via_raw_bridge() {
        let data = json!({"key": "Host", "value": "example.com", "extra": "bad"});
        let result = serde_json::from_value::<super::HeaderEntry>(data);
        assert!(
            result.is_err(),
            "HeaderEntry should reject unknown field via Raw bridge"
        );
    }

    #[test]
    fn credentials_rejects_unknown_field_via_raw_bridge() {
        let data = json!({"username": "u", "password": "p", "token": "bad"});
        let result = serde_json::from_value::<super::Credentials>(data);
        assert!(
            result.is_err(),
            "Credentials should reject unknown field via Raw bridge"
        );
    }

    #[test]
    fn brutal_ir_rejects_unknown_field_via_raw_bridge() {
        let data = json!({"up": 10, "down": 20, "lateral": 30});
        let result = serde_json::from_value::<super::BrutalIR>(data);
        assert!(
            result.is_err(),
            "BrutalIR should reject unknown field via Raw bridge"
        );
    }

    #[test]
    fn multiplex_options_ir_rejects_unknown_field_via_raw_bridge() {
        let data = json!({"enabled": true, "protocol": "yamux", "invented": true});
        let result = serde_json::from_value::<super::MultiplexOptionsIR>(data);
        assert!(
            result.is_err(),
            "MultiplexOptionsIR should reject unknown field via Raw bridge"
        );
    }

    #[test]
    fn outbound_ir_rejects_unknown_field_via_raw_bridge() {
        let data = json!({"ty": "direct", "phantom_field": "oops"});
        let result = serde_json::from_value::<super::OutboundIR>(data);
        assert!(
            result.is_err(),
            "OutboundIR should reject unknown field via Raw bridge"
        );
    }

    // ── Validated types roundtrip (serialize → deserialize) still works ──

    #[test]
    fn header_entry_roundtrip_via_raw_bridge() {
        let entry = super::HeaderEntry {
            key: "Authorization".to_string(),
            value: "Bearer tok".to_string(),
        };
        let json = serde_json::to_value(&entry).unwrap();
        let back: super::HeaderEntry = serde_json::from_value(json).unwrap();
        assert_eq!(back.key, "Authorization");
        assert_eq!(back.value, "Bearer tok");
    }

    #[test]
    fn credentials_roundtrip_via_raw_bridge() {
        let cred = super::Credentials {
            username: Some("user".to_string()),
            password: Some("pass".to_string()),
            username_env: Some("USER_ENV".to_string()),
            password_env: None,
        };
        let json = serde_json::to_value(&cred).unwrap();
        let back: super::Credentials = serde_json::from_value(json).unwrap();
        assert_eq!(back.username.as_deref(), Some("user"));
        assert_eq!(back.username_env.as_deref(), Some("USER_ENV"));
        assert!(back.password_env.is_none());
    }

    #[test]
    fn multiplex_options_ir_roundtrip_via_raw_bridge() {
        let mux = super::MultiplexOptionsIR {
            enabled: true,
            protocol: Some("yamux".to_string()),
            max_connections: Some(8),
            brutal: Some(super::BrutalIR { up: 100, down: 200 }),
            ..Default::default()
        };
        let json = serde_json::to_value(&mux).unwrap();
        let back: super::MultiplexOptionsIR = serde_json::from_value(json).unwrap();
        assert!(back.enabled);
        assert_eq!(back.protocol.as_deref(), Some("yamux"));
        assert_eq!(back.max_connections, Some(8));
        let b = back.brutal.unwrap();
        assert_eq!(b.up, 100);
        assert_eq!(b.down, 200);
    }

    #[test]
    fn brutal_ir_roundtrip_via_raw_bridge() {
        let brutal = super::BrutalIR { up: 50, down: 100 };
        let json = serde_json::to_value(&brutal).unwrap();
        let back: super::BrutalIR = serde_json::from_value(json).unwrap();
        assert_eq!(back.up, 50);
        assert_eq!(back.down, 100);
    }

    // ── OutboundIR roundtrip scenarios ──

    #[test]
    fn outbound_ir_basic_roundtrip_via_raw_bridge() {
        let ir = super::OutboundIR {
            ty: super::OutboundType::Direct,
            name: Some("direct-out".to_string()),
            ..Default::default()
        };
        let json = serde_json::to_value(&ir).unwrap();
        let back: super::OutboundIR = serde_json::from_value(json).unwrap();
        assert_eq!(back.ty, super::OutboundType::Direct);
        assert_eq!(back.name.as_deref(), Some("direct-out"));
    }

    #[test]
    fn outbound_ir_transport_tls_roundtrip_via_raw_bridge() {
        let ir = super::OutboundIR {
            ty: super::OutboundType::Vmess,
            server: Some("vmess.example.com".to_string()),
            port: Some(443),
            transport: Some(vec!["tls".into(), "ws".into()]),
            ws_path: Some("/chat".to_string()),
            tls_sni: Some("sni.example.com".to_string()),
            tls_alpn: Some(vec!["h2".into()]),
            utls_fingerprint: Some("chrome".to_string()),
            ..Default::default()
        };
        let json = serde_json::to_value(&ir).unwrap();
        let back: super::OutboundIR = serde_json::from_value(json).unwrap();
        assert_eq!(back.ty, super::OutboundType::Vmess);
        assert_eq!(back.ws_path.as_deref(), Some("/chat"));
        assert_eq!(back.tls_sni.as_deref(), Some("sni.example.com"));
        assert_eq!(back.utls_fingerprint.as_deref(), Some("chrome"));
    }

    #[test]
    fn outbound_ir_dns_roundtrip_via_raw_bridge() {
        let ir = super::OutboundIR {
            ty: super::OutboundType::Dns,
            dns_transport: Some("udp".to_string()),
            dns_timeout_ms: Some(5000),
            ..Default::default()
        };
        let json = serde_json::to_value(&ir).unwrap();
        let back: super::OutboundIR = serde_json::from_value(json).unwrap();
        assert_eq!(back.ty, super::OutboundType::Dns);
        assert_eq!(back.dns_transport.as_deref(), Some("udp"));
        assert_eq!(back.dns_timeout_ms, Some(5000));
    }

    #[test]
    fn outbound_ir_wireguard_roundtrip_via_raw_bridge() {
        let ir = super::OutboundIR {
            ty: super::OutboundType::Wireguard,
            name: Some("wg-out".to_string()),
            wireguard_interface: Some("wg0".to_string()),
            wireguard_local_address: vec!["10.0.0.2/32".to_string()],
            wireguard_persistent_keepalive: Some(25),
            ..Default::default()
        };
        let json = serde_json::to_value(&ir).unwrap();
        let back: super::OutboundIR = serde_json::from_value(json).unwrap();
        assert_eq!(back.ty, super::OutboundType::Wireguard);
        assert_eq!(back.wireguard_interface.as_deref(), Some("wg0"));
        assert_eq!(back.wireguard_persistent_keepalive, Some(25));
    }

    #[test]
    fn outbound_ir_ssh_roundtrip_via_raw_bridge() {
        let ir = super::OutboundIR {
            ty: super::OutboundType::Ssh,
            server: Some("ssh.example.com".to_string()),
            port: Some(22),
            credentials: Some(super::Credentials {
                username: Some("user".to_string()),
                password: Some("pass".to_string()),
                ..Default::default()
            }),
            ssh_connection_pool_size: Some(4),
            ssh_compression: Some(true),
            ..Default::default()
        };
        let json = serde_json::to_value(&ir).unwrap();
        let back: super::OutboundIR = serde_json::from_value(json).unwrap();
        assert_eq!(back.ty, super::OutboundType::Ssh);
        assert_eq!(
            back.credentials.as_ref().unwrap().username.as_deref(),
            Some("user")
        );
        assert_eq!(back.ssh_connection_pool_size, Some(4));
    }

    #[test]
    fn outbound_ir_tuic_roundtrip_via_raw_bridge() {
        let ir = super::OutboundIR {
            ty: super::OutboundType::Tuic,
            server: Some("tuic.example.com".to_string()),
            port: Some(443),
            uuid: Some("12345678-1234-1234-1234-123456789abc".to_string()),
            token: Some("secret".to_string()),
            congestion_control: Some("bbr".to_string()),
            udp_relay_mode: Some("native".to_string()),
            zero_rtt_handshake: Some(true),
            ..Default::default()
        };
        let json = serde_json::to_value(&ir).unwrap();
        let back: super::OutboundIR = serde_json::from_value(json).unwrap();
        assert_eq!(back.ty, super::OutboundType::Tuic);
        assert_eq!(back.congestion_control.as_deref(), Some("bbr"));
        assert_eq!(back.zero_rtt_handshake, Some(true));
    }

    #[test]
    fn outbound_ir_hysteria2_roundtrip_via_raw_bridge() {
        let ir = super::OutboundIR {
            ty: super::OutboundType::Hysteria2,
            server: Some("hy2.example.com".to_string()),
            port: Some(443),
            up_mbps: Some(100),
            down_mbps: Some(200),
            obfs: Some("salamander".to_string()),
            brutal_up_mbps: Some(50),
            ..Default::default()
        };
        let json = serde_json::to_value(&ir).unwrap();
        let back: super::OutboundIR = serde_json::from_value(json).unwrap();
        assert_eq!(back.ty, super::OutboundType::Hysteria2);
        assert_eq!(back.up_mbps, Some(100));
        assert_eq!(back.obfs.as_deref(), Some("salamander"));
    }

    #[test]
    fn outbound_ir_anytls_roundtrip_via_raw_bridge() {
        let ir = super::OutboundIR {
            ty: super::OutboundType::Anytls,
            server: Some("anytls.example.com".to_string()),
            port: Some(443),
            password: Some("pw".to_string()),
            anytls_padding: Some(vec!["0-100".to_string()]),
            ..Default::default()
        };
        let json = serde_json::to_value(&ir).unwrap();
        let back: super::OutboundIR = serde_json::from_value(json).unwrap();
        assert_eq!(back.ty, super::OutboundType::Anytls);
        assert_eq!(back.anytls_padding.as_ref().unwrap().len(), 1);
    }

    #[test]
    fn outbound_ir_hysteria_v1_roundtrip_via_raw_bridge() {
        let ir = super::OutboundIR {
            ty: super::OutboundType::Hysteria,
            server: Some("hy1.example.com".to_string()),
            port: Some(443),
            hysteria_protocol: Some("udp".to_string()),
            hysteria_auth: Some("auth-str".to_string()),
            ..Default::default()
        };
        let json = serde_json::to_value(&ir).unwrap();
        let back: super::OutboundIR = serde_json::from_value(json).unwrap();
        assert_eq!(back.ty, super::OutboundType::Hysteria);
        assert_eq!(back.hysteria_protocol.as_deref(), Some("udp"));
    }

    // ── OutboundType serde / ty_str() stability ──

    #[test]
    fn outbound_type_serde_stable_after_raw_bridge() {
        let variants = [
            ("direct", super::OutboundType::Direct),
            ("http", super::OutboundType::Http),
            ("socks", super::OutboundType::Socks),
            ("block", super::OutboundType::Block),
            ("selector", super::OutboundType::Selector),
            ("shadowsocks", super::OutboundType::Shadowsocks),
            ("shadowtls", super::OutboundType::Shadowtls),
            ("urltest", super::OutboundType::UrlTest),
            ("hysteria2", super::OutboundType::Hysteria2),
            ("tuic", super::OutboundType::Tuic),
            ("vless", super::OutboundType::Vless),
            ("vmess", super::OutboundType::Vmess),
            ("trojan", super::OutboundType::Trojan),
            ("ssh", super::OutboundType::Ssh),
            ("dns", super::OutboundType::Dns),
            ("tor", super::OutboundType::Tor),
            ("anytls", super::OutboundType::Anytls),
            ("hysteria", super::OutboundType::Hysteria),
            ("wireguard", super::OutboundType::Wireguard),
            ("tailscale", super::OutboundType::Tailscale),
            ("shadowsocksr", super::OutboundType::ShadowsocksR),
        ];
        for (expected_str, variant) in &variants {
            assert_eq!(variant.ty_str(), *expected_str);
            let json_val = serde_json::to_value(variant).unwrap();
            assert_eq!(json_val.as_str().unwrap(), *expected_str);
            let back: super::OutboundType = serde_json::from_value(json_val).unwrap();
            assert_eq!(&back, variant);
        }
    }

    // ── validate_reality() stability ──

    #[test]
    fn validate_reality_success_after_raw_bridge() {
        let outbound = super::OutboundIR {
            ty: super::OutboundType::Vless,
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
    fn validate_reality_failure_after_raw_bridge() {
        let outbound = super::OutboundIR {
            ty: super::OutboundType::Vless,
            name: Some("test-vless".to_string()),
            reality_enabled: Some(true),
            reality_public_key: None,
            reality_server_name: Some("www.apple.com".to_string()),
            ..Default::default()
        };
        let err = outbound.validate_reality().unwrap_err();
        assert!(err.contains("public_key is required"));
    }

    // ── ConfigIR root with outbound subtree ──

    #[test]
    fn config_ir_parses_valid_outbound_subtree() {
        let data = json!({
            "outbounds": [
                {
                    "ty": "direct",
                    "name": "direct-out"
                },
                {
                    "ty": "vmess",
                    "server": "example.com",
                    "port": 443,
                    "uuid": "abcdef00-1234-5678-9abc-def012345678",
                    "multiplex": {
                        "enabled": true,
                        "protocol": "yamux"
                    }
                }
            ]
        });
        let config: ConfigIR = serde_json::from_value(data).unwrap();
        assert_eq!(config.outbounds.len(), 2);
        assert_eq!(config.outbounds[0].ty, super::OutboundType::Direct);
        assert_eq!(config.outbounds[1].ty, super::OutboundType::Vmess);
        assert!(config.outbounds[1].multiplex.as_ref().unwrap().enabled);
    }

    #[test]
    fn config_ir_rejects_unknown_outbound_nested_field() {
        let data = json!({
            "outbounds": [
                {
                    "ty": "direct",
                    "name": "direct-out",
                    "not_a_real_field": true
                }
            ]
        });
        let result = serde_json::from_value::<ConfigIR>(data);
        assert!(
            result.is_err(),
            "ConfigIR should reject unknown fields in outbound subtree via Raw bridge"
        );
    }

    #[test]
    fn config_ir_rejects_unknown_field_in_outbound_multiplex() {
        let data = json!({
            "outbounds": [
                {
                    "ty": "vmess",
                    "server": "example.com",
                    "port": 443,
                    "multiplex": {
                        "enabled": true,
                        "fake_knob": 99
                    }
                }
            ]
        });
        let result = serde_json::from_value::<ConfigIR>(data);
        assert!(
            result.is_err(),
            "ConfigIR should reject unknown fields in outbound multiplex via Raw bridge"
        );
    }

    #[test]
    fn config_ir_rejects_unknown_field_in_outbound_credentials() {
        let data = json!({
            "outbounds": [
                {
                    "ty": "socks",
                    "server": "example.com",
                    "port": 1080,
                    "credentials": {
                        "username": "user",
                        "password": "pass",
                        "extra_field": "bad"
                    }
                }
            ]
        });
        let result = serde_json::from_value::<ConfigIR>(data);
        assert!(
            result.is_err(),
            "ConfigIR should reject unknown fields in outbound credentials via Raw bridge"
        );
    }

    // ─────────────────── Masquerade Raw boundary tests (WP-30j) ───────────────────

    #[test]
    fn raw_masquerade_ir_rejects_unknown_fields() {
        let data = json!({
            "type": "proxy",
            "proxy": {"url": "https://example.com"},
            "bogus": true
        });
        let result = serde_json::from_value::<RawMasqueradeIR>(data);
        assert!(
            result.is_err(),
            "RawMasqueradeIR should reject unknown fields"
        );
    }

    #[test]
    fn raw_masquerade_file_ir_rejects_unknown_fields() {
        let data = json!({
            "directory": "/var/www",
            "bogus": true
        });
        let result = serde_json::from_value::<RawMasqueradeFileIR>(data);
        assert!(
            result.is_err(),
            "RawMasqueradeFileIR should reject unknown fields"
        );
    }

    #[test]
    fn raw_masquerade_proxy_ir_rejects_unknown_fields() {
        let data = json!({
            "url": "https://example.com",
            "rewrite_host": true,
            "bogus": true
        });
        let result = serde_json::from_value::<RawMasqueradeProxyIR>(data);
        assert!(
            result.is_err(),
            "RawMasqueradeProxyIR should reject unknown fields"
        );
    }

    #[test]
    fn raw_masquerade_string_ir_rejects_unknown_fields() {
        let data = json!({
            "content": "<html>hello</html>",
            "status_code": 200,
            "bogus": true
        });
        let result = serde_json::from_value::<RawMasqueradeStringIR>(data);
        assert!(
            result.is_err(),
            "RawMasqueradeStringIR should reject unknown fields"
        );
    }

    #[test]
    fn masquerade_ir_bridge_rejects_unknown_fields() {
        let data = json!({
            "type": "proxy",
            "proxy": {"url": "https://example.com"},
            "bogus": true
        });
        let result = serde_json::from_value::<MasqueradeIR>(data);
        assert!(
            result.is_err(),
            "MasqueradeIR should reject unknown fields via Raw bridge"
        );
    }

    #[test]
    fn masquerade_file_ir_bridge_rejects_unknown_fields() {
        let data = json!({
            "directory": "/var/www",
            "bogus": true
        });
        let result = serde_json::from_value::<MasqueradeFileIR>(data);
        assert!(
            result.is_err(),
            "MasqueradeFileIR should reject unknown fields via Raw bridge"
        );
    }

    #[test]
    fn masquerade_proxy_ir_bridge_rejects_unknown_fields() {
        let data = json!({
            "url": "https://example.com",
            "bogus": true
        });
        let result = serde_json::from_value::<MasqueradeProxyIR>(data);
        assert!(
            result.is_err(),
            "MasqueradeProxyIR should reject unknown fields via Raw bridge"
        );
    }

    #[test]
    fn masquerade_string_ir_bridge_rejects_unknown_fields() {
        let data = json!({
            "content": "<html>hello</html>",
            "bogus": true
        });
        let result = serde_json::from_value::<MasqueradeStringIR>(data);
        assert!(
            result.is_err(),
            "MasqueradeStringIR should reject unknown fields via Raw bridge"
        );
    }

    #[test]
    fn config_ir_rejects_hysteria2_masquerade_unknown_nested() {
        let data = json!({
            "inbounds": [{
                "ty": "hysteria2",
                "listen": "0.0.0.0",
                "port": 443,
                "users_hysteria2": [{"name": "u1", "password": "pw"}],
                "masquerade": {
                    "type": "proxy",
                    "proxy": {"url": "https://example.com", "bogus_field": true}
                }
            }],
            "outbounds": []
        });
        let result = serde_json::from_value::<ConfigIR>(data);
        assert!(
            result.is_err(),
            "ConfigIR should reject unknown fields in masquerade proxy via Raw bridge"
        );
    }

    #[test]
    fn config_ir_rejects_masquerade_unknown_top_field() {
        let data = json!({
            "inbounds": [{
                "ty": "hysteria2",
                "listen": "0.0.0.0",
                "port": 443,
                "users_hysteria2": [{"name": "u1", "password": "pw"}],
                "masquerade": {
                    "type": "file",
                    "file": {"directory": "/var/www"},
                    "unknown_masq_field": 42
                }
            }],
            "outbounds": []
        });
        let result = serde_json::from_value::<ConfigIR>(data);
        assert!(
            result.is_err(),
            "ConfigIR should reject unknown fields in masquerade via Raw bridge"
        );
    }
}
