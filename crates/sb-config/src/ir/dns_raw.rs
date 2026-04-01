//! DNS Raw boundary owner.
//!
//! This module owns the DNS subtree's strict Raw input boundary:
//! - [`RawDnsServerIR`]
//! - [`RawDnsRuleIR`]
//! - [`RawDnsHostIR`]
//! - [`RawDnsIR`]
//!
//! It also owns the Raw -> Validated bridge via `From<RawDns*> for Dns*`.
//!
//! ## WP-30ar
//!
//! The DNS Raw subtree used to live inside the 5000+ line `ir/raw.rs` mega-file.
//! WP-30ar moves the owner here so the DNS phase boundary is explicit:
//!
//! ```text
//! dns_raw.rs  -> strict Raw owner + Raw -> Validated bridge
//! dns.rs      -> validated DNS owner + Deserialize delegates
//! planned.rs  -> DNS namespace/reference facts only
//! normalize.rs/minimize.rs -> not DNS planning owners
//! ```
//!
//! `ir/raw.rs` remains as the broader Raw boundary entry point for `RawConfigRoot`
//! and public compat/re-export paths.

use serde::Deserialize;

use super::{DnsHostIR, DnsIR, DnsRuleIR, DnsServerIR};

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::ConfigIR;
    use serde_json::json;
    use std::fs;

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

    #[test]
    fn raw_dns_bridge_preserves_valid_subtree_behavior() {
        let raw: RawDnsIR = serde_json::from_value(json!({
            "servers": [
                {
                    "tag": "google",
                    "address": "udp://8.8.8.8",
                    "detour": "direct",
                    "address_resolver": "bootstrap",
                    "service": "resolved"
                }
            ],
            "rules": [
                {
                    "domain_suffix": [".example.com"],
                    "server": "google",
                    "rewrite_ttl": 60
                }
            ],
            "default": "google",
            "final": "google",
            "hosts": [
                {
                    "domain": "localhost",
                    "ips": ["127.0.0.1", "::1"]
                }
            ]
        }))
        .unwrap();

        let dns: DnsIR = raw.into();
        assert_eq!(dns.servers.len(), 1);
        assert_eq!(dns.rules.len(), 1);
        assert_eq!(dns.hosts.len(), 1);
        assert_eq!(dns.servers[0].detour.as_deref(), Some("direct"));
        assert_eq!(
            dns.servers[0].address_resolver.as_deref(),
            Some("bootstrap")
        );
        assert_eq!(dns.servers[0].service.as_deref(), Some("resolved"));
        assert_eq!(dns.rules[0].server.as_deref(), Some("google"));
        assert_eq!(dns.default.as_deref(), Some("google"));
        assert_eq!(dns.final_server.as_deref(), Some("google"));
    }

    #[test]
    fn config_ir_parses_dns_subtree_through_dns_raw_bridge() {
        let data = json!({
            "dns": {
                "servers": [
                    {
                        "tag": "dns-1",
                        "address": "udp://1.1.1.1",
                        "detour": "proxy"
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
        assert_eq!(dns.servers[0].detour.as_deref(), Some("proxy"));
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
    fn wp30ar_pin_dns_raw_owner_lives_in_dns_raw_module() {
        let source = fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/ir/dns_raw.rs"))
            .expect("dns_raw source should be readable");
        assert!(source.contains("pub struct RawDnsServerIR"));
        assert!(source.contains("pub struct RawDnsRuleIR"));
        assert!(source.contains("pub struct RawDnsHostIR"));
        assert!(source.contains("pub struct RawDnsIR"));
        assert!(source.contains("impl From<RawDnsServerIR> for DnsServerIR"));
        assert!(source.contains("impl From<RawDnsIR> for DnsIR"));
    }

    #[test]
    fn wp30ar_pin_raw_module_is_dns_raw_compat_shell() {
        let source = fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/ir/raw.rs"))
            .expect("raw.rs source should be readable");
        assert!(source.contains(
            "pub use super::dns_raw::{RawDnsHostIR, RawDnsIR, RawDnsRuleIR, RawDnsServerIR};"
        ));
        assert!(
            !source.contains("pub struct RawDnsServerIR {"),
            "raw.rs should no longer own RawDnsServerIR directly"
        );
        assert!(
            !source.contains("impl From<RawDnsIR> for DnsIR {"),
            "raw.rs should no longer own the DNS Raw -> Validated bridge"
        );
    }
}
