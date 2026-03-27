//! DNS validated IR types and Raw bridges.
//!
//! ## Current status (WP-30d)
//!
//! The DNS subtree now has a nested Raw boundary:
//! [`super::raw::RawDnsServerIR`], [`super::raw::RawDnsRuleIR`],
//! [`super::raw::RawDnsHostIR`], and [`super::raw::RawDnsIR`] all carry
//! `#[serde(deny_unknown_fields)]`.
//!
//! `DnsServerIR`, `DnsRuleIR`, `DnsHostIR`, and `DnsIR` keep their existing
//! public fields and `Serialize` behavior, but no longer derive
//! `Deserialize` directly. Deserialization now flows through the Raw bridge,
//! so unknown DNS nested fields are strictly rejected.
//!
//! `RouteIR`, `InboundIR`, `OutboundIR`, `EndpointIR`, and `ServiceIR` still
//! have not entered nested Raw. `planned.rs` and `normalize.rs` also remain
//! Phase-3 skeletons.

use serde::{Deserialize, Serialize};

use super::raw::{RawDnsHostIR, RawDnsIR, RawDnsRuleIR, RawDnsServerIR};

/// DNS server entry (IR)
#[derive(Debug, Clone, Serialize, PartialEq, Default)]
pub struct DnsServerIR {
    /// Upstream tag (unique)
    pub tag: String,
    /// Address scheme for this upstream.
    ///
    /// Supported values (by scheme prefix or literal):
    /// - `system` - use system resolver
    /// - `local` / `local://` - local transport with system fallback
    /// - `udp://host[:port]` - plain UDP DNS (default port 53)
    /// - `https://...` / `http://...` - DoH (DNS over HTTPS; requires `dns_doh`)
    /// - `dot://host[:port]` / `tls://host[:port]` - DoT (DNS over TLS; requires `dns_dot`, default port 853)
    /// - `doq://host[:port][@sni]` / `quic://host[:port][@sni]` - DoQ (DNS over QUIC; requires `dns_doq`, default port 853)
    /// - `doh3://host[:port][/path]` / `h3://host[:port][/path]` - DoH3 (requires `dns_doh3`, default port 443, path defaults to `/dns-query`)
    /// - `dhcp` / `dhcp://iface` / `dhcp:///path` / `dhcp://?resolv=/path` - DHCP DNS (requires `dns_dhcp`)
    /// - `tailscale` / `tailscale://host:port` / `tailscale://?servers=a,b` - Tailscale DNS (requires `dns_tailscale`)
    /// - `resolved` / `resolved:///path` / `resolved://?resolv=/path` - systemd-resolved (Linux only, requires `dns_resolved`)
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
    /// Resolved transport: service tag (Go: required; Rust: defaults to "resolved" when missing).
    #[serde(default)]
    pub service: Option<String>,
    /// Resolved transport: accept default resolvers (Go zero-value default: false).
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

impl<'de> Deserialize<'de> for DnsServerIR {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        RawDnsServerIR::deserialize(deserializer).map(Into::into)
    }
}

/// DNS routing rule (IR)
#[derive(Debug, Clone, Serialize, PartialEq, Eq, Default)]
pub struct DnsRuleIR {
    /// Domain suffix list for this rule
    #[serde(default)]
    pub domain_suffix: Vec<String>,
    /// Exact domain list
    #[serde(default)]
    pub domain: Vec<String>,
    /// Keyword list
    #[serde(default)]
    pub keyword: Vec<String>,
    /// Target upstream tag
    #[serde(default)]
    pub server: Option<String>,
    /// Optional rule priority (lower = higher priority)
    #[serde(default)]
    pub priority: Option<u32>,

    // Additional Match Fields
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

    // New Matching Fields for Parity
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

    // Actions
    #[serde(default)]
    pub action: Option<String>,
    #[serde(default)]
    pub rewrite_ttl: Option<u32>,
    #[serde(default)]
    pub client_subnet: Option<String>,
    #[serde(default)]
    pub disable_cache: Option<bool>,
    /// Limit the number of addresses returned
    #[serde(default)]
    pub address_limit: Option<u32>,
    /// Predefined answer IPs (hijacks traffic if match)
    #[serde(default)]
    pub rewrite_ip: Option<Vec<String>>,
    /// Predefined answer RCode
    #[serde(default)]
    pub rcode: Option<String>,
    /// Predefined Answer Records
    #[serde(default)]
    pub answer: Option<Vec<String>>,
    /// Predefined Authority Records
    #[serde(default)]
    pub ns: Option<Vec<String>>,
    /// Predefined Additional Records
    #[serde(default)]
    pub extra: Option<Vec<String>>,
}

impl<'de> Deserialize<'de> for DnsRuleIR {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        RawDnsRuleIR::deserialize(deserializer).map(Into::into)
    }
}

/// DNS configuration (IR)
#[derive(Debug, Clone, Serialize, PartialEq, Default)]
pub struct DnsIR {
    /// Upstream servers
    #[serde(default)]
    pub servers: Vec<DnsServerIR>,
    /// Routing rules
    #[serde(default)]
    pub rules: Vec<DnsRuleIR>,
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
    /// EDNS0 Client Subnet (ECS) value, e.g., "1.2.3.0/24" or "2001:db8::/56"
    /// When set, an OPT(EDNS0) record with ECS will be attached to queries (backend permitting).
    #[serde(default)]
    pub client_subnet: Option<String>,
    /// Reverse mapping override (true to enable reverse mapping for all responses).
    #[serde(default)]
    pub reverse_mapping: Option<bool>,
    /// Resolution strategy: "prefer_ipv4", "prefer_ipv6", "ipv4_only", "ipv6_only".
    #[serde(default)]
    pub strategy: Option<String>,
    /// Use independent cache for this server/config.
    #[serde(default)]
    pub independent_cache: Option<bool>,
    /// When true, cached DNS entries never expire based on TTL;
    /// only LRU eviction removes them. (Go parity: disable_expire)
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
    /// Pool/concurrency strategy (best-effort if backend does not support)
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
    pub hosts: Vec<DnsHostIR>,
    #[serde(default)]
    pub hosts_ttl_s: Option<u64>,
}

impl<'de> Deserialize<'de> for DnsIR {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        RawDnsIR::deserialize(deserializer).map(Into::into)
    }
}

/// Static hosts mapping entry (IR)
#[derive(Debug, Clone, Serialize, PartialEq, Eq, Default)]
pub struct DnsHostIR {
    /// Domain
    pub domain: String,
    /// IP list (string form)
    #[serde(default)]
    pub ips: Vec<String>,
}

impl<'de> Deserialize<'de> for DnsHostIR {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        RawDnsHostIR::deserialize(deserializer).map(Into::into)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // ── DnsServerIR ──────────────────────────────────────────────────

    #[test]
    fn dns_server_basic_roundtrip() {
        let data = json!({
            "tag": "google",
            "address": "udp://8.8.8.8",
            "strategy": "prefer_ipv4",
            "detour": "direct"
        });
        let ir: DnsServerIR = serde_json::from_value(data.clone()).unwrap();
        assert_eq!(ir.tag, "google");
        assert_eq!(ir.address, "udp://8.8.8.8");
        assert_eq!(ir.strategy.as_deref(), Some("prefer_ipv4"));
        assert_eq!(ir.detour.as_deref(), Some("direct"));

        let rt = serde_json::to_value(&ir).unwrap();
        assert_eq!(rt["tag"], "google");
        assert_eq!(rt["address"], "udp://8.8.8.8");
    }

    #[test]
    fn dns_server_tls_transport_fields() {
        let data = json!({
            "tag": "dot-server",
            "address": "dot://1.1.1.1",
            "sni": "cloudflare-dns.com",
            "client_subnet": "1.2.3.0/24",
            "ca_paths": ["/etc/ssl/certs/ca.pem"],
            "ca_pem": ["-----BEGIN CERTIFICATE-----\nABC\n-----END CERTIFICATE-----"],
            "skip_cert_verify": true,
            "address_resolver": "local-dns",
            "address_strategy": "ipv4_only",
            "address_fallback_delay": "300ms"
        });
        let ir: DnsServerIR = serde_json::from_value(data).unwrap();
        assert_eq!(ir.sni.as_deref(), Some("cloudflare-dns.com"));
        assert_eq!(ir.client_subnet.as_deref(), Some("1.2.3.0/24"));
        assert_eq!(ir.ca_paths.len(), 1);
        assert_eq!(ir.ca_pem.len(), 1);
        assert_eq!(ir.skip_cert_verify, Some(true));
        assert_eq!(ir.address_resolver.as_deref(), Some("local-dns"));
        assert_eq!(ir.address_strategy.as_deref(), Some("ipv4_only"));
        assert_eq!(ir.address_fallback_delay.as_deref(), Some("300ms"));

        // roundtrip
        let rt: DnsServerIR = serde_json::from_value(serde_json::to_value(&ir).unwrap()).unwrap();
        assert_eq!(rt.sni, ir.sni);
        assert_eq!(rt.ca_paths, ir.ca_paths);
    }

    #[test]
    fn dns_server_type_rename() {
        let data = json!({
            "tag": "fakeip-srv",
            "address": "fakeip",
            "type": "fakeip",
            "inet4_range": "198.18.0.0/15",
            "inet6_range": "fc00::/18"
        });
        let ir: DnsServerIR = serde_json::from_value(data).unwrap();
        assert_eq!(ir.server_type.as_deref(), Some("fakeip"));
        assert_eq!(ir.inet4_range.as_deref(), Some("198.18.0.0/15"));
        assert_eq!(ir.inet6_range.as_deref(), Some("fc00::/18"));

        let rt = serde_json::to_value(&ir).unwrap();
        assert_eq!(rt["type"], "fakeip");
    }

    #[test]
    fn dns_server_resolved_fields() {
        let data = json!({
            "tag": "resolved-srv",
            "address": "resolved",
            "service": "resolved",
            "accept_default_resolvers": true
        });
        let ir: DnsServerIR = serde_json::from_value(data).unwrap();
        assert_eq!(ir.service.as_deref(), Some("resolved"));
        assert_eq!(ir.accept_default_resolvers, Some(true));
    }

    #[test]
    fn dns_server_hosts_fields() {
        let data = json!({
            "tag": "hosts-srv",
            "address": "hosts",
            "hosts_path": ["/etc/hosts"],
            "predefined": {"example.com": ["1.2.3.4"]}
        });
        let ir: DnsServerIR = serde_json::from_value(data).unwrap();
        assert_eq!(ir.hosts_path, vec!["/etc/hosts".to_string()]);
        assert!(ir.predefined.is_some());
    }

    #[test]
    fn dns_server_rejects_unknown_field_via_raw_bridge() {
        let data = json!({
            "tag": "dns-1",
            "address": "udp://1.1.1.1",
            "unknown_dns_server_field": true
        });
        let result = serde_json::from_value::<DnsServerIR>(data);
        assert!(
            result.is_err(),
            "DnsServerIR should reject unknown fields via Raw bridge"
        );
    }

    // ── DnsRuleIR ────────────────────────────────────────────────────

    #[test]
    fn dns_rule_basic_roundtrip() {
        let data = json!({
            "domain_suffix": [".cn", ".com.cn"],
            "server": "china-dns",
            "priority": 10
        });
        let ir: DnsRuleIR = serde_json::from_value(data).unwrap();
        assert_eq!(ir.domain_suffix.len(), 2);
        assert_eq!(ir.server.as_deref(), Some("china-dns"));
        assert_eq!(ir.priority, Some(10));

        let rt: DnsRuleIR = serde_json::from_value(serde_json::to_value(&ir).unwrap()).unwrap();
        assert_eq!(rt.domain_suffix, ir.domain_suffix);
        assert_eq!(rt.server, ir.server);
    }

    #[test]
    fn dns_rule_matching_fields() {
        let data = json!({
            "domain": ["example.com"],
            "keyword": ["ads"],
            "query_type": ["A", "AAAA"],
            "rule_set": ["geosite-cn"],
            "domain_regex": ["^ad\\."],
            "geosite": ["cn"],
            "geoip": ["CN"],
            "source_ip_cidr": ["192.168.0.0/16"],
            "ip_cidr": ["10.0.0.0/8"],
            "port": ["53"],
            "source_port": ["12345"],
            "process_name": ["chrome"],
            "process_path": ["/usr/bin/chrome"],
            "package_name": ["com.example"],
            "wifi_ssid": ["home"],
            "wifi_bssid": ["aa:bb:cc:dd:ee:ff"],
            "invert": true,
            "server": "block"
        });
        let ir: DnsRuleIR = serde_json::from_value(data).unwrap();
        assert_eq!(ir.domain, vec!["example.com"]);
        assert_eq!(ir.keyword, vec!["ads"]);
        assert_eq!(ir.query_type.len(), 2);
        assert_eq!(ir.rule_set, vec!["geosite-cn"]);
        assert!(ir.invert);
        assert_eq!(ir.geoip, vec!["CN"]);
        assert_eq!(ir.process_name, vec!["chrome"]);
    }

    #[test]
    fn dns_rule_parity_match_fields() {
        let data = json!({
            "ip_is_private": true,
            "source_ip_is_private": false,
            "ip_accept_any": true,
            "rule_set_ip_cidr_match_source": true,
            "rule_set_ip_cidr_accept_empty": false,
            "clash_mode": "rule",
            "network_is_expensive": true,
            "network_is_constrained": false,
            "server": "fallback"
        });
        let ir: DnsRuleIR = serde_json::from_value(data).unwrap();
        assert_eq!(ir.ip_is_private, Some(true));
        assert_eq!(ir.source_ip_is_private, Some(false));
        assert_eq!(ir.ip_accept_any, Some(true));
        assert_eq!(ir.clash_mode.as_deref(), Some("rule"));
        assert_eq!(ir.network_is_expensive, Some(true));
        assert_eq!(ir.network_is_constrained, Some(false));
    }

    #[test]
    fn dns_rule_action_fields() {
        let data = json!({
            "domain_suffix": [".example.com"],
            "action": "route",
            "server": "upstream",
            "rewrite_ttl": 300,
            "client_subnet": "2001:db8::/56",
            "disable_cache": true,
            "address_limit": 4,
            "rewrite_ip": ["1.2.3.4", "5.6.7.8"],
            "rcode": "NXDOMAIN",
            "answer": ["example.com. 300 IN A 1.2.3.4"],
            "ns": ["ns1.example.com."],
            "extra": ["extra.example.com. 300 IN A 9.8.7.6"]
        });
        let ir: DnsRuleIR = serde_json::from_value(data).unwrap();
        assert_eq!(ir.action.as_deref(), Some("route"));
        assert_eq!(ir.rewrite_ttl, Some(300));
        assert_eq!(ir.client_subnet.as_deref(), Some("2001:db8::/56"));
        assert_eq!(ir.disable_cache, Some(true));
        assert_eq!(ir.address_limit, Some(4));
        assert_eq!(ir.rewrite_ip.as_ref().unwrap().len(), 2);
        assert_eq!(ir.rcode.as_deref(), Some("NXDOMAIN"));
        assert_eq!(ir.answer.as_ref().unwrap().len(), 1);
        assert_eq!(ir.ns.as_ref().unwrap().len(), 1);
        assert_eq!(ir.extra.as_ref().unwrap().len(), 1);

        // roundtrip
        let rt: DnsRuleIR = serde_json::from_value(serde_json::to_value(&ir).unwrap()).unwrap();
        assert_eq!(rt.rewrite_ip, ir.rewrite_ip);
        assert_eq!(rt.rcode, ir.rcode);
    }

    #[test]
    fn dns_rule_rejects_unknown_field_via_raw_bridge() {
        let data = json!({
            "server": "dns-1",
            "unknown_dns_rule_field": true
        });
        let result = serde_json::from_value::<DnsRuleIR>(data);
        assert!(
            result.is_err(),
            "DnsRuleIR should reject unknown fields via Raw bridge"
        );
    }

    // ── DnsIR (top-level) ────────────────────────────────────────────

    #[test]
    fn dns_ir_toplevel_roundtrip() {
        let data = json!({
            "servers": [
                {"tag": "google", "address": "udp://8.8.8.8"},
                {"tag": "local", "address": "local"}
            ],
            "rules": [
                {"domain_suffix": [".cn"], "server": "local"}
            ],
            "default": "google",
            "final": "local",
            "disable_cache": false,
            "timeout_ms": 5000,
            "ttl_default_s": 600,
            "ttl_min_s": 60,
            "ttl_max_s": 86400,
            "ttl_neg_s": 30,
            "client_subnet": "1.2.3.0/24",
            "reverse_mapping": true,
            "strategy": "prefer_ipv4",
            "independent_cache": true,
            "disable_expire": false,
            "hosts": [
                {"domain": "localhost", "ips": ["127.0.0.1", "::1"]}
            ],
            "hosts_ttl_s": 3600
        });
        let ir: DnsIR = serde_json::from_value(data.clone()).unwrap();
        assert_eq!(ir.servers.len(), 2);
        assert_eq!(ir.rules.len(), 1);
        assert_eq!(ir.default.as_deref(), Some("google"));
        assert_eq!(ir.final_server.as_deref(), Some("local"));
        assert_eq!(ir.disable_cache, Some(false));
        assert_eq!(ir.timeout_ms, Some(5000));
        assert_eq!(ir.ttl_default_s, Some(600));
        assert_eq!(ir.ttl_min_s, Some(60));
        assert_eq!(ir.ttl_max_s, Some(86400));
        assert_eq!(ir.ttl_neg_s, Some(30));
        assert_eq!(ir.client_subnet.as_deref(), Some("1.2.3.0/24"));
        assert_eq!(ir.reverse_mapping, Some(true));
        assert_eq!(ir.strategy.as_deref(), Some("prefer_ipv4"));
        assert_eq!(ir.independent_cache, Some(true));
        assert_eq!(ir.disable_expire, Some(false));
        assert_eq!(ir.hosts.len(), 1);
        assert_eq!(ir.hosts_ttl_s, Some(3600));

        // full roundtrip
        let rt: DnsIR = serde_json::from_value(serde_json::to_value(&ir).unwrap()).unwrap();
        assert_eq!(rt.servers.len(), ir.servers.len());
        assert_eq!(rt.final_server, ir.final_server);
        assert_eq!(rt.hosts_ttl_s, ir.hosts_ttl_s);
    }

    #[test]
    fn dns_ir_final_field_rename() {
        // Verify "final" JSON key maps to final_server field
        let data = json!({"final": "fallback-dns"});
        let ir: DnsIR = serde_json::from_value(data).unwrap();
        assert_eq!(ir.final_server.as_deref(), Some("fallback-dns"));

        let rt = serde_json::to_value(&ir).unwrap();
        assert_eq!(rt["final"], "fallback-dns");
        // "final_server" should NOT appear in serialized output
        assert!(rt.get("final_server").is_none());
    }

    #[test]
    fn dns_ir_fakeip_fields() {
        let data = json!({
            "fakeip_enabled": true,
            "fakeip_v4_base": "198.18.0.0",
            "fakeip_v4_mask": 15,
            "fakeip_v6_base": "fc00::",
            "fakeip_v6_mask": 18,
            "servers": [{"tag": "fakeip", "address": "fakeip"}]
        });
        let ir: DnsIR = serde_json::from_value(data).unwrap();
        assert_eq!(ir.fakeip_enabled, Some(true));
        assert_eq!(ir.fakeip_v4_base.as_deref(), Some("198.18.0.0"));
        assert_eq!(ir.fakeip_v4_mask, Some(15));
        assert_eq!(ir.fakeip_v6_base.as_deref(), Some("fc00::"));
        assert_eq!(ir.fakeip_v6_mask, Some(18));
    }

    #[test]
    fn dns_ir_pool_fields() {
        let data = json!({
            "pool_strategy": "round_robin",
            "pool_race_window_ms": 100,
            "pool_he_race_ms": 250,
            "pool_he_order": "ipv4_first",
            "pool_max_inflight": 64,
            "pool_per_host_inflight": 8
        });
        let ir: DnsIR = serde_json::from_value(data).unwrap();
        assert_eq!(ir.pool_strategy.as_deref(), Some("round_robin"));
        assert_eq!(ir.pool_race_window_ms, Some(100));
        assert_eq!(ir.pool_he_race_ms, Some(250));
        assert_eq!(ir.pool_he_order.as_deref(), Some("ipv4_first"));
        assert_eq!(ir.pool_max_inflight, Some(64));
        assert_eq!(ir.pool_per_host_inflight, Some(8));
    }

    #[test]
    fn dns_ir_empty_default() {
        let ir = DnsIR::default();
        assert!(ir.servers.is_empty());
        assert!(ir.rules.is_empty());
        assert!(ir.default.is_none());
        assert!(ir.final_server.is_none());
        assert!(ir.hosts.is_empty());

        // roundtrip of empty
        let rt: DnsIR = serde_json::from_value(serde_json::to_value(&ir).unwrap()).unwrap();
        assert_eq!(rt.servers.len(), 0);
    }

    #[test]
    fn dns_ir_rejects_unknown_field_via_raw_bridge() {
        let data = json!({
            "servers": [],
            "unknown_dns_field": true
        });
        let result = serde_json::from_value::<DnsIR>(data);
        assert!(
            result.is_err(),
            "DnsIR should reject unknown fields via Raw bridge"
        );
    }

    // ── DnsHostIR ────────────────────────────────────────────────────

    #[test]
    fn dns_host_roundtrip() {
        let data = json!({
            "domain": "example.com",
            "ips": ["1.2.3.4", "::1"]
        });
        let ir: DnsHostIR = serde_json::from_value(data).unwrap();
        assert_eq!(ir.domain, "example.com");
        assert_eq!(ir.ips, vec!["1.2.3.4", "::1"]);

        let rt: DnsHostIR = serde_json::from_value(serde_json::to_value(&ir).unwrap()).unwrap();
        assert_eq!(rt.domain, ir.domain);
        assert_eq!(rt.ips, ir.ips);
    }

    #[test]
    fn dns_host_empty_ips_default() {
        let data = json!({"domain": "localhost"});
        let ir: DnsHostIR = serde_json::from_value(data).unwrap();
        assert_eq!(ir.domain, "localhost");
        assert!(ir.ips.is_empty());
    }

    #[test]
    fn dns_host_rejects_unknown_field_via_raw_bridge() {
        let data = json!({
            "domain": "localhost",
            "unknown_dns_host_field": true
        });
        let result = serde_json::from_value::<DnsHostIR>(data);
        assert!(
            result.is_err(),
            "DnsHostIR should reject unknown fields via Raw bridge"
        );
    }
}
