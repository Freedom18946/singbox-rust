//! Explicit, immutable runtime options injected by the application composition root.
//!
//! Environment parsing intentionally lives outside `sb-core`.  Defaults here preserve the
//! historical empty-environment behaviour for library users and tests.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DnsRuntimeOptions {
    pub enabled: bool,
    pub qtype: String,
    pub mode: String,
    pub timeout_ms: u64,
    pub resolver_timeout_ms: u64,
    pub query_timeout_ms: u64,
    pub udp_server: SocketAddr,
    pub udp_timeout_ms: u64,
    pub udp_retries: usize,
    pub tcp_timeout_ms: u64,
    pub dot_addr: Option<SocketAddr>,
    pub dot_timeout_ms: u64,
    pub doh_url: String,
    pub doh_timeout_ms: u64,
    pub doh3_timeout_ms: u64,
    pub doq_addr: Option<SocketAddr>,
    pub doq_server_name: Option<String>,
    pub doq_timeout_ms: u64,
    pub retries: usize,
    pub default_ttl_s: u64,
    pub min_ttl_s: u64,
    pub max_ttl_s: u64,
    pub negative_ttl_s: u64,
    pub legacy_ttl_s: u64,
    pub cache_enabled: bool,
    pub cache_capacity: usize,
    pub resolve_cache_capacity: usize,
    pub cache_max: usize,
    pub cache_negative_ttl_ms: u64,
    pub cache_stale_ms: u64,
    pub cache_ttl_s: u64,
    pub cache_cleanup_interval_s: u64,
    pub answer_cache_negative_ttl_s: u64,
    pub answer_cache_min_ttl_s: u64,
    pub answer_cache_max_ttl_s: u64,
    pub ipv6_enabled: bool,
    pub static_records: String,
    pub static_ttl_s: u64,
    pub hosts_enabled: bool,
    pub hosts_ttl_s: u64,
    pub hosts_file_ttl_s: u64,
    pub prefetch_enabled: bool,
    pub prefetch_before_ms: u64,
    pub prefetch_concurrency: usize,
    pub pool: String,
    pub pool_strategy: String,
    pub pool_max_inflight: usize,
    pub per_host_inflight: usize,
    pub race_window_ms: u64,
    pub happy_eyeballs_order: String,
    pub happy_eyeballs_race_ms: u64,
    pub client_subnet: Option<String>,
    pub fallback_enabled: bool,
    pub parallel: bool,
    pub upstream: Option<String>,
    pub servers: Vec<SocketAddr>,
    pub strategy: String,
    pub fakeip_enabled: bool,
    pub fakeip_v6: bool,
    pub fakeip_ttl_s: u64,
    pub fakeip_v4_base: Ipv4Addr,
    pub fakeip_v4_mask: u8,
    pub fakeip_v6_base: Ipv6Addr,
    pub fakeip_v6_mask: u8,
    pub fakeip_capacity: usize,
    pub dhcp_resolv_conf: Option<PathBuf>,
    pub resolved_stub: Option<PathBuf>,
    pub tailscale_addrs: Vec<SocketAddr>,
    pub system_ttl_s: u64,
    pub local_ttl_s: u64,
}

impl Default for DnsRuntimeOptions {
    fn default() -> Self {
        Self {
            enabled: false,
            qtype: "auto".into(),
            mode: "system".into(),
            timeout_ms: 1_500,
            resolver_timeout_ms: 2_000,
            query_timeout_ms: 5_000,
            udp_server: SocketAddr::from(([1, 1, 1, 1], 53)),
            udp_timeout_ms: 2_000,
            udp_retries: 2,
            tcp_timeout_ms: 5_000,
            dot_addr: None,
            dot_timeout_ms: 5_000,
            doh_url: "https://cloudflare-dns.com/dns-query".into(),
            doh_timeout_ms: 5_000,
            doh3_timeout_ms: 5_000,
            doq_addr: None,
            doq_server_name: None,
            doq_timeout_ms: 5_000,
            retries: 2,
            default_ttl_s: 60,
            min_ttl_s: 1,
            max_ttl_s: 86_400,
            negative_ttl_s: 30,
            legacy_ttl_s: 300,
            cache_enabled: false,
            cache_capacity: 1_024,
            resolve_cache_capacity: 4_096,
            cache_max: 1_024,
            cache_negative_ttl_ms: 20_000,
            cache_stale_ms: 0,
            cache_ttl_s: 60,
            cache_cleanup_interval_s: 300,
            answer_cache_negative_ttl_s: 300,
            answer_cache_min_ttl_s: 5,
            answer_cache_max_ttl_s: 3_600,
            ipv6_enabled: true,
            static_records: String::new(),
            static_ttl_s: 300,
            hosts_enabled: true,
            hosts_ttl_s: 300,
            hosts_file_ttl_s: 3_600,
            prefetch_enabled: false,
            prefetch_before_ms: 200,
            prefetch_concurrency: 4,
            pool: "system".into(),
            pool_strategy: "race".into(),
            pool_max_inflight: 64,
            per_host_inflight: 2,
            race_window_ms: 50,
            happy_eyeballs_order: "A_FIRST".into(),
            happy_eyeballs_race_ms: 30,
            client_subnet: None,
            fallback_enabled: true,
            parallel: false,
            upstream: None,
            servers: vec![
                SocketAddr::from(([8, 8, 8, 8], 53)),
                SocketAddr::from(([1, 1, 1, 1], 53)),
            ],
            strategy: "prefer_ipv4".into(),
            fakeip_enabled: false,
            fakeip_v6: false,
            fakeip_ttl_s: 300,
            fakeip_v4_base: Ipv4Addr::new(240, 0, 0, 0),
            fakeip_v4_mask: 8,
            fakeip_v6_base: Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0),
            fakeip_v6_mask: 8,
            fakeip_capacity: 16_384,
            dhcp_resolv_conf: None,
            resolved_stub: None,
            tailscale_addrs: Vec::new(),
            system_ttl_s: 60,
            local_ttl_s: 60,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RouterRuntimeOptions {
    pub rules_inline: String,
    pub rules_file: Option<PathBuf>,
    pub rules_base_dir: Option<PathBuf>,
    pub rules_enabled: bool,
    pub rules_text: Option<String>,
    pub rules_max: usize,
    pub rules_hot_reload_ms: u64,
    pub rules_jitter_ms: u64,
    pub rules_max_depth: usize,
    pub rules_include_depth: usize,
    pub rules_backoff_max_ms: u64,
    pub rules_require_default: bool,
    pub suffix_strict: bool,
    pub suffix_trie: bool,
    pub hot_reload: bool,
    pub decision_cache: bool,
    pub decision_cache_capacity: usize,
    pub decide_budget_ms: u64,
    pub dns_enabled: bool,
    pub dns_timeout_ms: u64,
    pub dns_integration_timeout_ms: u64,
    pub geoip_enabled: bool,
    pub geoip_mmdb: Option<PathBuf>,
    pub geoip_cache_capacity: usize,
    pub geoip_ttl: Duration,
    pub udp_enabled: bool,
    pub udp_rules: Option<String>,
    pub runtime_override: Option<String>,
    pub domain_overrides: Option<String>,
    pub default_proxy: Option<String>,
    pub default_proxy_kind: Option<String>,
    pub default_proxy_addr: Option<String>,
    pub json_rules_enabled: bool,
    pub json_file: Option<PathBuf>,
    pub json_text: Option<String>,
    pub keyword_ac_min: usize,
    pub explain_rebuild_ms: Option<u64>,
    pub rule_coverage: bool,
    pub public_suffix_list: Option<PathBuf>,
}

impl Default for RouterRuntimeOptions {
    fn default() -> Self {
        Self {
            rules_inline: String::new(),
            rules_file: None,
            rules_base_dir: None,
            rules_enabled: false,
            rules_text: None,
            rules_max: 8_192,
            rules_hot_reload_ms: 0,
            rules_jitter_ms: 0,
            rules_max_depth: 3,
            rules_include_depth: 4,
            rules_backoff_max_ms: 30_000,
            rules_require_default: false,
            suffix_strict: false,
            suffix_trie: false,
            hot_reload: false,
            decision_cache: false,
            decision_cache_capacity: 1_024,
            decide_budget_ms: 100,
            dns_enabled: false,
            dns_timeout_ms: 300,
            dns_integration_timeout_ms: 5_000,
            geoip_enabled: false,
            geoip_mmdb: None,
            geoip_cache_capacity: 8_192,
            geoip_ttl: Duration::from_secs(600),
            udp_enabled: false,
            udp_rules: None,
            runtime_override: None,
            domain_overrides: None,
            default_proxy: None,
            default_proxy_kind: None,
            default_proxy_addr: None,
            json_rules_enabled: false,
            json_file: None,
            json_text: None,
            keyword_ac_min: 64,
            explain_rebuild_ms: None,
            rule_coverage: false,
            public_suffix_list: None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NetworkRuntimeOptions {
    pub dial_timeout: Duration,
    pub dial_use_all: bool,
    pub udp_ttl: Duration,
    pub udp_gc_interval: Duration,
    pub udp_nat_max: usize,
    pub udp_outbound_bytes_per_second: u64,
    pub udp_outbound_packets_per_second: u64,
    pub inbound_rate_limit_per_ip: usize,
    pub inbound_rate_limit_window: Duration,
    pub inbound_rate_limit_qps: Option<usize>,
    pub socks_udp_resolve_bound: bool,
    pub tcp_proxy_mode: Option<String>,
    pub tcp_proxy_http: Option<String>,
    pub tcp_proxy_timeout: Duration,
    pub buffer_pool_size: usize,
    pub buffer_pool_max_capacity: usize,
    pub transport_sni_fallback: bool,
    pub network_strategy: Option<String>,
}

impl Default for NetworkRuntimeOptions {
    fn default() -> Self {
        Self {
            dial_timeout: Duration::from_millis(4_000),
            dial_use_all: false,
            udp_ttl: Duration::from_millis(300_000),
            udp_gc_interval: Duration::from_millis(5_000),
            udp_nat_max: 65_536,
            udp_outbound_bytes_per_second: 0,
            udp_outbound_packets_per_second: 0,
            inbound_rate_limit_per_ip: 100,
            inbound_rate_limit_window: Duration::from_secs(10),
            inbound_rate_limit_qps: None,
            socks_udp_resolve_bound: false,
            tcp_proxy_mode: None,
            tcp_proxy_http: None,
            tcp_proxy_timeout: Duration::from_millis(8_000),
            buffer_pool_size: 100,
            buffer_pool_max_capacity: 1024 * 1024,
            transport_sni_fallback: true,
            network_strategy: None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServiceRuntimeOptions {
    pub health_enabled: bool,
    pub proxy_health_enabled: bool,
    pub proxy_health_interval: Duration,
    pub proxy_health_timeout: Duration,
    pub ntp_server: String,
    pub ntp_interval: Duration,
    pub ntp_timeout: Duration,
    pub circuit_breaker_enabled: bool,
    pub runtime_diff: bool,
}

impl Default for ServiceRuntimeOptions {
    fn default() -> Self {
        Self {
            health_enabled: false,
            proxy_health_enabled: false,
            proxy_health_interval: Duration::from_millis(3_000),
            proxy_health_timeout: Duration::from_millis(800),
            ntp_server: "time.google.com:123".into(),
            ntp_interval: Duration::from_secs(1_800),
            ntp_timeout: Duration::from_millis(1_500),
            circuit_breaker_enabled: false,
            runtime_diff: false,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DebugRuntimeOptions {
    pub access_log: bool,
    pub failpoints: Option<String>,
    pub admin_max_header_bytes: usize,
    pub admin_max_body_bytes: usize,
    pub admin_first_byte_timeout: Duration,
    pub admin_first_line_timeout: Duration,
    pub admin_read_timeout: Duration,
    pub admin_write_timeout: Duration,
    pub admin_max_connections_per_ip: usize,
    pub admin_max_requests_per_second_per_ip: usize,
}

impl Default for DebugRuntimeOptions {
    fn default() -> Self {
        Self {
            access_log: false,
            failpoints: None,
            admin_max_header_bytes: 64 * 1024,
            admin_max_body_bytes: 2 * 1024 * 1024,
            admin_first_byte_timeout: Duration::from_millis(1_500),
            admin_first_line_timeout: Duration::from_millis(3_000),
            admin_read_timeout: Duration::from_millis(4_000),
            admin_write_timeout: Duration::from_millis(4_000),
            admin_max_connections_per_ip: 8,
            admin_max_requests_per_second_per_ip: 16,
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CoreRuntimeOptions {
    pub dns: DnsRuntimeOptions,
    pub router: RouterRuntimeOptions,
    pub network: NetworkRuntimeOptions,
    pub services: ServiceRuntimeOptions,
    pub debug: DebugRuntimeOptions,
}

pub type SharedCoreRuntimeOptions = Arc<CoreRuntimeOptions>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_environment_defaults_are_locked() {
        let options = CoreRuntimeOptions::default();
        assert!(!options.dns.enabled);
        assert_eq!(options.dns.default_ttl_s, 60);
        assert_eq!(options.dns.udp_timeout_ms, 2_000);
        assert_eq!(options.dns.pool_max_inflight, 64);
        assert_eq!(options.router.rules_max, 8_192);
        assert_eq!(options.router.decide_budget_ms, 100);
        assert_eq!(options.network.dial_timeout, Duration::from_millis(4_000));
        assert_eq!(options.network.udp_nat_max, 65_536);
        assert_eq!(options.services.ntp_interval, Duration::from_secs(1_800));
        assert_eq!(options.debug.admin_max_header_bytes, 64 * 1024);
    }
}
