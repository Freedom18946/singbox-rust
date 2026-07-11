//! Application-owned parsing for legacy core environment controls.

use sb_core::runtime_options::{
    CoreRuntimeOptions, DebugRuntimeOptions, DnsRuntimeOptions, NetworkRuntimeOptions,
    RouterRuntimeOptions, ServiceRuntimeOptions,
};
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

pub const CORE_ENV_KEYS: &[&str] = &[
    "SB_ACCESS_LOG",
    "SB_ADMIN_FIRSTBYTE_TIMEOUT_MS",
    "SB_ADMIN_FIRSTLINE_TIMEOUT_MS",
    "SB_ADMIN_MAX_BODY_BYTES",
    "SB_ADMIN_MAX_CONN_PER_IP",
    "SB_ADMIN_MAX_HEADER_BYTES",
    "SB_ADMIN_MAX_RPS_PER_IP",
    "SB_ADMIN_READ_TIMEOUT_MS",
    "SB_ADMIN_WRITE_TIMEOUT_MS",
    "SB_BUFFER_POOL_MAX_CAPACITY",
    "SB_BUFFER_POOL_SIZE",
    "SB_CB_ENABLE",
    "SB_DIAL_TIMEOUT_MS",
    "SB_DIAL_USE_ALL",
    "SB_DNS_CACHE_CAP",
    "SB_DNS_CACHE_CLEANUP_INTERVAL_S",
    "SB_DNS_CACHE_ENABLE",
    "SB_DNS_CACHE_MAX",
    "SB_DNS_CACHE_NEG_TTL_MS",
    "SB_DNS_CACHE_SIZE",
    "SB_DNS_CACHE_STALE_MS",
    "SB_DNS_CACHE_TTL_SEC",
    "SB_DNS_CLIENT_SUBNET",
    "SB_DNS_DEFAULT_TTL_S",
    "SB_DNS_DHCP_RESOLV_CONF",
    "SB_DNS_DOH3_TIMEOUT_MS",
    "SB_DNS_DOH_TIMEOUT_MS",
    "SB_DNS_DOH_URL",
    "SB_DNS_DOQ_ADDR",
    "SB_DNS_DOQ_SERVER_NAME",
    "SB_DNS_DOQ_TIMEOUT_MS",
    "SB_DNS_DOT_ADDR",
    "SB_DNS_DOT_TIMEOUT_MS",
    "SB_DNS_ENABLE",
    "SB_DNS_FAKEIP_ENABLE",
    "SB_DNS_FAKEIP_TTL_S",
    "SB_DNS_FAKEIP_V6",
    "SB_DNS_FALLBACK",
    "SB_DNS_HE_ORDER",
    "SB_DNS_HE_RACE_MS",
    "SB_DNS_HOSTS_ENABLE",
    "SB_DNS_HOSTS_TTL_S",
    "SB_DNS_IPV6",
    "SB_DNS_LOCAL_TTL_S",
    "SB_DNS_MAX_TTL_S",
    "SB_DNS_MIN_TTL_S",
    "SB_DNS_MODE",
    "SB_DNS_NEGATIVE_TTL_S",
    "SB_DNS_NEG_TTL_S",
    "SB_DNS_PARALLEL",
    "SB_DNS_PER_HOST_INFLIGHT",
    "SB_DNS_POOL",
    "SB_DNS_POOL_MAX_INFLIGHT",
    "SB_DNS_POOL_STRATEGY",
    "SB_DNS_PREFETCH",
    "SB_DNS_PREFETCH_BEFORE_MS",
    "SB_DNS_PREFETCH_CONCURRENCY",
    "SB_DNS_QTYPE",
    "SB_DNS_QUERY_TIMEOUT_MS",
    "SB_DNS_RACE_WINDOW_MS",
    "SB_DNS_RESOLVED_STUB",
    "SB_DNS_RETRIES",
    "SB_DNS_SERVERS",
    "SB_DNS_STATIC",
    "SB_DNS_STATIC_TTL_S",
    "SB_DNS_STRATEGY",
    "SB_DNS_SYSTEM_TTL_S",
    "SB_DNS_TCP_TIMEOUT_MS",
    "SB_DNS_TIMEOUT_MS",
    "SB_DNS_TTL",
    "SB_DNS_UDP_RETRIES",
    "SB_DNS_UDP_SERVER",
    "SB_DNS_UDP_TIMEOUT_MS",
    "SB_DNS_UPSTREAM",
    "SB_EXPLAIN_REBUILD_MS",
    "SB_FAILPOINTS",
    "SB_FAKEIP_CAP",
    "SB_FAKEIP_V4_BASE",
    "SB_FAKEIP_V4_MASK",
    "SB_FAKEIP_V6_BASE",
    "SB_FAKEIP_V6_MASK",
    "SB_GEOIP_CACHE",
    "SB_GEOIP_ENABLE",
    "SB_GEOIP_MMDB",
    "SB_GEOIP_TTL",
    "SB_HEALTH_ENABLE",
    "SB_INBOUND_RATE_LIMIT_PER_IP",
    "SB_INBOUND_RATE_LIMIT_QPS",
    "SB_INBOUND_RATE_LIMIT_WINDOW_SEC",
    "SB_NETWORK_STRATEGY",
    "SB_NTP_INTERVAL_S",
    "SB_NTP_SERVER",
    "SB_NTP_TIMEOUT_MS",
    "SB_PROXY_HEALTH_ENABLE",
    "SB_PROXY_HEALTH_INTERVAL_MS",
    "SB_PROXY_HEALTH_TIMEOUT_MS",
    "SB_PUBLIC_SUFFIX_LIST",
    "SB_ROUTER_DECIDE_BUDGET_MS",
    "SB_ROUTER_DECISION_CACHE",
    "SB_ROUTER_DECISION_CACHE_CAP",
    "SB_ROUTER_DEFAULT_PROXY",
    "SB_ROUTER_DEFAULT_PROXY_ADDR",
    "SB_ROUTER_DEFAULT_PROXY_KIND",
    "SB_ROUTER_DNS",
    "SB_ROUTER_DNS_TIMEOUT_MS",
    "SB_ROUTER_DOMAIN_OVERRIDES",
    "SB_ROUTER_HOT_RELOAD",
    "SB_ROUTER_JSON_FILE",
    "SB_ROUTER_JSON_TEXT",
    "SB_ROUTER_KEYWORD_AC_MIN",
    "SB_ROUTER_OVERRIDE",
    "SB_ROUTER_RULES",
    "SB_ROUTER_RULES_BACKOFF_MAX_MS",
    "SB_ROUTER_RULES_BASEDIR",
    "SB_ROUTER_RULES_ENABLE",
    "SB_ROUTER_RULES_FILE",
    "SB_ROUTER_RULES_FROM_JSON",
    "SB_ROUTER_RULES_HOT_RELOAD_MS",
    "SB_ROUTER_RULES_INCLUDE_DEPTH",
    "SB_ROUTER_RULES_JITTER_MS",
    "SB_ROUTER_RULES_MAX",
    "SB_ROUTER_RULES_MAX_DEPTH",
    "SB_ROUTER_RULES_REQUIRE_DEFAULT",
    "SB_ROUTER_RULES_TEXT",
    "SB_ROUTER_SUFFIX_STRICT",
    "SB_ROUTER_SUFFIX_TRIE",
    "SB_ROUTER_UDP",
    "SB_ROUTER_UDP_RULES",
    "SB_RULE_COVERAGE",
    "SB_RUNTIME_DIFF",
    "SB_SOCKS_UDP_RESOLVE_BND",
    "SB_TAILSCALE_DNS_ADDRS",
    "SB_TCP_PROXY_HTTP",
    "SB_TCP_PROXY_MODE",
    "SB_TCP_PROXY_TIMEOUT_MS",
    "SB_TRANSPORT_SNI_FALLBACK",
    "SB_UDP_GC_MS",
    "SB_UDP_NAT_MAX",
    "SB_UDP_OUTBOUND_BPS_MAX",
    "SB_UDP_OUTBOUND_PPS_MAX",
    "SB_UDP_TTL_MS",
];

fn raw(key: &str) -> Option<String> {
    std::env::var(key).ok()
}

fn string(key: &str) -> Option<String> {
    raw(key).and_then(|value| {
        let value = value.trim();
        (!value.is_empty()).then(|| value.to_string())
    })
}

fn bool_value(key: &str, default: bool) -> bool {
    let Some(value) = raw(key) else {
        return default;
    };
    match value.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => true,
        "" | "0" | "false" | "no" | "off" => false,
        other => {
            tracing::warn!(
                key,
                value = other,
                default,
                "invalid boolean runtime environment value"
            );
            default
        }
    }
}

fn present(key: &str) -> bool {
    std::env::var_os(key).is_some()
}

fn number<T>(key: &str, default: T) -> T
where
    T: std::str::FromStr + Copy + std::fmt::Display,
    T::Err: std::fmt::Display,
{
    let Some(value) = raw(key) else {
        return default;
    };
    match value.trim().parse::<T>() {
        Ok(value) => value,
        Err(error) => {
            tracing::warn!(key, value, %error, %default, "invalid numeric runtime environment value");
            default
        }
    }
}

fn optional_number<T>(key: &str) -> Option<T>
where
    T: std::str::FromStr,
    T::Err: std::fmt::Display,
{
    let value = raw(key)?;
    match value.trim().parse::<T>() {
        Ok(value) => Some(value),
        Err(error) => {
            tracing::warn!(key, value, %error, "invalid optional numeric runtime environment value");
            None
        }
    }
}

fn socket(key: &str, default: SocketAddr) -> SocketAddr {
    string(key)
        .and_then(|value| match value.parse() {
            Ok(address) => Some(address),
            Err(error) => {
                tracing::warn!(key, value, %error, %default, "invalid socket runtime environment value");
                None
            }
        })
        .unwrap_or(default)
}

fn optional_socket(key: &str) -> Option<SocketAddr> {
    let value = string(key)?;
    match value.parse() {
        Ok(address) => Some(address),
        Err(error) => {
            tracing::warn!(key, value, %error, "invalid optional socket runtime environment value");
            None
        }
    }
}

fn ip<T>(key: &str, default: T) -> T
where
    T: std::str::FromStr + Copy + std::fmt::Display,
    T::Err: std::fmt::Display,
{
    string(key)
        .and_then(|value| match value.parse() {
            Ok(address) => Some(address),
            Err(error) => {
                tracing::warn!(key, value, %error, %default, "invalid IP runtime environment value");
                None
            }
        })
        .unwrap_or(default)
}

fn sockets(key: &str, defaults: Vec<SocketAddr>, default_port: u16) -> Vec<SocketAddr> {
    let Some(value) = string(key) else {
        return defaults;
    };
    let parsed: Vec<_> = value
        .split(',')
        .filter_map(|item| {
            let item = item.trim();
            item.parse::<SocketAddr>().ok().or_else(|| {
                item.parse::<IpAddr>()
                    .ok()
                    .map(|address| SocketAddr::new(address, default_port))
            })
        })
        .collect();
    if parsed.is_empty() {
        tracing::warn!(
            key,
            value,
            "runtime address list contained no valid entries; using defaults"
        );
        defaults
    } else {
        parsed
    }
}

fn dns_options() -> DnsRuntimeOptions {
    let defaults = DnsRuntimeOptions::default();
    DnsRuntimeOptions {
        enabled: bool_value("SB_DNS_ENABLE", defaults.enabled),
        qtype: string("SB_DNS_QTYPE").unwrap_or(defaults.qtype),
        mode: string("SB_DNS_MODE").unwrap_or(defaults.mode),
        timeout_ms: number("SB_DNS_TIMEOUT_MS", defaults.timeout_ms),
        resolver_timeout_ms: number("SB_DNS_TIMEOUT_MS", defaults.resolver_timeout_ms),
        query_timeout_ms: number("SB_DNS_QUERY_TIMEOUT_MS", defaults.query_timeout_ms),
        udp_server: socket("SB_DNS_UDP_SERVER", defaults.udp_server),
        udp_timeout_ms: number("SB_DNS_UDP_TIMEOUT_MS", defaults.udp_timeout_ms),
        udp_retries: number("SB_DNS_UDP_RETRIES", defaults.udp_retries),
        tcp_timeout_ms: number("SB_DNS_TCP_TIMEOUT_MS", defaults.tcp_timeout_ms),
        dot_addr: optional_socket("SB_DNS_DOT_ADDR"),
        dot_timeout_ms: number("SB_DNS_DOT_TIMEOUT_MS", defaults.dot_timeout_ms),
        doh_url: string("SB_DNS_DOH_URL").unwrap_or(defaults.doh_url),
        doh_timeout_ms: number("SB_DNS_DOH_TIMEOUT_MS", defaults.doh_timeout_ms),
        doh3_timeout_ms: number("SB_DNS_DOH3_TIMEOUT_MS", defaults.doh3_timeout_ms),
        doq_addr: optional_socket("SB_DNS_DOQ_ADDR"),
        doq_server_name: string("SB_DNS_DOQ_SERVER_NAME"),
        doq_timeout_ms: number("SB_DNS_DOQ_TIMEOUT_MS", defaults.doq_timeout_ms),
        retries: number("SB_DNS_RETRIES", defaults.retries),
        default_ttl_s: number("SB_DNS_DEFAULT_TTL_S", defaults.default_ttl_s),
        min_ttl_s: number("SB_DNS_MIN_TTL_S", defaults.min_ttl_s),
        max_ttl_s: number("SB_DNS_MAX_TTL_S", defaults.max_ttl_s),
        negative_ttl_s: optional_number("SB_DNS_NEG_TTL_S")
            .or_else(|| optional_number("SB_DNS_NEGATIVE_TTL_S"))
            .unwrap_or(defaults.negative_ttl_s),
        legacy_ttl_s: number("SB_DNS_TTL", defaults.legacy_ttl_s),
        cache_enabled: bool_value("SB_DNS_CACHE_ENABLE", defaults.cache_enabled),
        cache_capacity: optional_number("SB_DNS_CACHE_SIZE")
            .or_else(|| optional_number("SB_DNS_CACHE_CAP"))
            .unwrap_or(defaults.cache_capacity),
        resolve_cache_capacity: number("SB_DNS_CACHE_CAP", defaults.resolve_cache_capacity),
        cache_max: number("SB_DNS_CACHE_MAX", defaults.cache_max),
        cache_negative_ttl_ms: number("SB_DNS_CACHE_NEG_TTL_MS", defaults.cache_negative_ttl_ms),
        cache_stale_ms: number("SB_DNS_CACHE_STALE_MS", defaults.cache_stale_ms),
        cache_ttl_s: number("SB_DNS_CACHE_TTL_SEC", defaults.cache_ttl_s),
        cache_cleanup_interval_s: number("SB_DNS_CACHE_CLEANUP_INTERVAL_S", 300),
        answer_cache_negative_ttl_s: number("SB_DNS_NEGATIVE_TTL_S", 300),
        answer_cache_min_ttl_s: number("SB_DNS_MIN_TTL_S", 5),
        answer_cache_max_ttl_s: number("SB_DNS_MAX_TTL_S", 3_600),
        ipv6_enabled: bool_value("SB_DNS_IPV6", defaults.ipv6_enabled),
        static_records: raw("SB_DNS_STATIC").unwrap_or(defaults.static_records),
        static_ttl_s: optional_number("SB_DNS_STATIC_TTL_S")
            .or_else(|| optional_number("SB_DNS_HOSTS_TTL_S"))
            .unwrap_or(defaults.static_ttl_s),
        hosts_enabled: bool_value("SB_DNS_HOSTS_ENABLE", defaults.hosts_enabled),
        hosts_ttl_s: number("SB_DNS_HOSTS_TTL_S", defaults.hosts_ttl_s),
        hosts_file_ttl_s: number("SB_DNS_HOSTS_TTL_S", defaults.hosts_file_ttl_s),
        prefetch_enabled: bool_value("SB_DNS_PREFETCH", defaults.prefetch_enabled),
        prefetch_before_ms: number("SB_DNS_PREFETCH_BEFORE_MS", defaults.prefetch_before_ms),
        prefetch_concurrency: number("SB_DNS_PREFETCH_CONCURRENCY", defaults.prefetch_concurrency),
        pool: string("SB_DNS_POOL").unwrap_or(defaults.pool),
        pool_strategy: string("SB_DNS_POOL_STRATEGY").unwrap_or(defaults.pool_strategy),
        pool_max_inflight: number("SB_DNS_POOL_MAX_INFLIGHT", defaults.pool_max_inflight),
        per_host_inflight: number("SB_DNS_PER_HOST_INFLIGHT", defaults.per_host_inflight),
        race_window_ms: number("SB_DNS_RACE_WINDOW_MS", defaults.race_window_ms),
        happy_eyeballs_order: string("SB_DNS_HE_ORDER").unwrap_or(defaults.happy_eyeballs_order),
        happy_eyeballs_race_ms: number("SB_DNS_HE_RACE_MS", defaults.happy_eyeballs_race_ms),
        client_subnet: string("SB_DNS_CLIENT_SUBNET"),
        fallback_enabled: bool_value("SB_DNS_FALLBACK", defaults.fallback_enabled),
        parallel: bool_value("SB_DNS_PARALLEL", defaults.parallel),
        upstream: string("SB_DNS_UPSTREAM"),
        servers: sockets("SB_DNS_SERVERS", defaults.servers, 53),
        strategy: string("SB_DNS_STRATEGY").unwrap_or(defaults.strategy),
        fakeip_enabled: bool_value("SB_DNS_FAKEIP_ENABLE", defaults.fakeip_enabled),
        fakeip_v6: bool_value("SB_DNS_FAKEIP_V6", defaults.fakeip_v6),
        fakeip_ttl_s: number("SB_DNS_FAKEIP_TTL_S", defaults.fakeip_ttl_s),
        fakeip_v4_base: ip("SB_FAKEIP_V4_BASE", defaults.fakeip_v4_base),
        fakeip_v4_mask: number("SB_FAKEIP_V4_MASK", defaults.fakeip_v4_mask),
        fakeip_v6_base: ip("SB_FAKEIP_V6_BASE", defaults.fakeip_v6_base),
        fakeip_v6_mask: number("SB_FAKEIP_V6_MASK", defaults.fakeip_v6_mask),
        fakeip_capacity: number("SB_FAKEIP_CAP", defaults.fakeip_capacity),
        dhcp_resolv_conf: string("SB_DNS_DHCP_RESOLV_CONF").map(PathBuf::from),
        resolved_stub: string("SB_DNS_RESOLVED_STUB").map(PathBuf::from),
        tailscale_addrs: sockets("SB_TAILSCALE_DNS_ADDRS", defaults.tailscale_addrs, 53),
        system_ttl_s: number("SB_DNS_SYSTEM_TTL_S", defaults.system_ttl_s),
        local_ttl_s: number("SB_DNS_LOCAL_TTL_S", defaults.local_ttl_s),
    }
}

fn router_options() -> RouterRuntimeOptions {
    let defaults = RouterRuntimeOptions::default();
    RouterRuntimeOptions {
        rules_inline: raw("SB_ROUTER_RULES").unwrap_or(defaults.rules_inline),
        rules_file: string("SB_ROUTER_RULES_FILE").map(PathBuf::from),
        rules_base_dir: string("SB_ROUTER_RULES_BASEDIR").map(PathBuf::from),
        rules_enabled: bool_value("SB_ROUTER_RULES_ENABLE", defaults.rules_enabled),
        rules_text: string("SB_ROUTER_RULES_TEXT"),
        rules_max: number("SB_ROUTER_RULES_MAX", defaults.rules_max),
        rules_hot_reload_ms: number(
            "SB_ROUTER_RULES_HOT_RELOAD_MS",
            defaults.rules_hot_reload_ms,
        ),
        rules_jitter_ms: number("SB_ROUTER_RULES_JITTER_MS", defaults.rules_jitter_ms),
        rules_max_depth: number("SB_ROUTER_RULES_MAX_DEPTH", defaults.rules_max_depth),
        rules_include_depth: number(
            "SB_ROUTER_RULES_INCLUDE_DEPTH",
            defaults.rules_include_depth,
        ),
        rules_backoff_max_ms: number(
            "SB_ROUTER_RULES_BACKOFF_MAX_MS",
            defaults.rules_backoff_max_ms,
        ),
        rules_require_default: bool_value(
            "SB_ROUTER_RULES_REQUIRE_DEFAULT",
            defaults.rules_require_default,
        ),
        suffix_strict: bool_value("SB_ROUTER_SUFFIX_STRICT", defaults.suffix_strict),
        suffix_trie: bool_value("SB_ROUTER_SUFFIX_TRIE", defaults.suffix_trie),
        hot_reload: bool_value("SB_ROUTER_HOT_RELOAD", defaults.hot_reload),
        decision_cache: bool_value("SB_ROUTER_DECISION_CACHE", defaults.decision_cache),
        decision_cache_capacity: number(
            "SB_ROUTER_DECISION_CACHE_CAP",
            defaults.decision_cache_capacity,
        ),
        decide_budget_ms: number("SB_ROUTER_DECIDE_BUDGET_MS", defaults.decide_budget_ms),
        dns_enabled: bool_value("SB_ROUTER_DNS", defaults.dns_enabled),
        dns_timeout_ms: number("SB_ROUTER_DNS_TIMEOUT_MS", defaults.dns_timeout_ms),
        dns_integration_timeout_ms: number(
            "SB_ROUTER_DNS_TIMEOUT_MS",
            defaults.dns_integration_timeout_ms,
        ),
        geoip_enabled: bool_value("SB_GEOIP_ENABLE", defaults.geoip_enabled),
        geoip_mmdb: string("SB_GEOIP_MMDB").map(PathBuf::from),
        geoip_cache_capacity: number("SB_GEOIP_CACHE", defaults.geoip_cache_capacity),
        geoip_ttl: Duration::from_secs(number("SB_GEOIP_TTL", defaults.geoip_ttl.as_secs())),
        udp_enabled: bool_value("SB_ROUTER_UDP", defaults.udp_enabled),
        udp_rules: string("SB_ROUTER_UDP_RULES"),
        runtime_override: string("SB_ROUTER_OVERRIDE"),
        domain_overrides: string("SB_ROUTER_DOMAIN_OVERRIDES"),
        default_proxy: string("SB_ROUTER_DEFAULT_PROXY"),
        default_proxy_kind: string("SB_ROUTER_DEFAULT_PROXY_KIND"),
        default_proxy_addr: string("SB_ROUTER_DEFAULT_PROXY_ADDR"),
        json_rules_enabled: bool_value("SB_ROUTER_RULES_FROM_JSON", defaults.json_rules_enabled),
        json_file: string("SB_ROUTER_JSON_FILE").map(PathBuf::from),
        json_text: string("SB_ROUTER_JSON_TEXT"),
        keyword_ac_min: number("SB_ROUTER_KEYWORD_AC_MIN", defaults.keyword_ac_min),
        explain_rebuild_ms: optional_number("SB_EXPLAIN_REBUILD_MS").filter(|value| *value > 0),
        rule_coverage: bool_value("SB_RULE_COVERAGE", defaults.rule_coverage),
        public_suffix_list: string("SB_PUBLIC_SUFFIX_LIST").map(PathBuf::from),
    }
}

fn network_options(ir: &sb_config::ir::ConfigIR) -> NetworkRuntimeOptions {
    let defaults = NetworkRuntimeOptions::default();
    NetworkRuntimeOptions {
        dial_timeout: Duration::from_millis(number(
            "SB_DIAL_TIMEOUT_MS",
            defaults.dial_timeout.as_millis() as u64,
        )),
        dial_use_all: bool_value("SB_DIAL_USE_ALL", defaults.dial_use_all),
        udp_ttl: Duration::from_millis(number(
            "SB_UDP_TTL_MS",
            defaults.udp_ttl.as_millis() as u64,
        )),
        udp_gc_interval: Duration::from_millis(number(
            "SB_UDP_GC_MS",
            defaults.udp_gc_interval.as_millis() as u64,
        )),
        udp_nat_max: number("SB_UDP_NAT_MAX", defaults.udp_nat_max),
        udp_outbound_bytes_per_second: number(
            "SB_UDP_OUTBOUND_BPS_MAX",
            defaults.udp_outbound_bytes_per_second,
        ),
        udp_outbound_packets_per_second: number(
            "SB_UDP_OUTBOUND_PPS_MAX",
            defaults.udp_outbound_packets_per_second,
        ),
        inbound_rate_limit_per_ip: number(
            "SB_INBOUND_RATE_LIMIT_PER_IP",
            defaults.inbound_rate_limit_per_ip,
        ),
        inbound_rate_limit_window: Duration::from_secs(number(
            "SB_INBOUND_RATE_LIMIT_WINDOW_SEC",
            defaults.inbound_rate_limit_window.as_secs(),
        )),
        inbound_rate_limit_qps: optional_number("SB_INBOUND_RATE_LIMIT_QPS"),
        socks_udp_resolve_bound: bool_value(
            "SB_SOCKS_UDP_RESOLVE_BND",
            defaults.socks_udp_resolve_bound,
        ),
        tcp_proxy_mode: string("SB_TCP_PROXY_MODE"),
        tcp_proxy_http: string("SB_TCP_PROXY_HTTP"),
        tcp_proxy_timeout: Duration::from_millis(number(
            "SB_TCP_PROXY_TIMEOUT_MS",
            defaults.tcp_proxy_timeout.as_millis() as u64,
        )),
        buffer_pool_size: number("SB_BUFFER_POOL_SIZE", defaults.buffer_pool_size),
        buffer_pool_max_capacity: number(
            "SB_BUFFER_POOL_MAX_CAPACITY",
            defaults.buffer_pool_max_capacity,
        ),
        transport_sni_fallback: bool_value(
            "SB_TRANSPORT_SNI_FALLBACK",
            defaults.transport_sni_fallback,
        ),
        network_strategy: ir
            .route
            .network_strategy
            .clone()
            .or_else(|| string("SB_NETWORK_STRATEGY")),
    }
}

fn service_options() -> ServiceRuntimeOptions {
    let defaults = ServiceRuntimeOptions::default();
    ServiceRuntimeOptions {
        health_enabled: present("SB_HEALTH_ENABLE"),
        proxy_health_enabled: bool_value("SB_PROXY_HEALTH_ENABLE", defaults.proxy_health_enabled),
        proxy_health_interval: Duration::from_millis(number(
            "SB_PROXY_HEALTH_INTERVAL_MS",
            defaults.proxy_health_interval.as_millis() as u64,
        )),
        proxy_health_timeout: Duration::from_millis(number(
            "SB_PROXY_HEALTH_TIMEOUT_MS",
            defaults.proxy_health_timeout.as_millis() as u64,
        )),
        ntp_server: string("SB_NTP_SERVER").unwrap_or(defaults.ntp_server),
        ntp_interval: Duration::from_secs(number(
            "SB_NTP_INTERVAL_S",
            defaults.ntp_interval.as_secs(),
        )),
        ntp_timeout: Duration::from_millis(number(
            "SB_NTP_TIMEOUT_MS",
            defaults.ntp_timeout.as_millis() as u64,
        )),
        circuit_breaker_enabled: bool_value("SB_CB_ENABLE", defaults.circuit_breaker_enabled),
        runtime_diff: bool_value("SB_RUNTIME_DIFF", defaults.runtime_diff),
    }
}

fn debug_options() -> DebugRuntimeOptions {
    let defaults = DebugRuntimeOptions::default();
    DebugRuntimeOptions {
        access_log: bool_value("SB_ACCESS_LOG", defaults.access_log),
        failpoints: string("SB_FAILPOINTS"),
        admin_max_header_bytes: number(
            "SB_ADMIN_MAX_HEADER_BYTES",
            defaults.admin_max_header_bytes,
        ),
        admin_max_body_bytes: number("SB_ADMIN_MAX_BODY_BYTES", defaults.admin_max_body_bytes),
        admin_first_byte_timeout: Duration::from_millis(number(
            "SB_ADMIN_FIRSTBYTE_TIMEOUT_MS",
            defaults.admin_first_byte_timeout.as_millis() as u64,
        )),
        admin_first_line_timeout: Duration::from_millis(number(
            "SB_ADMIN_FIRSTLINE_TIMEOUT_MS",
            defaults.admin_first_line_timeout.as_millis() as u64,
        )),
        admin_read_timeout: Duration::from_millis(number(
            "SB_ADMIN_READ_TIMEOUT_MS",
            defaults.admin_read_timeout.as_millis() as u64,
        )),
        admin_write_timeout: Duration::from_millis(number(
            "SB_ADMIN_WRITE_TIMEOUT_MS",
            defaults.admin_write_timeout.as_millis() as u64,
        )),
        admin_max_connections_per_ip: number(
            "SB_ADMIN_MAX_CONN_PER_IP",
            defaults.admin_max_connections_per_ip,
        ),
        admin_max_requests_per_second_per_ip: number(
            "SB_ADMIN_MAX_RPS_PER_IP",
            defaults.admin_max_requests_per_second_per_ip,
        ),
    }
}

#[must_use]
pub fn failpoint_config() -> Option<String> {
    string("SB_FAILPOINTS")
}

#[must_use]
pub fn load(ir: &sb_config::ir::ConfigIR) -> Arc<CoreRuntimeOptions> {
    Arc::new(CoreRuntimeOptions {
        dns: dns_options(),
        router: router_options(),
        network: network_options(ir),
        services: service_options(),
        debug: debug_options(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_is_sorted_and_unique() {
        assert!(CORE_ENV_KEYS.windows(2).all(|pair| pair[0] < pair[1]));
    }

    #[test]
    fn parser_empty_environment_matches_core_defaults() {
        let options = CoreRuntimeOptions::default();
        assert_eq!(dns_options().default_ttl_s, options.dns.default_ttl_s);
        assert_eq!(router_options().rules_max, options.router.rules_max);
        assert_eq!(service_options().ntp_timeout, options.services.ntp_timeout);
        assert_eq!(
            debug_options().admin_max_body_bytes,
            options.debug.admin_max_body_bytes
        );
    }
}
