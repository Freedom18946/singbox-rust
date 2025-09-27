// DNS metrics helpers + enums used by DNS client/transport. Provide both
// metrics-crate increments and optional Prometheus registry for cache metrics.
#![cfg_attr(
    any(test),
    allow(dead_code, unused_imports, unused_variables, unused_must_use)
)]

#[cfg(feature = "metrics")]
use crate::metrics::registry_ext::{
    get_or_register_counter_vec,
    get_or_register_gauge_vec_f64,
    get_or_register_histogram_vec,
};
#[cfg(feature = "metrics")]
use metrics::counter;

#[derive(Clone, Copy, Debug)]
pub enum DnsQueryType {
    A,
    AAAA,
    Other,
}
impl DnsQueryType {
    pub fn from_u16(v: u16) -> Self {
        match v {
            1 => Self::A,
            28 => Self::AAAA,
            _ => Self::Other,
        }
    }
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::A => "A",
            Self::AAAA => "AAAA",
            Self::Other => "OTHER",
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub enum DnsErrorClass {
    Timeout,
    NameError,
    NetworkError,
    Other,
}
impl DnsErrorClass {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Timeout => "timeout",
            Self::NameError => "name_error",
            Self::NetworkError => "network_error",
            Self::Other => "other",
        }
    }
    pub fn from_error_str(s: &str) -> Self {
        let ls = s.to_ascii_lowercase();
        if ls.contains("timeout") {
            Self::Timeout
        } else if ls.contains("nxdomain") || ls.contains("name") {
            Self::NameError
        } else if ls.contains("network") || ls.contains("unreachable") {
            Self::NetworkError
        } else {
            Self::Other
        }
    }
}

pub fn record_query(_q: DnsQueryType) {
    #[cfg(feature = "metrics")]
    {
        let cv = get_or_register_counter_vec("dns_query_total", "DNS queries", &["qtype"]);
        cv.with_label_values(&[_q.as_str()]).inc();
    }
}
pub fn record_rtt(_rtt_ms: f64) {
    #[cfg(feature = "metrics")]
    {
        let hv = get_or_register_histogram_vec("dns_rtt_ms", "DNS RTT (ms)", &[], None);
        hv.with_label_values(&[]).observe(_rtt_ms);
    }
}
pub fn record_error(_c: DnsErrorClass) {
    #[cfg(feature = "metrics")]
    {
        let cv = get_or_register_counter_vec("dns_error_total", "DNS errors", &["kind"]);
        cv.with_label_values(&[_c.as_str()]).inc();
    }
}

pub fn record_cache_hit() {
    #[cfg(feature = "metrics")]
    counter!("dns_cache_hit_total").increment(1);
}
pub fn record_cache_miss() {
    #[cfg(feature = "metrics")]
    counter!("dns_cache_miss_total").increment(1);
}
pub fn set_cache_size(_size: usize) {
    #[cfg(feature = "metrics")]
    {
        let gv = get_or_register_gauge_vec_f64("dns_cache_size", "DNS cache size", &[]);
        gv.with_label_values(&[]).set(_size as f64);
    }
}
pub fn record_successful_query(_q: DnsQueryType, _rtt_ms: f64, _from_cache: bool) {
    #[cfg(feature = "metrics")]
    {
        let cv = get_or_register_counter_vec(
            "dns_success_total",
            "DNS successful queries",
            &["qtype", "from_cache"],
        );
        let from_cache = if _from_cache { "1" } else { "0" };
        cv.with_label_values(&[_q.as_str(), from_cache]).inc();
        let hv = get_or_register_histogram_vec("dns_rtt_ms", "DNS RTT (ms)", &[], None);
        hv.with_label_values(&[]).observe(_rtt_ms);
    }
}
pub fn record_failed_query(_q: DnsQueryType, _class: DnsErrorClass) {
    #[cfg(feature = "metrics")]
    {
        let cv = get_or_register_counter_vec(
            "dns_failed_total",
            "DNS failed queries",
            &["qtype", "class"],
        );
        cv.with_label_values(&[_q.as_str(), _class.as_str()]).inc();
    }
}

pub fn register_metrics() {
    // no-op: metrics crate uses lazy counters
}

// Optional Prometheus registry for cache metrics (legacy experiments)
#[cfg(feature = "metrics")]
use prometheus::IntCounterVec;



#[cfg(feature = "metrics")]
pub fn dns_query_total() -> &'static prometheus::IntCounterVec {
    get_or_register_counter_vec("dns_query_total", "DNS queries", &["qtype"])
}

#[cfg(feature = "metrics")]
pub fn dns_error_total() -> &'static prometheus::IntCounterVec {
    get_or_register_counter_vec("dns_error_total", "DNS errors", &["kind"])
}

#[cfg(feature = "metrics")]
pub fn dns_cache_hit_total() -> &'static prometheus::IntCounterVec {
    get_or_register_counter_vec(
        "dns_cache_hit_total_prom",
        "DNS cache hit (prometheus crate)",
        &["kind"],
    )
}

#[cfg(feature = "metrics")]
pub fn dns_cache_store_total() -> &'static prometheus::IntCounterVec {
    get_or_register_counter_vec(
        "dns_cache_store_total_prom",
        "DNS cache store (prometheus crate)",
        &["kind"],
    )
}

#[cfg(feature = "metrics")]
pub fn dns_cache_ttl_clamped_total() -> &'static prometheus::IntCounterVec {
    get_or_register_counter_vec(
        "dns_cache_ttl_clamped_total_prom",
        "TTL clamped (prometheus crate)",
        &["dir"],
    )
}

#[cfg(feature = "metrics")]
pub struct DnsCacheMetrics {
    pub hit_total: IntCounterVec,         // {kind=pos|neg}
    pub store_total: IntCounterVec,       // {kind=pos|neg}
    pub ttl_clamped_total: IntCounterVec, // {dir=up|down}
}

#[cfg(feature = "metrics")]
pub fn register_dns_cache_metrics() -> DnsCacheMetrics {
    DnsCacheMetrics {
        hit_total: dns_cache_hit_total().clone(),
        store_total: dns_cache_store_total().clone(),
        ttl_clamped_total: dns_cache_ttl_clamped_total().clone(),
    }
}

#[cfg(not(feature = "metrics"))]
pub struct DnsCacheMetrics {}
#[cfg(not(feature = "metrics"))]
pub fn register_dns_cache_metrics() -> DnsCacheMetrics {
    DnsCacheMetrics {}
}
