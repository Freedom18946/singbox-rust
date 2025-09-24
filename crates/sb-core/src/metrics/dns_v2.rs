#[cfg(feature = "metrics")]
use prometheus::{IntCounterVec, Opts};

#[cfg(feature = "metrics")]
pub struct DnsCacheMetrics {
    pub hit_total: IntCounterVec,         // {kind=pos|neg}
    pub store_total: IntCounterVec,       // {kind=pos|neg}
    pub ttl_clamped_total: IntCounterVec, // {dir=up|down}
}

#[cfg(feature = "metrics")]
pub fn register_dns_cache_metrics() -> DnsCacheMetrics {
    let reg = crate::metrics::registry();
    let hit_total =
        IntCounterVec::new(Opts::new("dns_cache_hit_total", "DNS cache hit"), &["kind"]).unwrap();
    let store_total = IntCounterVec::new(
        Opts::new("dns_cache_store_total", "DNS cache store"),
        &["kind"],
    )
    .unwrap();
    let ttl_clamped_total = IntCounterVec::new(
        Opts::new("dns_cache_ttl_clamped_total", "TTL clamped"),
        &["dir"],
    )
    .unwrap();
    reg.register(Box::new(hit_total.clone())).ok();
    reg.register(Box::new(store_total.clone())).ok();
    reg.register(Box::new(ttl_clamped_total.clone())).ok();
    DnsCacheMetrics {
        hit_total,
        store_total,
        ttl_clamped_total,
    }
}

#[cfg(not(feature = "metrics"))]
pub struct DnsCacheMetrics {}
#[cfg(not(feature = "metrics"))]
pub fn register_dns_cache_metrics() -> DnsCacheMetrics {
    DnsCacheMetrics {}
}
