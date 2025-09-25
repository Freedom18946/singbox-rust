// UDP metrics: provide a minimal API used by NAT and upstream code
// Placeholder metrics for future prometheus export - parameters may appear unused when metrics feature disabled
#![allow(clippy::unused_self, clippy::unused_io_amount)]
#![cfg_attr(
    any(test),
    allow(dead_code, unused_imports, unused_variables, unused_must_use)
)]

#[cfg(feature = "metrics")]
use metrics::{counter, gauge, histogram};

// NAT metrics compatible with earlier Prometheus-based registry registration
#[cfg(feature = "metrics")]
use prometheus::{Histogram, HistogramOpts, IntCounter, IntGauge, Opts};

#[cfg(feature = "metrics")]
use crate::metrics::registry_ext::{get_or_register_counter_vec, get_or_register_gauge_vec};

#[cfg(feature = "metrics")]
pub struct UdpNatMetrics {
    pub size_gauge: IntGauge,
    pub heap_len: IntGauge,
    pub evicted_total: prometheus::IntCounterVec,
    pub gen_mismatch: IntCounter,
    pub bytes_in: IntCounter,
    pub bytes_out: IntCounter,
    pub ttl_histogram: Histogram,
}

#[cfg(feature = "metrics")]
pub fn register_udp_nat_metrics() -> UdpNatMetrics {
    let reg = crate::metrics::registry();
    let size_gauge = IntGauge::with_opts(Opts::new(
        "udp_nat_size_prom",
        "Current UDP NAT map size (prometheus crate)",
    ))
    .unwrap();
    let heap_len = IntGauge::with_opts(Opts::new(
        "udp_nat_heap_len_prom",
        "UDP NAT heap length (prometheus crate)",
    ))
    .unwrap();
    let gen_mismatch = IntCounter::with_opts(Opts::new(
        "udp_nat_gen_mismatch_total_prom",
        "Heap gen mismatches (prometheus crate)",
    ))
    .unwrap();
    let bytes_in = IntCounter::with_opts(Opts::new(
        "udp_flow_bytes_in_total_prom",
        "UDP flow bytes in (prometheus crate)",
    ))
    .unwrap();
    let bytes_out = IntCounter::with_opts(Opts::new(
        "udp_flow_bytes_out_total_prom",
        "UDP flow bytes out (prometheus crate)",
    ))
    .unwrap();

    let ttl_histogram = Histogram::with_opts(HistogramOpts::new(
        "udp_nat_ttl_seconds",
        "UDP NAT session TTL in seconds",
    ))
    .unwrap();

    // Use registry_ext for evicted_total
    let evicted_total = udp_nat_evicted_total().clone();

    let _ = reg.register(Box::new(size_gauge.clone()));
    let _ = reg.register(Box::new(heap_len.clone()));
    let _ = reg.register(Box::new(gen_mismatch.clone()));
    let _ = reg.register(Box::new(bytes_in.clone()));
    let _ = reg.register(Box::new(bytes_out.clone()));
    let _ = reg.register(Box::new(ttl_histogram.clone()));
    UdpNatMetrics {
        size_gauge,
        heap_len,
        evicted_total,
        gen_mismatch,
        bytes_in,
        bytes_out,
        ttl_histogram,
    }
}

#[cfg(not(feature = "metrics"))]
pub struct UdpNatMetrics {}
#[cfg(not(feature = "metrics"))]
pub fn register_udp_nat_metrics() -> UdpNatMetrics {
    UdpNatMetrics {}
}

// Lightweight metrics crate helpers (used by runtime code)
pub fn set_nat_size(_size: usize) {
    #[cfg(feature = "metrics")]
    gauge!("udp_nat_size").set(_size as f64);
}

/// Set NAT entry gauges for observability
pub fn set_nat_entries(_alive: usize, _gc: usize) {
    #[cfg(feature = "metrics")]
    {
        gauge!("udp_nat_entries", "state" => "alive").set(_alive as f64);
        gauge!("udp_nat_entries", "state" => "gc").set(_gc as f64);
    }
}

pub enum EvictionReason {
    Ttl,
    Capacity,
    Replace,
}

pub fn record_nat_eviction(_reason: EvictionReason) {
    #[cfg(feature = "metrics")]
    {
        let r = match _reason {
            EvictionReason::Ttl => "ttl",
            EvictionReason::Capacity => "capacity",
            EvictionReason::Replace => "replace",
        };
        counter!("udp_nat_evicted_total", "reason" => r.to_string()).increment(1);
    }
}

pub fn inc_packets_in() {
    #[cfg(feature = "metrics")]
    counter!("udp_pkts_in_total").increment(1);
}
pub fn inc_packets_out() {
    #[cfg(feature = "metrics")]
    counter!("udp_pkts_out_total").increment(1);
}

pub enum UdpErrorClass {
    Io,
    Timeout,
    Upstream,
    Other,
}
pub fn record_upstream_failure(class: UdpErrorClass) {
    #[cfg(feature = "metrics")]
    {
        let c = match class {
            UdpErrorClass::Io => "io",
            UdpErrorClass::Timeout => "timeout",
            UdpErrorClass::Upstream => "upstream",
            UdpErrorClass::Other => "other",
        };
        counter!("udp_upstream_error_total", "class" => c.to_string()).increment(1);
    }
}

pub fn record_flow_bytes(_dir: &str, _n: usize) {
    #[cfg(feature = "metrics")]
    match _dir {
        "in" => counter!("udp_flow_bytes_in_total").increment(_n as u64),
        _ => counter!("udp_flow_bytes_out_total").increment(_n as u64),
    }
}

pub fn record_session_ttl(_ttl_seconds: f64) {
    #[cfg(feature = "metrics")]
    histogram!("udp_nat_ttl_seconds").record(_ttl_seconds);
}

// Helper functions using registry_ext
#[cfg(feature = "metrics")]
pub fn udp_nat_size_gauge() -> &'static prometheus::IntGaugeVec {
    get_or_register_gauge_vec("udp_nat_size_gauge", "udp nat size", &["shard"])
}

#[cfg(feature = "metrics")]
pub fn udp_nat_evicted_total() -> &'static prometheus::IntCounterVec {
    get_or_register_counter_vec("udp_nat_evicted_total", "udp nat evicted", &["reason"])
}

pub fn register_metrics() {
    // no-op; metrics are created by macros on use
}
