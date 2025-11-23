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
    .expect("Failed to create udp_nat_size_prom gauge");
    let heap_len = IntGauge::with_opts(Opts::new(
        "udp_nat_heap_len_prom",
        "UDP NAT heap length (prometheus crate)",
    ))
    .expect("Failed to create udp_nat_heap_len_prom gauge");
    let gen_mismatch = IntCounter::with_opts(Opts::new(
        "udp_nat_gen_mismatch_total_prom",
        "Heap gen mismatches (prometheus crate)",
    ))
    .expect("Failed to create udp_nat_gen_mismatch_total_prom counter");
    let bytes_in = IntCounter::with_opts(Opts::new(
        "udp_flow_bytes_in_total_prom",
        "UDP flow bytes in (prometheus crate)",
    ))
    .expect("Failed to create udp_flow_bytes_in_total_prom counter");
    let bytes_out = IntCounter::with_opts(Opts::new(
        "udp_flow_bytes_out_total_prom",
        "UDP flow bytes out (prometheus crate)",
    ))
    .expect("Failed to create udp_flow_bytes_out_total_prom counter");

    let ttl_histogram = Histogram::with_opts(HistogramOpts::new(
        "udp_nat_ttl_seconds",
        "UDP NAT session TTL in seconds",
    ))
    .expect("Failed to create udp_nat_ttl_seconds histogram");

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
    Timeout,
    Io,
    Decode,
    NoRoute,
    Canceled,
    Other,
}
pub fn record_upstream_failure(_class: UdpErrorClass) {
    #[cfg(feature = "metrics")]
    {
        use crate::metrics::registry_ext::get_or_register_counter_vec;
        let class = _class;
        let c = match class {
            UdpErrorClass::Timeout => "timeout",
            UdpErrorClass::Io => "io",
            UdpErrorClass::Decode => "decode",
            UdpErrorClass::NoRoute => "no_route",
            UdpErrorClass::Canceled => "canceled",
            UdpErrorClass::Other => "other",
        };
        let cv = get_or_register_counter_vec(
            "udp_upstream_fail_total",
            "udp upstream failure total",
            &["class"],
        );
        cv.with_label_values(&[c]).inc();
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

// Convenience functions for common UDP failure scenarios
pub fn record_timeout_failure() {
    record_upstream_failure(UdpErrorClass::Timeout);
}

pub fn record_io_failure() {
    record_upstream_failure(UdpErrorClass::Io);
}

pub fn record_decode_failure() {
    record_upstream_failure(UdpErrorClass::Decode);
}

pub fn record_no_route_failure() {
    record_upstream_failure(UdpErrorClass::NoRoute);
}

pub fn record_canceled_failure() {
    record_upstream_failure(UdpErrorClass::Canceled);
}

pub fn record_other_failure() {
    record_upstream_failure(UdpErrorClass::Other);
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

/// Convenience: record UDP upstream failure from a Display error using heuristic classification
pub fn record_error_display(e: &dyn core::fmt::Display) {
    let s = e.to_string().to_ascii_lowercase();
    let class = if s.contains("timeout") || s.contains("timed out") {
        UdpErrorClass::Timeout
    } else if s.contains("decode")
        || s.contains("invalid")
        || s.contains("bad")
        || s.contains("parse")
    {
        UdpErrorClass::Decode
    } else if s.contains("canceled") || s.contains("cancelled") {
        UdpErrorClass::Canceled
    } else if s.contains("no route") || s.contains("unreachable") {
        UdpErrorClass::NoRoute
    } else if s.contains("io")
        || s.contains("connection")
        || s.contains("refused")
        || s.contains("send")
        || s.contains("recv")
    {
        UdpErrorClass::Io
    } else {
        UdpErrorClass::Other
    };
    record_upstream_failure(class);
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "metrics")]
    use prometheus::Encoder;

    #[test]
    fn upstream_failure_counts_with_class() {
        record_upstream_failure(UdpErrorClass::Timeout);
        #[cfg(feature = "metrics")]
        {
            let mfs = crate::metrics::registry().gather();
            let mut buf = Vec::new();
            prometheus::TextEncoder::new()
                .encode(&mfs, &mut buf)
                .expect("encode");
            let s = String::from_utf8(buf).unwrap();
            assert!(s.contains("udp_upstream_fail_total"));
            assert!(s.contains("class=\"timeout\""));
        }
    }
}
