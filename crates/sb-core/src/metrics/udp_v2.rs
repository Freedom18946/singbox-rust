#[cfg(feature = "metrics")]
use prometheus::{IntCounter, IntCounterVec, IntGauge, Opts};

#[cfg(feature = "metrics")]
pub struct UdpNatMetrics {
    pub size_gauge: IntGauge,
    pub heap_len: IntGauge,
    pub evicted_total: IntCounterVec,
    pub gen_mismatch: IntCounter,
    pub bytes_in: IntCounter,
    pub bytes_out: IntCounter,
}

#[cfg(feature = "metrics")]
pub fn register_udp_nat_metrics() -> UdpNatMetrics {
    let reg = crate::metrics::registry();
    let size_gauge =
        IntGauge::with_opts(Opts::new("udp_nat_size", "Current UDP NAT map size")).unwrap();
    let heap_len =
        IntGauge::with_opts(Opts::new("udp_nat_heap_len", "UDP NAT heap length")).unwrap();
    let evicted_total = IntCounterVec::new(
        Opts::new("udp_nat_evicted_total", "UDP NAT evictions"),
        &["reason"],
    )
    .unwrap();
    let gen_mismatch = IntCounter::with_opts(Opts::new(
        "udp_nat_gen_mismatch_total",
        "Heap gen mismatches",
    ))
    .unwrap();
    let bytes_in =
        IntCounter::with_opts(Opts::new("udp_flow_bytes_in_total", "UDP flow bytes in")).unwrap();
    let bytes_out =
        IntCounter::with_opts(Opts::new("udp_flow_bytes_out_total", "UDP flow bytes out")).unwrap();
    reg.register(Box::new(size_gauge.clone())).ok();
    reg.register(Box::new(heap_len.clone())).ok();
    reg.register(Box::new(evicted_total.clone())).ok();
    reg.register(Box::new(gen_mismatch.clone())).ok();
    reg.register(Box::new(bytes_in.clone())).ok();
    reg.register(Box::new(bytes_out.clone())).ok();
    UdpNatMetrics {
        size_gauge,
        heap_len,
        evicted_total,
        gen_mismatch,
        bytes_in,
        bytes_out,
    }
}

#[cfg(not(feature = "metrics"))]
pub struct UdpNatMetrics {}
#[cfg(not(feature = "metrics"))]
pub fn register_udp_nat_metrics() -> UdpNatMetrics {
    UdpNatMetrics {}
}
