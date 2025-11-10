//! Comprehensive Metrics System
//!
//! This module provides a unified metrics system for all components:
//! - HTTP inbound metrics (response codes, connection timing)
//! - Outbound connection metrics (attempts, errors, duration)
//! - UDP NAT metrics (table size, evictions, flow tracking)
//! - DNS metrics (queries, errors, cache performance)

pub mod dns;
pub mod dns_v2;
pub mod geoip;
pub mod http;
pub mod http_exporter;
pub mod labels;
pub mod error_class;
pub mod label_guard;
pub mod inbound;
pub mod outbound;
pub mod udp;
pub mod udp_v2;

#[cfg(feature = "metrics")]
pub fn registry() -> &'static prometheus::Registry {
    use once_cell::sync::OnceCell;
    static REGISTRY: OnceCell<prometheus::Registry> = OnceCell::new();
    REGISTRY.get_or_init(prometheus::Registry::new)
}

#[cfg(feature = "metrics")]
pub mod registry_ext;

/// Start-of-life prewarm to avoid empty /metrics on fresh boot.
#[cfg(feature = "metrics")]
pub fn prewarm_build_info() {
    use prometheus::{GaugeVec, Opts};
    use std::sync::Once;
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        // Prometheus crate gauge (kept for compatibility — no-op without custom exporter)
        let reg = registry();
        let gv = GaugeVec::new(
            Opts::new("sb_build_info", "singbox-rust build info"),
            &["version", "features"],
        )
        .expect("gaugevec");
        let _ = reg.register(Box::new(gv.clone()));
        let ver = env!("CARGO_PKG_VERSION");
        gv.with_label_values(&[ver, "compiled"]).set(1.0);

        // Also emit via `metrics` crate so metrics-exporter-prometheus exposes it
        let lbls = [
            metrics::Label::new("version", ver),
            metrics::Label::new("features", "compiled"),
        ];
        metrics::gauge!("sb_build_info", lbls.iter()).set(1.0);

        // metrics crate 栈也写一笔，确保 exporter 侧非空
        metrics::gauge!("sb_build_info_gauge").set(1.0);

        // 启动 uptime 刷新
        tokio::spawn(async move {
            let start = std::time::Instant::now();
            loop {
                let secs = start.elapsed().as_secs_f64();
                metrics::gauge!("sb_uptime_seconds").set(secs);
                tokio::time::sleep(std::time::Duration::from_secs(10)).await;
            }
        });
    });
}

/// Initialize and register all metrics
pub fn register_all_metrics() {
    http::register_metrics();
    inbound::register_metrics();
    outbound::register_metrics();
    udp::register_metrics();
    dns::register_metrics();
}

/// Re-export commonly used metric recording functions
pub use http::{
    inc_405_responses, inc_requests as inc_http_requests,
    record_connect_duration as record_http_duration, record_error as record_http_error,
    set_active_connections as set_http_active_connections,
};

pub use outbound::{
    record_connect_attempt, record_connect_duration as record_outbound_duration,
    record_connect_error, record_connect_failure, record_connect_success, OutboundErrorClass,
    OutboundKind, set_circuit_state as set_outbound_circuit_state,
};

pub use udp::{
    inc_packets_in as inc_udp_packets_in, inc_packets_out as inc_udp_packets_out,
    record_flow_bytes as record_udp_flow_bytes, record_nat_eviction,
    record_upstream_failure as record_udp_upstream_failure, set_nat_size, EvictionReason,
    UdpErrorClass,
};

pub use dns::{
    record_cache_hit, record_cache_miss, record_error as record_dns_error,
    record_failed_query as record_dns_failure, record_query as record_dns_query,
    record_rtt as record_dns_rtt, record_successful_query as record_dns_success,
    set_cache_size as set_dns_cache_size, DnsErrorClass, DnsQueryType,
};

pub use error_class::{classify_display as classify_error, record_outbound_error, ErrorClass};
pub use inbound::{record_error as record_inbound_error, record_error_display as record_inbound_error_display};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metrics_registration() {
        // Test that all metrics can be registered without panicking
        register_all_metrics();
    }
}
