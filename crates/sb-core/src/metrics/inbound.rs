//! Inbound metrics helpers (WS7)
//!
//! Provides a unified counter for inbound errors across protocols, with
//! standardized error-class mapping and a stable label set.

/// Register all inbound-related metrics (no-op: sb-metrics owns Prom registry)
pub fn register_metrics() {}

/// Increment inbound error counter for a given protocol and class label.
/// Delegates to sb-metrics so it appears under the HTTP exporter.
pub fn record_error(protocol: &str, class: &str) {
    sb_metrics::inbound::record_error(protocol, class);
}

/// Convenience: classify an error and record it for the given protocol.
pub fn record_error_display(protocol: &str, e: &dyn core::fmt::Display) {
    use crate::metrics::error_class::classify_display;
    let ec = classify_display(e);
    sb_metrics::inbound::record_error(protocol, ec.as_label());
}

/// Set active inbound connections for a protocol
/// Emits metrics only when the `metrics` feature is enabled.
#[cfg_attr(not(feature = "metrics"), allow(unused_variables))]
pub fn set_active_connections(protocol: &str, count: u64) {
    #[cfg(feature = "metrics")]
    {
        metrics::gauge!("inbound_active_connections", "protocol" => protocol.to_string())
            .set(count as f64);
    }
}
