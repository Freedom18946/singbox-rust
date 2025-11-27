//! Prometheus metrics for rate limiting
//!
//! Provides observability into rate limiting behavior across inbound protocols.

use once_cell::sync::Lazy;
use prometheus::{register_int_counter_vec, register_int_gauge_vec, IntCounterVec, IntGaugeVec};

/// Counter for rate-limited connections
/// Labels: protocol (trojan, shadowsocks, etc.), reason (connection_limit, auth_failure_ban)
pub static RATE_LIMITED_TOTAL: Lazy<IntCounterVec> = Lazy::new(|| {
    register_int_counter_vec!(
        "sb_inbound_rate_limited_total",
        "Total number of rate-limited inbound connections",
        &["protocol", "reason"]
    )
    .unwrap()
});

/// Counter for authentication failures
/// Labels: protocol
pub static AUTH_FAILURES_TOTAL: Lazy<IntCounterVec> = Lazy::new(|| {
    register_int_counter_vec!(
        "sb_inbound_auth_failures_total",
        "Total number of authentication failures",
        &["protocol"]
    )
    .unwrap()
});

/// Gauge for active connections
/// Labels: protocol
pub static ACTIVE_CONNECTIONS: Lazy<IntGaugeVec> = Lazy::new(|| {
    register_int_gauge_vec!(
        "sb_inbound_active_connections",
        "Number of active inbound connections",
        &["protocol"]
    )
    .unwrap()
});

/// Record a rate-limited connection
#[inline]
pub fn record_rate_limited(protocol: &str, reason: &str) {
    RATE_LIMITED_TOTAL
        .with_label_values(&[protocol, reason])
        .inc();
}

/// Record an authentication failure
#[inline]
pub fn record_auth_failure(protocol: &str) {
    AUTH_FAILURES_TOTAL.with_label_values(&[protocol]).inc();
}

/// Increment active connections counter
#[inline]
pub fn inc_active_connections(protocol: &str) {
    ACTIVE_CONNECTIONS.with_label_values(&[protocol]).inc();
}

/// Decrement active connections counter
#[inline]
pub fn dec_active_connections(protocol: &str) {
    ACTIVE_CONNECTIONS.with_label_values(&[protocol]).dec();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metrics_recording() {
        // Record some metrics
        record_rate_limited("trojan", "connection_limit");
        record_rate_limited("shadowsocks", "auth_failure_ban");
        record_auth_failure("trojan");
        inc_active_connections("shadowsocks");
        inc_active_connections("shadowsocks");
        dec_active_connections("shadowsocks");

        // Verify metrics are reachable (actual values tested in integration tests)
        let rate_limited = RATE_LIMITED_TOTAL
            .with_label_values(&["trojan", "connection_limit"])
            .get();
        assert!(rate_limited >= 1);

        let auth_failures = AUTH_FAILURES_TOTAL.with_label_values(&["trojan"]).get();
        assert!(auth_failures >= 1);

        let active = ACTIVE_CONNECTIONS.with_label_values(&["shadowsocks"]).get();
        assert!(active >= 1);
    }
}
