//! Inbound metrics: unified error counter per protocol with class labels.
use crate::{guarded_counter_vec, IntCounterVec, LazyLock, REGISTRY};

/// inbound_error_total{protocol,class}
pub static INBOUND_ERROR_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    let v = guarded_counter_vec(
        "inbound_error_total",
        "Inbound errors total by protocol and class",
        &["protocol", "class"],
    );
    REGISTRY.register(Box::new(v.clone())).ok();
    v
});

/// Increment inbound_error_total with explicit class label
pub fn record_error(protocol: &str, class: &str) {
    INBOUND_ERROR_TOTAL
        .with_label_values(&[protocol, class])
        .inc();
}

/// Best-effort classification from Display text (duplicated lightweight heuristic)
pub fn record_error_display(protocol: &str, e: &dyn core::fmt::Display) {
    let s = e.to_string().to_ascii_lowercase();
    let class = if s.contains("timeout") || s.contains("timed out") || s.contains("deadline") {
        "timeout"
    } else if s.contains("dns") || s.contains("resolve") || s.contains("nxdomain") {
        "dns"
    } else if s.contains("tls") || s.contains("certificate") || s.contains("handshake") {
        "tls"
    } else if s.contains("auth") || s.contains("unauthorized") || s.contains("forbidden") {
        "auth"
    } else if s.contains("protocol") || s.contains("invalid") || s.contains("decode") {
        "protocol"
    } else if s.contains("conn") || s.contains("refused") || s.contains("unreachable")
        || s.contains("broken pipe") || s.contains("reset")
    {
        "io"
    } else {
        "other"
    };
    record_error(protocol, class);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registers_and_exports() {
        // Emit one sample error and ensure it appears in Prometheus text
        record_error("http", "protocol");
        record_error_display("http", &"timeout while reading".to_string());
        let text = crate::export_prometheus();
        assert!(text.contains("inbound_error_total"));
    }
}
