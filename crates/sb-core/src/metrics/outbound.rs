// Minimal outbound metrics API used across the codebase.
// Implemented with metrics crate (when enabled) and no-op otherwise.
#![cfg_attr(
    any(test),
    allow(dead_code, unused_imports, unused_variables, unused_must_use)
)]

#[cfg(feature = "metrics")]
use crate::metrics::registry_ext::{
    get_or_register_counter_vec, get_or_register_gauge_vec, get_or_register_histogram_vec,
};
#[cfg(feature = "metrics")]
use metrics::{counter, histogram};

// Reuse the real outbound kind type to avoid duplicate definitions
pub use crate::outbound::OutboundKind;

// Error classification for outbound operations
#[derive(Clone, Copy, Debug)]
pub enum OutboundErrorClass {
    Timeout,
    Io,
    Handshake,
    Protocol,
    Other,
}

#[cfg(any(test, feature = "dev-cli", feature = "metrics"))]
#[deprecated(since = "0.1.0", note = "preserved for JSON contract/future export")]
fn label_kind(k: OutboundKind) -> &'static str {
    match k {
        OutboundKind::Direct => "direct",
        OutboundKind::Socks => "socks5",
        OutboundKind::Http => "http",
        OutboundKind::Block => "block",
        #[cfg(feature = "out_trojan")]
        OutboundKind::Trojan => "trojan",
        #[cfg(feature = "out_ss")]
        OutboundKind::Shadowsocks => "shadowsocks",
        #[cfg(feature = "out_shadowtls")]
        OutboundKind::ShadowTls => "shadowtls",
        #[cfg(feature = "out_naive")]
        OutboundKind::Naive => "naive",
        #[cfg(feature = "out_vless")]
        OutboundKind::Vless => "vless",
        #[cfg(feature = "out_vmess")]
        OutboundKind::Vmess => "vmess",
        #[cfg(feature = "out_tuic")]
        OutboundKind::Tuic => "tuic",
        #[cfg(feature = "out_hysteria2")]
        OutboundKind::Hysteria2 => "hysteria2",
        #[cfg(feature = "out_wireguard")]
        OutboundKind::WireGuard => "wireguard",
        #[cfg(feature = "out_ssh")]
        OutboundKind::Ssh => "ssh",
    }
}

#[cfg(any(test, feature = "dev-cli", feature = "metrics"))]
#[deprecated(since = "0.1.0", note = "preserved for JSON contract/future export")]
fn label_err(c: OutboundErrorClass) -> &'static str {
    match c {
        OutboundErrorClass::Timeout => "timeout",
        OutboundErrorClass::Io => "io",
        OutboundErrorClass::Handshake => "handshake",
        OutboundErrorClass::Protocol => "protocol",
        OutboundErrorClass::Other => "other",
    }
}

pub fn register_metrics() {
    // no-op; metrics are on-demand by macros
}

pub fn record_connect_attempt(_kind: OutboundKind) {
    #[cfg(feature = "metrics")]
    {
        let kind = _kind;
        let cv = get_or_register_counter_vec(
            "outbound_connect_total",
            "outbound connect attempts/results",
            &["kind", "result"],
        );
        #[allow(deprecated)] // 使用已弃用函数以维护JSON合约兼容性
        cv.with_label_values(&[label_kind(kind), "attempt"]).inc();
    }
}

pub fn record_connect_success(_kind: OutboundKind) {
    #[cfg(feature = "metrics")]
    {
        let kind = _kind;
        let cv = get_or_register_counter_vec(
            "outbound_connect_total",
            "outbound connect attempts/results",
            &["kind", "result"],
        );
        #[allow(deprecated)] // 使用已弃用函数以维护JSON合约兼容性
        cv.with_label_values(&[label_kind(kind), "success"]).inc();
    }
}

pub fn record_connect_failure(_kind: OutboundKind) {
    #[cfg(feature = "metrics")]
    {
        let kind = _kind;
        let cv = get_or_register_counter_vec(
            "outbound_connect_total",
            "outbound connect attempts/results",
            &["kind", "result"],
        );
        #[allow(deprecated)] // 使用已弃用函数以维护JSON合约兼容性
        cv.with_label_values(&[label_kind(kind), "failure"]).inc();
    }
}

pub fn record_connect_error(_kind: OutboundKind, _class: OutboundErrorClass) {
    #[cfg(feature = "metrics")]
    {
        let kind = _kind;
        let class = _class;
        let cv = get_or_register_counter_vec(
            "outbound_connect_error_total",
            "outbound connect error total",
            &["kind", "class"],
        );
        #[allow(deprecated)] // 使用已弃用函数以维护JSON合约兼容性
        cv.with_label_values(&[label_kind(kind), label_err(class)])
            .inc();
    }
}

pub fn record_connect_duration(_duration_ms: f64) {
    #[cfg(feature = "metrics")]
    {
        // If kind is needed per instruction, callers should provide it via kind-specific histograms.
        let hv = get_or_register_histogram_vec(
            "outbound_connect_duration_ms",
            "outbound connect duration (ms)",
            &[],
            None,
        );
        hv.with_label_values(&[]).observe(_duration_ms);
    }
}

// P3 selector Prometheus-export style (kept for compatibility with earlier experiments)
#[cfg(feature = "metrics")]
use prometheus::{GaugeVec, IntCounterVec};

#[cfg(feature = "metrics")]
pub struct SelectorMetrics {
    pub score: GaugeVec,              // proxy_select_score{outbound}
    pub switch_total: IntCounterVec,  // proxy_select_switch_total{reason}
    pub explore_total: IntCounterVec, // proxy_select_explore_total{mode}
}

// (imports consolidated above)

#[cfg(feature = "metrics")]
pub fn params_gauge() -> &'static prometheus::IntGaugeVec {
    get_or_register_gauge_vec(
        "proxy_select_params",
        "p3 selector params",
        &[
            "alpha",
            "eps",
            "cooldown_ms",
            "bias",
            "min_dwell_ms",
            "min_samples",
            "ema_halflife_ms",
            "explore",
        ],
    )
}

#[cfg(feature = "metrics")]
pub fn proxy_select_score() -> &'static prometheus::GaugeVec {
    use crate::metrics::registry_ext::get_or_register_gauge_vec_f64;
    get_or_register_gauge_vec_f64(
        "proxy_select_score_prom",
        "P3 selector score (prometheus crate)",
        &["outbound"],
    )
}

#[cfg(feature = "metrics")]
pub fn proxy_select_switch_total() -> &'static prometheus::IntCounterVec {
    get_or_register_counter_vec(
        "proxy_select_switch_total_prom",
        "selector switch count (prometheus crate)",
        &["reason"],
    )
}

#[cfg(feature = "metrics")]
pub fn proxy_select_explore_total() -> &'static prometheus::IntCounterVec {
    get_or_register_counter_vec(
        "proxy_select_explore_total",
        "selector exploration count",
        &["mode"],
    )
}

#[cfg(feature = "metrics")]
pub fn rate_limited_total() -> &'static prometheus::IntCounterVec {
    get_or_register_counter_vec(
        "proxy_rate_limited_total",
        "rate limited events",
        &["place"],
    )
}

#[cfg(feature = "metrics")]
pub fn register_selector_metrics() -> SelectorMetrics {
    SelectorMetrics {
        score: proxy_select_score().clone(),
        switch_total: proxy_select_switch_total().clone(),
        explore_total: proxy_select_explore_total().clone(),
    }
}

#[cfg(not(feature = "metrics"))]
pub struct SelectorMetrics {}

#[cfg(not(feature = "metrics"))]
pub fn register_selector_metrics() -> SelectorMetrics {
    SelectorMetrics {}
}

// Encrypted protocol-specific metrics
#[cfg(feature = "metrics")]
pub fn handshake_duration_histogram() -> &'static prometheus::HistogramVec {
    use crate::metrics::registry_ext::get_or_register_histogram_vec;
    get_or_register_histogram_vec(
        "outbound_handshake_duration_ms",
        "outbound handshake duration in milliseconds",
        &["protocol"],
        Some(vec![
            1.0, 5.0, 10.0, 25.0, 50.0, 100.0, 250.0, 500.0, 1000.0, 2500.0, 5000.0, 10000.0,
        ]),
    )
}

#[cfg(not(feature = "metrics"))]
pub fn handshake_duration_histogram() -> DummyHistogramVec {
    DummyHistogramVec
}

#[cfg(not(feature = "metrics"))]
pub struct DummyHistogramVec;

#[cfg(not(feature = "metrics"))]
impl DummyHistogramVec {
    pub const fn with_label_values(&self, _labels: &[&str]) -> DummyHistogram {
        DummyHistogram
    }
}

#[cfg(not(feature = "metrics"))]
pub struct DummyHistogram;

#[cfg(not(feature = "metrics"))]
impl DummyHistogram {
    pub const fn observe(&self, _value: f64) {}
}

#[cfg(feature = "out_trojan")]
pub fn record_trojan_connect_success() {
    #[cfg(feature = "metrics")]
    counter!("trojan_connect_total", "result" => "ok").increment(1);
}

#[cfg(feature = "out_trojan")]
pub fn record_trojan_connect_error() {
    #[cfg(feature = "metrics")]
    counter!("trojan_connect_total", "result" => "error").increment(1);
}

#[cfg(feature = "out_trojan")]
pub fn record_trojan_handshake_duration(duration_ms: f64) {
    #[cfg(feature = "metrics")]
    histogram!("trojan_handshake_ms").record(duration_ms);
}

#[cfg(feature = "out_ss")]
pub fn record_shadowsocks_connect_success() {
    #[cfg(feature = "metrics")]
    counter!("ss_connect_total", "result" => "ok").increment(1);
}

#[cfg(feature = "out_ss")]
pub fn record_shadowsocks_connect_error() {
    #[cfg(feature = "metrics")]
    counter!("ss_connect_total", "result" => "error").increment(1);
}

#[cfg(feature = "out_ss")]
pub fn record_shadowsocks_encrypt_bytes(bytes: u64) {
    #[cfg(feature = "metrics")]
    counter!("ss_encrypt_bytes_total").increment(bytes);
}

// Comprehensive metrics for encrypted outbound protocols as per P1 requirements

#[cfg(feature = "metrics")]
pub fn register_comprehensive_metrics() {
    use metrics::describe_counter;
    use metrics::describe_histogram;

    // Trojan metrics
    describe_counter!("trojan_connect_total", "Trojan connect attempts");
    describe_histogram!("trojan_handshake_ms", "Trojan TLS+auth handshake duration");

    // Shadowsocks metrics
    describe_counter!("ss_connect_total", "Shadowsocks connect attempts");
    describe_counter!(
        "ss_encrypt_bytes_total",
        "Shadowsocks encrypted bytes (TCP)"
    );
    describe_counter!("ss_udp_send_total", "Shadowsocks UDP send packets");
    describe_counter!("ss_udp_recv_total", "Shadowsocks UDP recv packets");
    describe_histogram!(
        "ss_aead_op_duration_ms",
        "Shadowsocks AEAD operation duration"
    );

    // ShadowTLS metrics
    describe_counter!("shadowtls_connect_total", "ShadowTLS connect attempts");
    describe_histogram!("shadowtls_handshake_ms", "ShadowTLS handshake duration");

    // Naive HTTP/2 metrics
    describe_counter!("naive_connect_total", "Naive HTTP/2 CONNECT attempts");
    describe_histogram!("naive_handshake_ms", "Naive HTTP/2 handshake duration");

    // VLESS metrics
    describe_counter!("vless_connect_total", "VLESS connect attempts");
    describe_histogram!("vless_handshake_ms", "VLESS handshake duration");

    // VMess metrics
    describe_counter!("vmess_connect_total", "VMess connect attempts");
    describe_histogram!("vmess_handshake_ms", "VMess handshake duration");

    // QUIC common metrics
    describe_counter!("quic_connect_total", "QUIC connect attempts");
    describe_histogram!("quic_handshake_ms", "QUIC handshake duration");

    // TUIC metrics
    describe_counter!("tuic_connect_total", "TUIC connect attempts");
    describe_histogram!("tuic_handshake_ms", "TUIC handshake duration");

    // Hysteria2 metrics
    describe_counter!("hysteria2_connect_total", "Hysteria2 connect attempts");
    describe_histogram!("hysteria2_handshake_ms", "Hysteria2 handshake duration");
    describe_histogram!("hysteria2_up_mbps", "Hysteria2 upload bandwidth (Mbps)");
    describe_histogram!("hysteria2_down_mbps", "Hysteria2 download bandwidth (Mbps)");

    // WireGuard metrics (placeholder)
    describe_counter!("wireguard_connect_total", "WireGuard connect attempts");

    // SSH metrics (placeholder)
    describe_counter!("ssh_connect_total", "SSH connect attempts");

    // Generic outbound AEAD metrics
    describe_histogram!(
        "outbound_aead_encrypt_duration_ms",
        "AEAD encryption duration"
    );
    describe_histogram!(
        "outbound_aead_decrypt_duration_ms",
        "AEAD decryption duration"
    );
    describe_counter!("outbound_aead_encrypt_total", "AEAD encryption operations");
    describe_counter!("outbound_aead_decrypt_total", "AEAD decryption operations");
}

#[cfg(not(feature = "metrics"))]
pub fn register_comprehensive_metrics() {
    // No-op when metrics are disabled
}

// Enhanced Trojan metrics
#[cfg(feature = "out_trojan")]
pub fn record_trojan_connect_attempt(cipher: &str) {
    #[cfg(feature = "metrics")]
    counter!("trojan_connect_total", "cipher" => cipher.to_string(), "result" => "attempt")
        .increment(1);
}

#[cfg(feature = "out_trojan")]
pub fn record_trojan_connect_success_with_cipher(cipher: &str) {
    #[cfg(feature = "metrics")]
    counter!("trojan_connect_total", "cipher" => cipher.to_string(), "result" => "ok").increment(1);
}

#[cfg(feature = "out_trojan")]
pub fn record_trojan_connect_error_with_cipher(cipher: &str) {
    #[cfg(feature = "metrics")]
    counter!("trojan_connect_total", "cipher" => cipher.to_string(), "result" => "error")
        .increment(1);
}

// Enhanced Shadowsocks metrics
#[cfg(feature = "out_ss")]
pub fn record_ss_connect_attempt(cipher: &str) {
    #[cfg(feature = "metrics")]
    counter!("ss_connect_total", "cipher" => cipher.to_string(), "result" => "attempt")
        .increment(1);
}

#[cfg(feature = "out_ss")]
pub fn record_ss_connect_success_with_cipher(cipher: &str) {
    #[cfg(feature = "metrics")]
    counter!("ss_connect_total", "cipher" => cipher.to_string(), "result" => "ok").increment(1);
}

#[cfg(feature = "out_ss")]
pub fn record_ss_connect_error_with_cipher(cipher: &str) {
    #[cfg(feature = "metrics")]
    counter!("ss_connect_total", "cipher" => cipher.to_string(), "result" => "error").increment(1);
}

#[cfg(feature = "out_ss")]
pub fn record_ss_encrypt_bytes_with_cipher(bytes: u64, cipher: &str) {
    #[cfg(feature = "metrics")]
    counter!("ss_encrypt_bytes_total", "cipher" => cipher.to_string()).increment(bytes);
}

#[cfg(feature = "out_ss")]
pub fn record_ss_udp_send_with_cipher(cipher: &str) {
    #[cfg(feature = "metrics")]
    counter!("ss_udp_send_total", "cipher" => cipher.to_string()).increment(1);
}

#[cfg(feature = "out_ss")]
pub fn record_ss_udp_recv_with_cipher(cipher: &str) {
    #[cfg(feature = "metrics")]
    counter!("ss_udp_recv_total", "cipher" => cipher.to_string()).increment(1);
}

#[cfg(feature = "out_ss")]
pub fn record_ss_aead_op_duration(duration_ms: f64, cipher: &str, operation: &str) {
    #[cfg(feature = "metrics")]
    histogram!("ss_aead_op_duration_ms", "cipher" => cipher.to_string(), "operation" => operation.to_string())
        .record(duration_ms);
}

// Generic AEAD operation metrics using static labels
pub fn record_aead_encrypt_duration(
    _duration_ms: f64,
    _protocol: crate::metrics::labels::Proto,
    _cipher: crate::metrics::labels::CipherType,
) {
    #[cfg(feature = "metrics")]
    histogram!(
        "outbound_aead_encrypt_duration_ms",
        "protocol" => _protocol.as_str(),
        "cipher" => _cipher.as_str()
    )
    .record(_duration_ms);
}

pub fn record_aead_decrypt_duration(
    _duration_ms: f64,
    _protocol: crate::metrics::labels::Proto,
    _cipher: crate::metrics::labels::CipherType,
) {
    #[cfg(feature = "metrics")]
    histogram!(
        "outbound_aead_decrypt_duration_ms",
        "protocol" => _protocol.as_str(),
        "cipher" => _cipher.as_str()
    )
    .record(_duration_ms);
}

pub fn record_aead_encrypt_total(
    _protocol: crate::metrics::labels::Proto,
    _cipher: crate::metrics::labels::CipherType,
    _result: crate::metrics::labels::ResultTag,
) {
    #[cfg(feature = "metrics")]
    counter!(
        "outbound_aead_encrypt_total",
        "protocol" => _protocol.as_str(),
        "cipher" => _cipher.as_str(),
        "result" => _result.as_str()
    )
    .increment(1);
}

pub fn record_aead_decrypt_total(
    _protocol: crate::metrics::labels::Proto,
    _cipher: crate::metrics::labels::CipherType,
    _result: crate::metrics::labels::ResultTag,
) {
    #[cfg(feature = "metrics")]
    counter!(
        "outbound_aead_decrypt_total",
        "protocol" => _protocol.as_str(),
        "cipher" => _cipher.as_str(),
        "result" => _result.as_str()
    )
    .increment(1);
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "metrics")]
    use prometheus::Encoder;

    #[test]
    fn connect_success_increments_with_kind_label() {
        // arrange
        record_connect_success(OutboundKind::Direct);

        // assert (only when metrics feature enabled)
        #[cfg(feature = "metrics")]
        {
            let mfs = crate::metrics::registry().gather();
            let mut buf = Vec::new();
            prometheus::TextEncoder::new()
                .encode(&mfs, &mut buf)
                .expect("encode");
            let s = String::from_utf8(buf).unwrap();
            assert!(s.contains("outbound_connect_total"));
            assert!(s.contains("kind=\"direct\""));
            assert!(s.contains("result=\"success\""));
        }
    }
}
