//! R16: 可选的 DNS 指标细化辅助（不改变逻辑；由调用点决定是否使用）
#[allow(unused)]
pub fn inc_timeout(kind: &'static str) {
    #[cfg(feature = "metrics")]
    metrics::counter!("dns_timeout_total", "kind" => kind).increment(1);
}

#[allow(unused)]
pub fn inc_blackhole() {
    #[cfg(feature = "metrics")]
    metrics::counter!("dns_blackhole_total").increment(1);
}

#[allow(unused)]
pub fn inc_resolve_err(code: &'static str) {
    #[cfg(feature = "metrics")]
    metrics::counter!("dns_resolve_error_total", "code" => code).increment(1);
}

#[allow(unused)]
pub fn obs_inflight(scope: &'static str, v: i64) {
    #[cfg(feature = "metrics")]
    metrics::gauge!("dns_inflight", "scope" => scope).increment(v as f64);
}
