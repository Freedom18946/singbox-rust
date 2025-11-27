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

/// Set DNS cache size gauge
#[allow(unused)]
pub fn set_cache_size(size: usize) {
    #[cfg(feature = "metrics")]
    metrics::gauge!("dns_cache_size").set(size as f64);
}

/// Increment DNS cache hit counter
#[allow(unused)]
pub fn inc_cache_hit() {
    #[cfg(feature = "metrics")]
    metrics::counter!("dns_cache_hits_total").increment(1);
}

/// Increment DNS cache miss counter
#[allow(unused)]
pub fn inc_cache_miss() {
    #[cfg(feature = "metrics")]
    metrics::counter!("dns_cache_misses_total").increment(1);
}

/// Increment DNS upstream error counter
#[allow(unused)]
pub fn inc_upstream_error(upstream: &str, error_type: &str) {
    #[cfg(feature = "metrics")]
    metrics::counter!("dns_upstream_errors_total", "upstream" => upstream.to_string(), "error_type" => error_type.to_string()).increment(1);
}
