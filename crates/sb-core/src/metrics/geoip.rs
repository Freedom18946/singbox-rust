//! GeoIP metrics collection
//!
//! This module provides metrics for GeoIP lookup operations including:
//! - Lookup duration and success rates
//! - Provider performance statistics
//! - Country lookup distribution
//! - Cache hit/miss ratios

/// Record GeoIP lookup duration
#[cfg(feature = "metrics")]
pub fn geoip_lookup_duration(duration: f64) {
    metrics::histogram!("geoip_lookup_duration_seconds").record(duration);
}

/// Record GeoIP lookup total count with result
#[cfg(feature = "metrics")]
pub fn geoip_lookup_total(result: &str) {
    metrics::counter!("geoip_lookup_total", "result" => result.to_string()).increment(1);
}

/// Record country lookup distribution
#[cfg(feature = "metrics")]
pub fn geoip_country_lookup_total(country: &str) {
    metrics::counter!("geoip_country_lookup_total", "country" => country.to_string()).increment(1);
}

/// Record provider success metrics
#[cfg(feature = "metrics")]
pub fn geoip_provider_success(provider: &str, duration: f64) {
    metrics::counter!("geoip_provider_success_total", "provider" => provider.to_string()).increment(1);
    metrics::histogram!("geoip_provider_duration_seconds", "provider" => provider.to_string(), "result" => "success").record(duration);
}

/// Record provider failure metrics
#[cfg(feature = "metrics")]
pub fn geoip_provider_failure(provider: &str, duration: f64) {
    metrics::counter!("geoip_provider_failure_total", "provider" => provider.to_string()).increment(1);
    metrics::histogram!("geoip_provider_duration_seconds", "provider" => provider.to_string(), "result" => "failure").record(duration);
}

/// Record fastest provider selection
#[cfg(feature = "metrics")]
pub fn geoip_fastest_provider(provider: &str, duration: f64) {
    metrics::counter!("geoip_fastest_provider_total", "provider" => provider.to_string()).increment(1);
    metrics::histogram!("geoip_fastest_provider_duration_seconds", "provider" => provider.to_string()).record(duration);
}

/// Record cache statistics
#[cfg(feature = "metrics")]
pub fn geoip_cache_hit() {
    metrics::counter!("geoip_cache_hit_total").increment(1);
}

/// Record cache miss
#[cfg(feature = "metrics")]
pub fn geoip_cache_miss() {
    metrics::counter!("geoip_cache_miss_total").increment(1);
}

/// Record cache size
#[cfg(feature = "metrics")]
pub fn geoip_cache_size(size: usize) {
    metrics::gauge!("geoip_cache_size").set(size as f64);
}

/// Record database load events
#[cfg(feature = "metrics")]
pub fn geoip_database_loaded(db_type: &str, file_size: u64) {
    metrics::counter!("geoip_database_loaded_total", "type" => db_type.to_string()).increment(1);
    metrics::gauge!("geoip_database_size_bytes", "type" => db_type.to_string()).set(file_size as f64);
}

/// Record database load errors
#[cfg(feature = "metrics")]
pub fn geoip_database_load_error(db_type: &str, error: &str) {
    metrics::counter!("geoip_database_load_error_total", "type" => db_type.to_string(), "error" => error.to_string()).increment(1);
}

// No-op implementations when metrics are disabled
#[cfg(not(feature = "metrics"))]
pub fn geoip_lookup_duration(_duration: f64) {}

#[cfg(not(feature = "metrics"))]
pub fn geoip_lookup_total(_result: &str) {}

#[cfg(not(feature = "metrics"))]
pub fn geoip_country_lookup_total(_country: &str) {}

#[cfg(not(feature = "metrics"))]
pub fn geoip_provider_success(_provider: &str, _duration: f64) {}

#[cfg(not(feature = "metrics"))]
pub fn geoip_provider_failure(_provider: &str, _duration: f64) {}

#[cfg(not(feature = "metrics"))]
pub fn geoip_fastest_provider(_provider: &str, _duration: f64) {}

#[cfg(not(feature = "metrics"))]
pub fn geoip_cache_hit() {}

#[cfg(not(feature = "metrics"))]
pub fn geoip_cache_miss() {}

#[cfg(not(feature = "metrics"))]
pub fn geoip_cache_size(_size: usize) {}

#[cfg(not(feature = "metrics"))]
pub fn geoip_database_loaded(_db_type: &str, _file_size: u64) {}

#[cfg(not(feature = "metrics"))]
pub fn geoip_database_load_error(_db_type: &str, _error: &str) {}

/// Initialize GeoIP metrics
#[cfg(feature = "metrics")]
pub fn init_geoip_metrics() {
    // Pre-register metrics to ensure they appear in /metrics output
    geoip_lookup_duration(0.0);
    geoip_lookup_total("init");
    geoip_cache_hit();
    geoip_cache_miss();
    geoip_cache_size(0);
}

#[cfg(not(feature = "metrics"))]
pub fn init_geoip_metrics() {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metrics_compilation() {
        // These should compile regardless of feature flags
        geoip_lookup_duration(0.5);
        geoip_lookup_total("hit");
        geoip_country_lookup_total("US");
        geoip_provider_success("mmdb", 0.1);
        geoip_provider_failure("fallback", 1.0);
        geoip_fastest_provider("mmdb", 0.05);
        geoip_cache_hit();
        geoip_cache_miss();
        geoip_cache_size(100);
        geoip_database_loaded("country", 1024);
        geoip_database_load_error("city", "file_not_found");
        init_geoip_metrics();
    }
}