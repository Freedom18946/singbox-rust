//! HTTP Inbound Metrics
//!
//! Provides comprehensive metrics for HTTP proxy operations including:
//! - Response status code tracking
//! - Connection duration histograms
//! - Error classification

#[cfg(feature = "metrics")]
use crate::metrics::registry_ext::{
    get_or_register_counter_vec, get_or_register_gauge_vec_f64, get_or_register_histogram_vec,
};

#[cfg(feature = "metrics")]
use metrics::{counter, Counter};
#[cfg(feature = "metrics")]
use once_cell::sync::Lazy;

#[cfg(feature = "metrics")]
static HTTP_RESPOND_405_TOTAL: Lazy<Counter> = Lazy::new(|| counter!("http_respond_405_total"));

#[cfg(feature = "metrics")]
static HTTP_CONNECT_DURATION_MS: Lazy<&'static prometheus::HistogramVec> = Lazy::new(|| {
    get_or_register_histogram_vec(
        "http_connect_duration_ms",
        "http connect duration (ms)",
        &[],
        None,
    )
});

#[cfg(feature = "metrics")]
static HTTP_REQUESTS_TOTAL: Lazy<&'static prometheus::IntCounterVec> = Lazy::new(|| {
    get_or_register_counter_vec(
        "http_requests_total",
        "http requests total",
        &["method", "status"],
    )
});

#[cfg(feature = "metrics")]
static HTTP_ERRORS_TOTAL: Lazy<&'static prometheus::IntCounterVec> =
    Lazy::new(|| get_or_register_counter_vec("http_errors_total", "http errors total", &["class"]));

#[cfg(feature = "metrics")]
static HTTP_ACTIVE_CONNECTIONS: Lazy<&'static prometheus::GaugeVec> = Lazy::new(|| {
    get_or_register_gauge_vec_f64("http_active_connections", "active http connections", &[])
});

/// Register all HTTP metrics
pub fn register_metrics() {
    #[cfg(feature = "metrics")]
    {
        Lazy::force(&HTTP_RESPOND_405_TOTAL);
        Lazy::force(&HTTP_CONNECT_DURATION_MS);
        Lazy::force(&HTTP_REQUESTS_TOTAL);
        Lazy::force(&HTTP_ERRORS_TOTAL);
        Lazy::force(&HTTP_ACTIVE_CONNECTIONS);
    }
}

/// Increment 405 Method Not Allowed responses
pub fn inc_405_responses() {
    #[cfg(feature = "metrics")]
    HTTP_RESPOND_405_TOTAL.increment(1);
}

/// Record HTTP connection duration
pub fn record_connect_duration(_duration_ms: f64) {
    #[cfg(feature = "metrics")]
    HTTP_CONNECT_DURATION_MS
        .with_label_values(&[])
        .observe(_duration_ms);
}

/// Increment total HTTP requests
pub fn inc_requests(_method: &str, _status: u16) {
    #[cfg(feature = "metrics")]
    {
        HTTP_REQUESTS_TOTAL
            .with_label_values(&[_method, &format!("{}", _status)])
            .inc();
    }
}

/// Increment HTTP errors with classification
pub fn inc_errors(_class: &str) {
    #[cfg(feature = "metrics")]
    {
        HTTP_ERRORS_TOTAL.with_label_values(&[_class]).inc();
    }
}

/// Set active HTTP connections count
pub fn set_active_connections(_count: usize) {
    #[cfg(feature = "metrics")]
    HTTP_ACTIVE_CONNECTIONS
        .with_label_values(&[])
        .set(_count as f64);
}

/// Increment active connections
pub fn inc_active_connections() {
    #[cfg(feature = "metrics")]
    HTTP_ACTIVE_CONNECTIONS.with_label_values(&[]).inc();
}

/// Decrement active connections
pub fn dec_active_connections() {
    #[cfg(feature = "metrics")]
    HTTP_ACTIVE_CONNECTIONS.with_label_values(&[]).dec();
}

/// Error classes for HTTP operations
pub enum HttpErrorClass {
    ParseError,
    ConnectTimeout,
    ReadTimeout,
    WriteTimeout,
    ConnectionReset,
    BadRequest,
    AuthFailed,
    Other,
}

impl HttpErrorClass {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::ParseError => "parse_error",
            Self::ConnectTimeout => "connect_timeout",
            Self::ReadTimeout => "read_timeout",
            Self::WriteTimeout => "write_timeout",
            Self::ConnectionReset => "connection_reset",
            Self::BadRequest => "bad_request",
            Self::AuthFailed => "auth_failed",
            Self::Other => "other",
        }
    }
}

/// Record HTTP error with classification
pub fn record_error(error_class: HttpErrorClass) {
    inc_errors(error_class.as_str());
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "metrics")]
    use prometheus::Encoder;

    #[test]
    fn test_error_classification() {
        assert_eq!(HttpErrorClass::ParseError.as_str(), "parse_error");
        assert_eq!(HttpErrorClass::ConnectTimeout.as_str(), "connect_timeout");
        assert_eq!(HttpErrorClass::Other.as_str(), "other");
    }

    #[test]
    fn test_metrics_registration() {
        // This test ensures metrics can be registered without panicking
        register_metrics();
    }

    #[test]
    fn active_connections_gauge_set() {
        set_active_connections(7);
        #[cfg(feature = "metrics")]
        {
            let mut buf = Vec::new();
            prometheus::TextEncoder::new()
                .encode(&crate::metrics::registry().gather(), &mut buf)
                .unwrap();
            let s = String::from_utf8(buf).unwrap();
            assert!(s.contains("http_active_connections"));
        }
    }
}
