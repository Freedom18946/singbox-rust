//! HTTP Inbound Metrics
//!
//! Provides comprehensive metrics for HTTP proxy operations including:
//! - Response status code tracking
//! - Connection duration histograms
//! - Error classification

#[cfg(feature = "metrics")]
use metrics::{counter, gauge, histogram, Counter, Gauge, Histogram};

#[cfg(feature = "metrics")]
use once_cell::sync::Lazy;

#[cfg(feature = "metrics")]
static HTTP_RESPOND_405_TOTAL: Lazy<Counter> = Lazy::new(|| counter!("http_respond_405_total"));

#[cfg(feature = "metrics")]
static HTTP_CONNECT_DURATION_MS: Lazy<Histogram> =
    Lazy::new(|| histogram!("http_connect_duration_ms"));

#[cfg(feature = "metrics")]
static HTTP_REQUESTS_TOTAL: Lazy<Counter> = Lazy::new(|| counter!("http_requests_total"));

#[cfg(feature = "metrics")]
static HTTP_ERRORS_TOTAL: Lazy<Counter> = Lazy::new(|| counter!("http_errors_total"));

#[cfg(feature = "metrics")]
static HTTP_ACTIVE_CONNECTIONS: Lazy<Gauge> = Lazy::new(|| gauge!("http_active_connections"));

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
pub fn record_connect_duration(duration_ms: f64) {
    #[cfg(feature = "metrics")]
    HTTP_CONNECT_DURATION_MS.record(duration_ms);
}

/// Increment total HTTP requests
pub fn inc_requests(method: &str, status: u16) {
    #[cfg(feature = "metrics")]
    {
        counter!("http_requests_total", "method" => method.to_string(), "status" => status.to_string()).increment(1);
    }
}

/// Increment HTTP errors with classification
pub fn inc_errors(class: &str) {
    #[cfg(feature = "metrics")]
    {
        counter!("http_errors_total", "class" => class.to_string()).increment(1);
    }
}

/// Set active HTTP connections count
pub fn set_active_connections(count: usize) {
    #[cfg(feature = "metrics")]
    HTTP_ACTIVE_CONNECTIONS.set(count as f64);
}

/// Increment active connections
pub fn inc_active_connections() {
    #[cfg(feature = "metrics")]
    HTTP_ACTIVE_CONNECTIONS.increment(1.0);
}

/// Decrement active connections
pub fn dec_active_connections() {
    #[cfg(feature = "metrics")]
    HTTP_ACTIVE_CONNECTIONS.decrement(1.0);
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
    pub fn as_str(&self) -> &'static str {
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
}
