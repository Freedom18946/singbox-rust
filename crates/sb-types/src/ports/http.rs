//! HTTP client port for cross-crate HTTP abstraction.
//!
//! Allows sb-core to perform HTTP requests without depending on a specific
//! HTTP client library (e.g. reqwest). The concrete implementation is injected
//! by the application layer.

use std::collections::HashMap;

/// A simple HTTP request descriptor.
#[derive(Debug, Clone)]
pub struct HttpRequest {
    /// HTTP method (GET, POST, etc.)
    pub method: HttpMethod,
    /// Full URL
    pub url: String,
    /// Request headers
    pub headers: HashMap<String, String>,
    /// Optional request body
    pub body: Option<Vec<u8>>,
    /// Timeout in seconds (0 = no timeout)
    pub timeout_secs: u64,
}

/// Supported HTTP methods.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpMethod {
    Get,
    Post,
    Put,
    Delete,
    Head,
}

/// A simple HTTP response descriptor.
#[derive(Debug, Clone)]
pub struct HttpResponse {
    /// HTTP status code
    pub status: u16,
    /// Response headers (lowercased keys)
    pub headers: HashMap<String, String>,
    /// Response body bytes
    pub body: Vec<u8>,
}

impl HttpRequest {
    /// Create a simple GET request with a timeout.
    pub fn get(url: impl Into<String>, timeout_secs: u64) -> Self {
        Self {
            method: HttpMethod::Get,
            url: url.into(),
            headers: HashMap::new(),
            body: None,
            timeout_secs,
        }
    }

    /// Add a header to the request.
    pub fn with_header(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.insert(key.into(), value.into());
        self
    }
}

impl HttpResponse {
    /// Get a header value by key (case-insensitive lookup).
    pub fn header(&self, key: &str) -> Option<&str> {
        let key_lower = key.to_lowercase();
        self.headers
            .iter()
            .find(|(k, _)| k.to_lowercase() == key_lower)
            .map(|(_, v)| v.as_str())
    }

    /// Check if the status code indicates success (2xx).
    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.status)
    }
}

/// Port trait for performing HTTP requests.
///
/// Implementations are injected at the application layer, allowing sb-core
/// to remain decoupled from any specific HTTP client library.
pub trait HttpClient: Send + Sync {
    /// Execute an HTTP request and return the response.
    ///
    /// Implementations should handle TLS, redirects, and timeouts internally.
    fn execute(
        &self,
        req: HttpRequest,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<HttpResponse, crate::CoreError>> + Send + '_>,
    >;
}
