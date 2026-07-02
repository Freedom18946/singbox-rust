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
    /// Create a response, normalizing header keys for stable lookup.
    pub fn new(
        status: u16,
        headers: impl IntoIterator<Item = (impl Into<String>, impl Into<String>)>,
        body: impl Into<Vec<u8>>,
    ) -> Self {
        let mut response = Self {
            status,
            headers: HashMap::new(),
            body: body.into(),
        };
        for (key, value) in headers {
            response.insert_header(key, value);
        }
        response
    }

    /// Insert a response header, normalizing the key to lowercase ASCII.
    pub fn insert_header(
        &mut self,
        key: impl Into<String>,
        value: impl Into<String>,
    ) -> Option<String> {
        self.headers
            .insert(key.into().to_ascii_lowercase(), value.into())
    }

    /// Add a header to the response.
    pub fn with_header(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.insert_header(key, value);
        self
    }

    /// Get a header value by key (case-insensitive lookup).
    pub fn header(&self, key: &str) -> Option<&str> {
        let key_lower = key.to_ascii_lowercase();
        self.headers
            .get(&key_lower)
            .map(String::as_str)
            .or_else(|| {
                self.headers
                    .iter()
                    .find(|(k, _)| k.eq_ignore_ascii_case(key))
                    .map(|(_, v)| v.as_str())
            })
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

#[cfg(test)]
mod tests {
    use super::HttpResponse;
    use std::collections::HashMap;

    #[test]
    fn response_new_normalizes_header_keys_for_lookup() {
        let response = HttpResponse::new(
            200,
            [("ETag", "v1"), ("Last-Modified", "today")],
            Vec::new(),
        );

        assert_eq!(response.header("etag"), Some("v1"));
        assert_eq!(response.header("ETAG"), Some("v1"));
        assert_eq!(response.header("last-modified"), Some("today"));
        assert!(response.headers.contains_key("etag"));
        assert!(response.headers.contains_key("last-modified"));
    }

    #[test]
    fn response_header_lookup_preserves_direct_field_compatibility() {
        let response = HttpResponse {
            status: 200,
            headers: HashMap::from([("ETag".to_string(), "direct".to_string())]),
            body: Vec::new(),
        };

        assert_eq!(response.header("etag"), Some("direct"));
    }

    #[test]
    fn response_success_is_limited_to_2xx() {
        assert!(
            HttpResponse::new(204, std::iter::empty::<(&str, &str)>(), Vec::new()).is_success()
        );
        assert!(
            !HttpResponse::new(199, std::iter::empty::<(&str, &str)>(), Vec::new()).is_success()
        );
        assert!(
            !HttpResponse::new(300, std::iter::empty::<(&str, &str)>(), Vec::new()).is_success()
        );
    }
}
