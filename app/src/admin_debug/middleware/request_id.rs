//! Request ID middleware for admin debug HTTP server
//!
//! This middleware extracts request IDs from headers (X-Request-ID, Request-ID)
//! or generates a new one if none is provided. The request ID is injected into
//! the request context and will be included in response envelopes.

use super::{Middleware, MiddlewareResult, RequestContext};
use std::collections::HashMap;

/// Extract request ID from headers or generate a new one
pub fn extract_or_generate(headers: &HashMap<String, String>) -> String {
    headers.get("x-request-id")
        .or_else(|| headers.get("request-id"))
        .cloned()
        .unwrap_or_else(generate_request_id)
}

/// Generate a unique request ID
fn generate_request_id() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    format!("req-{:016x}-{:04x}", timestamp, rand::random::<u16>())
}

/// Request ID middleware implementation
#[derive(Debug, Clone)]
pub struct RequestIdMiddleware;

impl RequestIdMiddleware {
    pub fn new() -> Self {
        Self
    }
}

impl Default for RequestIdMiddleware {
    fn default() -> Self {
        Self::new()
    }
}

impl Middleware for RequestIdMiddleware {
    fn process(&self, ctx: &mut RequestContext) -> MiddlewareResult<()> {
        // Request ID is already set during RequestContext creation,
        // but we can log it here for debugging
        tracing::debug!(
            request_id = %ctx.request_id,
            method = %ctx.method,
            path = %ctx.path,
            target = "admin",
            "processing request"
        );
        Ok(())
    }
}

/// Helper function to add request ID to response headers
pub fn add_to_response_headers(request_id: &str) -> String {
    format!("X-Request-ID: {}\r\n", request_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_request_id_from_x_request_id() {
        let mut headers = HashMap::new();
        headers.insert("x-request-id".to_string(), "test-123".to_string());

        let id = extract_or_generate(&headers);
        assert_eq!(id, "test-123");
    }

    #[test]
    fn test_extract_request_id_from_request_id() {
        let mut headers = HashMap::new();
        headers.insert("request-id".to_string(), "test-456".to_string());

        let id = extract_or_generate(&headers);
        assert_eq!(id, "test-456");
    }

    #[test]
    fn test_extract_request_id_priority() {
        let mut headers = HashMap::new();
        headers.insert("x-request-id".to_string(), "priority".to_string());
        headers.insert("request-id".to_string(), "fallback".to_string());

        let id = extract_or_generate(&headers);
        assert_eq!(id, "priority"); // x-request-id takes priority
    }

    #[test]
    fn test_generate_request_id_when_missing() {
        let headers = HashMap::new();
        let id = extract_or_generate(&headers);

        // Should generate an ID starting with "req-"
        assert!(id.starts_with("req-"));
        assert!(id.len() > 10); // Should be reasonably long
    }

    #[test]
    fn test_generate_request_id_uniqueness() {
        let id1 = generate_request_id();
        let id2 = generate_request_id();

        // Should generate different IDs
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_middleware_process() {
        let middleware = RequestIdMiddleware::new();
        let mut ctx = RequestContext::new(
            "GET".to_string(),
            "/test".to_string(),
            HashMap::new(),
        );

        let result = middleware.process(&mut ctx);
        assert!(result.is_ok());

        // Request ID should be set
        assert!(ctx.request_id.starts_with("req-"));
    }

    #[test]
    fn test_add_to_response_headers() {
        let header = add_to_response_headers("test-123");
        assert_eq!(header, "X-Request-ID: test-123\r\n");
    }
}