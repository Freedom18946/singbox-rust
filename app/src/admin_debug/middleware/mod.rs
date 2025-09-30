//! Middleware infrastructure for admin debug HTTP server
//!
//! This module provides a composable middleware chain for the admin debug server:
//! `request_id` → `rate_limit` (optional) → auth → handler
//!
//! All middleware failures return contract-compliant `ResponseEnvelope` errors.

pub mod auth;
#[cfg(feature = "rate_limit")]
pub mod rate_limit;
pub mod request_id;

use std::collections::HashMap;
use tokio::io::AsyncWrite;

/// Result type for middleware operations
pub type MiddlewareResult<T> = Result<T, sb_admin_contract::ResponseEnvelope<()>>;

/// Request context passed through middleware chain
#[derive(Debug, Clone)]
pub struct RequestContext {
    pub method: String,
    pub path: String,
    pub headers: HashMap<String, String>,
    pub request_id: String,
    pub body: Option<bytes::Bytes>,
}

impl RequestContext {
    #[must_use] 
    pub fn new(method: String, path: String, headers: HashMap<String, String>) -> Self {
        let request_id = request_id::extract_or_generate(&headers);
        Self {
            method,
            path,
            headers,
            request_id,
            body: None,
        }
    }

    pub fn with_body(mut self, body: bytes::Bytes) -> Self {
        self.body = Some(body);
        self
    }
}

/// Trait for middleware components
pub trait Middleware: Send + Sync {
    /// Process the request context and either continue or return an error
    fn process(&self, ctx: &mut RequestContext) -> MiddlewareResult<()>;
}

/// Middleware chain builder for composing multiple middleware
pub struct MiddlewareChain {
    middlewares: Vec<Box<dyn Middleware>>,
}

impl MiddlewareChain {
    #[must_use] 
    pub fn new() -> Self {
        Self {
            middlewares: Vec::new(),
        }
    }

    pub fn add<M: Middleware + 'static>(mut self, middleware: M) -> Self {
        self.middlewares.push(Box::new(middleware));
        self
    }

    /// Execute the middleware chain
    pub fn execute(&self, ctx: &mut RequestContext) -> MiddlewareResult<()> {
        for middleware in &self.middlewares {
            middleware.process(ctx)?;
        }
        Ok(())
    }
}

impl Default for MiddlewareChain {
    fn default() -> Self {
        Self::new()
    }
}

/// Convenience function to send error response
pub async fn send_error_response<W: AsyncWrite + Unpin>(
    writer: &mut W,
    envelope: sb_admin_contract::ResponseEnvelope<()>,
    status_code: u16,
) -> std::io::Result<()> {
    use tokio::io::AsyncWriteExt;

    let body = serde_json::to_string(&envelope).map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, "JSON serialization failed")
    })?;

    let status_text = match status_code {
        401 => "Unauthorized",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        _ => "Error",
    };

    let response = format!(
        "HTTP/1.1 {} {}\r\n\
        Content-Type: application/json\r\n\
        Content-Length: {}\r\n\
        \r\n\
        {}",
        status_code,
        status_text,
        body.len(),
        body
    );

    writer.write_all(response.as_bytes()).await
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestMiddleware {
        should_fail: bool,
    }

    impl Middleware for TestMiddleware {
        fn process(&self, _ctx: &mut RequestContext) -> MiddlewareResult<()> {
            if self.should_fail {
                Err(sb_admin_contract::ResponseEnvelope::err(
                    sb_admin_contract::ErrorKind::Internal,
                    "test failure",
                ))
            } else {
                Ok(())
            }
        }
    }

    #[test]
    fn test_middleware_chain_success() {
        let chain = MiddlewareChain::new()
            .add(TestMiddleware { should_fail: false })
            .add(TestMiddleware { should_fail: false });

        let mut ctx = RequestContext::new("GET".to_string(), "/test".to_string(), HashMap::new());

        assert!(chain.execute(&mut ctx).is_ok());
    }

    #[test]
    fn test_middleware_chain_failure() {
        let chain = MiddlewareChain::new()
            .add(TestMiddleware { should_fail: false })
            .add(TestMiddleware { should_fail: true });

        let mut ctx = RequestContext::new("GET".to_string(), "/test".to_string(), HashMap::new());

        assert!(chain.execute(&mut ctx).is_err());
    }

    #[test]
    fn test_request_context_creation() {
        let mut headers = HashMap::new();
        headers.insert("x-request-id".to_string(), "test-id".to_string());

        let ctx = RequestContext::new("POST".to_string(), "/api/test".to_string(), headers);

        assert_eq!(ctx.method, "POST");
        assert_eq!(ctx.path, "/api/test");
        assert_eq!(ctx.request_id, "test-id");
    }
}
