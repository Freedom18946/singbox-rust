//! No authentication provider
//!
//! This provider allows all requests to pass through without authentication.
//! Used when authentication is disabled or as a fallback.

use super::{AuthProvider, AuthError};
use std::collections::HashMap;

/// Authentication provider that allows all requests
#[derive(Debug, Clone)]
pub struct NoneProvider;

impl NoneProvider {
    /// Create a new NoneProvider instance
    pub fn new() -> Self {
        Self
    }
}

impl Default for NoneProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl AuthProvider for NoneProvider {
    /// Always allows authentication
    fn check(&self, _headers: &HashMap<String, String>, _path: &str) -> Result<(), AuthError> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_none_provider_allows_all() {
        let provider = NoneProvider::new();
        let headers = HashMap::new();

        // Should allow any request
        assert!(provider.check(&headers, "/any/path").is_ok());

        // Should allow with any headers
        let mut headers_with_auth = HashMap::new();
        headers_with_auth.insert("authorization".to_string(), "Bearer invalid".to_string());
        assert!(provider.check(&headers_with_auth, "/secure").is_ok());
    }

    #[test]
    fn test_none_provider_default() {
        let provider = NoneProvider::default();
        let headers = HashMap::new();
        assert!(provider.check(&headers, "/test").is_ok());
    }
}