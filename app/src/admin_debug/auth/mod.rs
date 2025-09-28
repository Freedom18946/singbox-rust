//! Authentication module for admin debug HTTP server
//!
//! This module provides a unified authentication interface supporting multiple
//! authentication methods: JWT, API Key, and None (no authentication).
//!
//! All authentication errors are mapped to `sb_admin_contract::ErrorKind::Auth`
//! for consistent contract compliance.

#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

pub mod jwt;
pub mod apikey;
pub mod none;

use thiserror::Error;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Unified authentication provider trait
pub trait AuthProvider: Send + Sync {
    /// Check authentication for the given request
    ///
    /// # Arguments
    /// * `req` - HTTP request containing headers and other auth data
    ///
    /// # Returns
    /// * `Ok(())` if authentication succeeds
    /// * `Err(AuthError)` if authentication fails
    fn check(&self, headers: &HashMap<String, String>, path: &str) -> Result<(), AuthError>;
}

/// Authentication configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum AuthConfig {
    /// No authentication required
    None,
    /// JWT-based authentication
    Jwt {
        /// JWT secret for verification
        secret: String,
        /// Optional algorithm (defaults to HS256)
        #[serde(default = "default_jwt_algorithm")]
        algorithm: String,
        /// Token expiration time in seconds (defaults to 3600)
        #[serde(default = "default_jwt_expiry")]
        expiry_seconds: u64,
    },
    /// API Key authentication
    ApiKey {
        /// API key for authentication
        key: String,
        /// Optional key ID for identification
        key_id: Option<String>,
    },
}

fn default_jwt_algorithm() -> String {
    "HS256".to_string()
}

fn default_jwt_expiry() -> u64 {
    3600 // 1 hour
}

/// Authentication errors
#[derive(Error, Debug)]
pub enum AuthError {
    /// Authentication failed - invalid credentials
    #[error("Authentication failed: {message}")]
    InvalidCredentials { message: String },

    /// Authentication failed - missing credentials
    #[error("Authentication required: {message}")]
    MissingCredentials { message: String },

    /// Authentication failed - expired credentials
    #[error("Authentication expired: {message}")]
    ExpiredCredentials { message: String },

    /// Internal authentication error
    #[error("Authentication system error: {message}")]
    Internal { message: String },
}

impl AuthError {
    /// Create an invalid credentials error
    pub fn invalid(message: impl Into<String>) -> Self {
        Self::InvalidCredentials { message: message.into() }
    }

    /// Create a missing credentials error
    pub fn missing(message: impl Into<String>) -> Self {
        Self::MissingCredentials { message: message.into() }
    }

    /// Create an expired credentials error
    pub fn expired(message: impl Into<String>) -> Self {
        Self::ExpiredCredentials { message: message.into() }
    }

    /// Create an internal error
    pub fn internal(message: impl Into<String>) -> Self {
        Self::Internal { message: message.into() }
    }

    /// Get the error message
    pub fn message(&self) -> &str {
        match self {
            Self::InvalidCredentials { message } => message,
            Self::MissingCredentials { message } => message,
            Self::ExpiredCredentials { message } => message,
            Self::Internal { message } => message,
        }
    }

    /// Get a hint for the error
    pub fn hint(&self) -> Option<String> {
        match self {
            Self::MissingCredentials { .. } => Some("Include Authorization header with valid credentials".to_string()),
            Self::InvalidCredentials { .. } => Some("Check your authentication credentials and try again".to_string()),
            Self::ExpiredCredentials { .. } => Some("Refresh your authentication token and try again".to_string()),
            Self::Internal { .. } => Some("Contact system administrator if this persists".to_string()),
        }
    }
}

/// Convert AuthError to sb_admin_contract::ErrorBody
impl From<AuthError> for sb_admin_contract::ErrorBody {
    fn from(err: AuthError) -> Self {
        Self {
            kind: sb_admin_contract::ErrorKind::Auth,
            msg: err.message().to_string(),
            ptr: None,
            hint: err.hint(),
        }
    }
}

/// Factory function to create AuthProvider from configuration
///
/// # Arguments
/// * `config` - Authentication configuration
///
/// # Returns
/// * `Ok(Box<dyn AuthProvider>)` - Authentication provider instance
/// * `Err(AuthError)` - Configuration error
#[cfg(feature = "auth")]
pub fn from_config(config: &AuthConfig) -> Result<Box<dyn AuthProvider>, AuthError> {
    match config {
        AuthConfig::None => Ok(Box::new(none::NoneProvider::new())),
        AuthConfig::Jwt { secret, algorithm, expiry_seconds: _ } => {
            let config = jwt::JwtConfig {
                jwks_file: None,
                jwks_url: None,
                algo_allowlist: vec![jwt::JwtAlgorithm::from_str(algorithm)?],
                ttl: std::time::Duration::from_secs(3600),
                skew: std::time::Duration::from_secs(60),
                hmac_secret: Some(secret.clone()),
            };
            Ok(Box::new(jwt::JwtProvider::new(config)?))
        }
        AuthConfig::ApiKey { key, key_id } => {
            Ok(Box::new(apikey::ApiKeyProvider::new(key.clone(), key_id.clone())))
        }
    }
}

/// Factory function when auth feature is disabled - returns NoneProvider
#[cfg(not(feature = "auth"))]
pub fn from_config(_config: &AuthConfig) -> Result<Box<dyn AuthProvider>, AuthError> {
    Ok(Box::new(none::NoneProvider::new()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_auth_error_creation() {
        let err = AuthError::invalid("bad token");
        assert_eq!(err.message(), "bad token");
        assert!(err.hint().is_some());
    }

    #[test]
    fn test_auth_error_to_contract() {
        let err = AuthError::missing("no auth header");
        let body: sb_admin_contract::ErrorBody = err.into();
        assert_eq!(body.kind, sb_admin_contract::ErrorKind::Auth);
        assert_eq!(body.msg, "no auth header");
        assert!(body.hint.is_some());
    }

    #[test]
    fn test_auth_config_defaults() {
        let config = AuthConfig::Jwt {
            secret: "test".to_string(),
            algorithm: default_jwt_algorithm(),
            expiry_seconds: default_jwt_expiry(),
        };

        if let AuthConfig::Jwt { algorithm, expiry_seconds, .. } = config {
            assert_eq!(algorithm, "HS256");
            assert_eq!(expiry_seconds, 3600);
        } else {
            panic!("Expected JWT config");
        }
    }

    #[cfg(feature = "auth")]
    #[test]
    fn test_factory_none() {
        let config = AuthConfig::None;
        let provider = from_config(&config).unwrap();

        // Test that none provider allows all requests
        let headers = HashMap::new();
        assert!(provider.check(&headers, "/test").is_ok());
    }

    #[cfg(not(feature = "auth"))]
    #[test]
    fn test_factory_disabled() {
        let config = AuthConfig::ApiKey {
            key: "test".to_string(),
            key_id: Some("test-id".to_string()),
        };

        // Should return NoneProvider regardless of config
        let provider = from_config(&config).unwrap();
        let headers = HashMap::new();
        assert!(provider.check(&headers, "/test").is_ok());
    }
}