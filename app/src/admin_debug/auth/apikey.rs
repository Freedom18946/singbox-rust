//! API Key authentication provider
//!
//! This provider supports Bearer token authentication and HMAC-SHA256 signature verification.
//! Compatible with the existing authentication system in http_server.rs.

use super::{AuthError, AuthProvider};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use subtle::ConstantTimeEq;

type HmacSha256 = Hmac<Sha256>;

/// API Key authentication provider
#[derive(Debug, Clone)]
pub struct ApiKeyProvider {
    /// The API key for Bearer token authentication
    key: String,
    /// Optional key ID for HMAC authentication
    key_id: Option<String>,
}

impl ApiKeyProvider {
    /// Create a new API Key provider
    ///
    /// # Arguments
    /// * `key` - The API key (used as Bearer token or HMAC secret)
    /// * `key_id` - Optional key ID for HMAC authentication
    pub fn new(key: String, key_id: Option<String>) -> Self {
        Self { key, key_id }
    }

    /// Check Bearer token authentication
    fn check_bearer(&self, auth_header: &str) -> Result<(), AuthError> {
        if let Some(token) = auth_header.strip_prefix("Bearer ") {
            let provided_token = token.trim();
            if provided_token == self.key {
                Ok(())
            } else {
                Err(AuthError::invalid("Invalid Bearer token"))
            }
        } else {
            Err(AuthError::invalid("Malformed Bearer authentication header"))
        }
    }

    /// Check HMAC signature authentication
    fn check_hmac(&self, auth_header: &str, path: &str) -> Result<(), AuthError> {
        if let Some(hmac_part) = auth_header.strip_prefix("SB-HMAC ") {
            self.verify_hmac_signature(hmac_part.trim(), path)
        } else {
            Err(AuthError::invalid("Malformed HMAC authentication header"))
        }
    }

    /// Verify HMAC signature using the format: keyId:timestamp:signature
    fn verify_hmac_signature(&self, hmac_auth: &str, path: &str) -> Result<(), AuthError> {
        // Parse HMAC auth string: keyId:timestamp:signature
        let parts: Vec<&str> = hmac_auth.split(':').collect();
        if parts.len() != 3 {
            return Err(AuthError::invalid(
                "HMAC authentication format must be keyId:timestamp:signature",
            ));
        }

        let (provided_key_id, timestamp_str, provided_signature) = (parts[0], parts[1], parts[2]);

        // Verify key ID if configured
        if let Some(expected_key_id) = &self.key_id {
            if provided_key_id != expected_key_id {
                return Err(AuthError::invalid("Invalid key ID"));
            }
        }

        // Parse and validate timestamp
        let timestamp = timestamp_str
            .parse::<u64>()
            .map_err(|_| AuthError::invalid("Invalid timestamp format"))?;

        // Check time window (5 minutes = 300 seconds)
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| AuthError::internal("System time error"))?
            .as_secs();

        if now.abs_diff(timestamp) > 300 {
            return Err(AuthError::expired(
                "Authentication timestamp outside 5-minute window",
            ));
        }

        // Create message to sign: timestamp||path
        let message = format!("{}{}", timestamp, path);

        // Calculate expected signature using HMAC-SHA256
        let mut mac = HmacSha256::new_from_slice(self.key.as_bytes())
            .map_err(|_| AuthError::internal("Invalid HMAC key"))?;
        mac.update(message.as_bytes());
        let expected = mac.finalize().into_bytes();
        let expected_hex = hex::encode(expected);

        // Constant-time comparison to prevent timing attacks
        if expected_hex
            .as_bytes()
            .ct_eq(provided_signature.as_bytes())
            .into()
        {
            Ok(())
        } else {
            Err(AuthError::invalid("Invalid HMAC signature"))
        }
    }
}

impl AuthProvider for ApiKeyProvider {
    fn check(&self, headers: &HashMap<String, String>, path: &str) -> Result<(), AuthError> {
        let auth_header = headers
            .get("authorization")
            .ok_or_else(|| AuthError::missing("Authorization header required"))?;

        let auth_header = auth_header.trim();

        // Try Bearer token authentication first
        if auth_header.starts_with("Bearer ") {
            return self.check_bearer(auth_header);
        }

        // Try HMAC authentication
        if auth_header.starts_with("SB-HMAC ") {
            return self.check_hmac(auth_header, path);
        }

        Err(AuthError::invalid(
            "Unsupported authentication method. Use Bearer token or SB-HMAC",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bearer_auth_success() {
        let provider = ApiKeyProvider::new("secret123".to_string(), None);
        let mut headers = HashMap::new();
        headers.insert("authorization".to_string(), "Bearer secret123".to_string());

        assert!(provider.check(&headers, "/test").is_ok());
    }

    #[test]
    fn test_bearer_auth_failure() {
        let provider = ApiKeyProvider::new("secret123".to_string(), None);
        let mut headers = HashMap::new();
        headers.insert("authorization".to_string(), "Bearer wrongtoken".to_string());

        let result = provider.check(&headers, "/test");
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .message()
            .contains("Invalid Bearer token"));
    }

    #[test]
    fn test_bearer_auth_with_whitespace() {
        let provider = ApiKeyProvider::new("secret123".to_string(), None);
        let mut headers = HashMap::new();
        headers.insert(
            "authorization".to_string(),
            "  Bearer   secret123  ".to_string(),
        );

        assert!(provider.check(&headers, "/test").is_ok());
    }

    #[test]
    fn test_missing_auth_header() {
        let provider = ApiKeyProvider::new("secret123".to_string(), None);
        let headers = HashMap::new();

        let result = provider.check(&headers, "/test");
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .message()
            .contains("Authorization header required"));
    }

    #[test]
    fn test_hmac_auth_format_validation() {
        let provider = ApiKeyProvider::new("testsecret".to_string(), Some("testkey".to_string()));
        let mut headers = HashMap::new();

        // Invalid format: too few parts
        headers.insert(
            "authorization".to_string(),
            "SB-HMAC admin:123456".to_string(),
        );
        let result = provider.check(&headers, "/test");
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .message()
            .contains("keyId:timestamp:signature"));

        // Invalid timestamp
        headers.insert(
            "authorization".to_string(),
            "SB-HMAC admin:notanumber:sig".to_string(),
        );
        let result = provider.check(&headers, "/test");
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .message()
            .contains("Invalid timestamp format"));
    }

    #[test]
    fn test_hmac_auth_time_window() {
        let provider = ApiKeyProvider::new("testsecret".to_string(), Some("testkey".to_string()));
        let mut headers = HashMap::new();

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Too old (more than 5 minutes)
        let old_timestamp = now - 400; // 400 seconds ago
        headers.insert(
            "authorization".to_string(),
            format!("SB-HMAC testkey:{}:somesig", old_timestamp),
        );
        let result = provider.check(&headers, "/test");
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .message()
            .contains("outside 5-minute window"));

        // Future timestamp (more than 5 minutes ahead)
        let future_timestamp = now + 400; // 400 seconds in future
        headers.insert(
            "authorization".to_string(),
            format!("SB-HMAC testkey:{}:somesig", future_timestamp),
        );
        let result = provider.check(&headers, "/test");
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .message()
            .contains("outside 5-minute window"));
    }

    #[test]
    fn test_hmac_auth_signature_verification() {
        let provider = ApiKeyProvider::new("testsecret".to_string(), Some("testkey".to_string()));
        let mut headers = HashMap::new();

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let path = "/test";

        // Generate correct signature
        let message = format!("{}{}", now, path);
        let mut mac = HmacSha256::new_from_slice("testsecret".as_bytes()).unwrap();
        mac.update(message.as_bytes());
        let expected = mac.finalize().into_bytes();
        let correct_signature = hex::encode(expected);

        // Valid signature
        headers.insert(
            "authorization".to_string(),
            format!("SB-HMAC testkey:{}:{}", now, correct_signature),
        );
        assert!(provider.check(&headers, path).is_ok());

        // Invalid signature
        headers.insert(
            "authorization".to_string(),
            format!("SB-HMAC testkey:{}:invalidsig", now),
        );
        let result = provider.check(&headers, path);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .message()
            .contains("Invalid HMAC signature"));
    }

    #[test]
    fn test_hmac_auth_key_id_validation() {
        let provider =
            ApiKeyProvider::new("testsecret".to_string(), Some("expected_key".to_string()));
        let mut headers = HashMap::new();

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Wrong key ID
        headers.insert(
            "authorization".to_string(),
            format!("SB-HMAC wrong_key:{}:sig", now),
        );
        let result = provider.check(&headers, "/test");
        assert!(result.is_err());
        assert!(result.unwrap_err().message().contains("Invalid key ID"));
    }

    #[test]
    fn test_unsupported_auth_method() {
        let provider = ApiKeyProvider::new("secret".to_string(), None);
        let mut headers = HashMap::new();
        headers.insert(
            "authorization".to_string(),
            "Basic dXNlcjpwYXNz".to_string(),
        );

        let result = provider.check(&headers, "/test");
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .message()
            .contains("Unsupported authentication method"));
    }
}
