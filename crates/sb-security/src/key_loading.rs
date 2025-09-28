//! Secure key loading strategies and utilities
//!
//! This module provides secure methods for loading cryptographic keys and secrets
//! from various sources (environment variables, files, inline configuration) with
//! proper security considerations.

use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::ZeroizeOnDrop;

/// Errors that can occur during key loading
#[derive(Error, Debug)]
pub enum KeyLoadingError {
    #[error("Environment variable '{name}' not found")]
    EnvVarNotFound { name: String },

    #[error("Failed to read key file '{path}': {source}")]
    FileReadError {
        path: String,
        source: std::io::Error,
    },

    #[error("Key file '{path}' is empty")]
    EmptyKeyFile { path: String },

    #[error("Inline key configuration is empty")]
    EmptyInlineKey,

    #[error("Invalid key format: {reason}")]
    InvalidKeyFormat { reason: String },

    #[error("Key validation failed: {reason}")]
    ValidationFailed { reason: String },

    #[error("Insecure key source configuration: {reason}")]
    InsecureConfiguration { reason: String },
}

/// Sources from which keys/secrets can be loaded
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "source", rename_all = "snake_case")]
pub enum KeySource {
    /// Load from environment variable
    Env {
        /// Environment variable name
        name: String,
        /// Optional fallback if env var is not set
        fallback: Option<String>,
    },
    /// Load from file
    File {
        /// File path
        path: String,
        /// Whether to trim whitespace from file contents
        trim: Option<bool>,
    },
    /// Use inline configuration (not recommended for production)
    Inline {
        /// The actual key/secret value
        value: String,
    },
}

impl KeySource {
    /// Create an environment variable source
    pub fn env(name: impl Into<String>) -> Self {
        Self::Env {
            name: name.into(),
            fallback: None,
        }
    }

    /// Create an environment variable source with fallback
    pub fn env_with_fallback(name: impl Into<String>, fallback: impl Into<String>) -> Self {
        Self::Env {
            name: name.into(),
            fallback: Some(fallback.into()),
        }
    }

    /// Create a file source
    pub fn file(path: impl Into<String>) -> Self {
        Self::File {
            path: path.into(),
            trim: Some(true),
        }
    }

    /// Create an inline source (not recommended for production)
    pub fn inline(value: impl Into<String>) -> Self {
        Self::Inline {
            value: value.into(),
        }
    }

    /// Check if this key source is considered secure for production use
    pub fn is_secure_for_production(&self) -> bool {
        match self {
            KeySource::Env { .. } => true,
            KeySource::File { .. } => true,
            KeySource::Inline { .. } => false, // Inline is never secure for production
        }
    }

    /// Get a description of the key source for logging (without exposing values)
    pub fn description(&self) -> String {
        match self {
            KeySource::Env { name, fallback } => {
                if fallback.is_some() {
                    format!("env:{} (with fallback)", name)
                } else {
                    format!("env:{}", name)
                }
            }
            KeySource::File { path, .. } => format!("file:{}", path),
            KeySource::Inline { .. } => "inline:***".to_string(),
        }
    }
}

/// A securely loaded secret that automatically zeroes its memory on drop
#[derive(Clone, ZeroizeOnDrop)]
pub struct LoadedSecret {
    /// The actual secret value
    value: String,
    /// Source description for logging
    source: String,
    /// Whether this secret was loaded from a secure source
    is_secure: bool,
}

impl LoadedSecret {
    /// Create a new loaded secret
    fn new(value: String, source: String, is_secure: bool) -> Self {
        Self {
            value,
            source,
            is_secure,
        }
    }

    /// Get the secret value (use with caution!)
    pub fn expose(&self) -> &str {
        &self.value
    }

    /// Get the source description (safe for logging)
    pub fn source(&self) -> &str {
        &self.source
    }

    /// Check if this secret was loaded from a secure source
    pub fn is_secure(&self) -> bool {
        self.is_secure
    }

    /// Get the length of the secret (safe for logging)
    pub fn len(&self) -> usize {
        self.value.len()
    }

    /// Check if the secret is empty
    pub fn is_empty(&self) -> bool {
        self.value.is_empty()
    }

    /// Validate the secret using a custom validator
    pub fn validate<F>(&self, validator: F) -> Result<(), KeyLoadingError>
    where
        F: FnOnce(&str) -> Result<(), String>,
    {
        validator(&self.value).map_err(|reason| KeyLoadingError::ValidationFailed { reason })
    }
}

impl std::fmt::Debug for LoadedSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoadedSecret")
            .field("source", &self.source)
            .field("length", &self.value.len())
            .field("is_secure", &self.is_secure)
            .field("value", &"[REDACTED]")
            .finish()
    }
}

/// Secret loader with security policies
pub struct SecretLoader {
    /// Whether to allow insecure sources in production
    allow_insecure_sources: bool,
    /// Environment variable cache to avoid repeated lookups
    env_cache: HashMap<String, Option<String>>,
}

impl Default for SecretLoader {
    fn default() -> Self {
        Self::new()
    }
}

impl SecretLoader {
    /// Create a new secret loader with default security settings
    pub fn new() -> Self {
        Self {
            allow_insecure_sources: false,
            env_cache: HashMap::new(),
        }
    }

    /// Create a secret loader that allows insecure sources (for development)
    pub fn allow_insecure() -> Self {
        Self {
            allow_insecure_sources: true,
            env_cache: HashMap::new(),
        }
    }

    /// Load a secret from the specified source
    pub fn load(&mut self, source: &KeySource) -> Result<LoadedSecret, KeyLoadingError> {
        // Check security policy
        if !self.allow_insecure_sources && !source.is_secure_for_production() {
            return Err(KeyLoadingError::InsecureConfiguration {
                reason: format!(
                    "Insecure key source '{}' not allowed in production mode",
                    source.description()
                ),
            });
        }

        match source {
            KeySource::Env { name, fallback } => self.load_from_env(name, fallback.as_deref()),
            KeySource::File { path, trim } => self.load_from_file(path, trim.unwrap_or(true)),
            KeySource::Inline { value } => self.load_inline(value),
        }
    }

    /// Load from environment variable
    fn load_from_env(
        &mut self,
        name: &str,
        fallback: Option<&str>,
    ) -> Result<LoadedSecret, KeyLoadingError> {
        // Check cache first
        let value = if let Some(cached) = self.env_cache.get(name) {
            cached.clone()
        } else {
            let env_value = std::env::var(name).ok();
            self.env_cache.insert(name.to_string(), env_value.clone());
            env_value
        };

        let (final_value, actual_source) = match (value, fallback) {
            (Some(env_val), _) => {
                if env_val.is_empty() {
                    return Err(KeyLoadingError::EnvVarNotFound {
                        name: name.to_string(),
                    });
                }
                (env_val, format!("env:{}", name))
            }
            (None, Some(fallback_val)) => {
                if fallback_val.is_empty() {
                    return Err(KeyLoadingError::EnvVarNotFound {
                        name: name.to_string(),
                    });
                }
                (fallback_val.to_string(), format!("env:{}(fallback)", name))
            }
            (None, None) => {
                return Err(KeyLoadingError::EnvVarNotFound {
                    name: name.to_string(),
                });
            }
        };

        Ok(LoadedSecret::new(final_value, actual_source, true))
    }

    /// Load from file
    fn load_from_file(&self, path: &str, trim: bool) -> Result<LoadedSecret, KeyLoadingError> {
        let content = std::fs::read_to_string(path).map_err(|source| {
            KeyLoadingError::FileReadError {
                path: path.to_string(),
                source,
            }
        })?;

        let final_content = if trim { content.trim().to_string() } else { content };

        if final_content.is_empty() {
            return Err(KeyLoadingError::EmptyKeyFile {
                path: path.to_string(),
            });
        }

        // Check file permissions for security
        self.validate_file_permissions(path)?;

        Ok(LoadedSecret::new(
            final_content,
            format!("file:{}", path),
            true,
        ))
    }

    /// Load inline value
    fn load_inline(&self, value: &str) -> Result<LoadedSecret, KeyLoadingError> {
        if value.is_empty() {
            return Err(KeyLoadingError::EmptyInlineKey);
        }

        Ok(LoadedSecret::new(
            value.to_string(),
            "inline:[REDACTED]".to_string(),
            false,
        ))
    }

    /// Validate file permissions for security
    fn validate_file_permissions(&self, path: &str) -> Result<(), KeyLoadingError> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            let metadata = std::fs::metadata(path).map_err(|source| {
                KeyLoadingError::FileReadError {
                    path: path.to_string(),
                    source,
                }
            })?;

            let permissions = metadata.permissions();
            let mode = permissions.mode();

            // Check that file is not world-readable or group-readable
            if mode & 0o044 != 0 {
                return Err(KeyLoadingError::InsecureConfiguration {
                    reason: format!(
                        "Key file '{}' has insecure permissions {:o} (should be 0o600 or similar)",
                        path, mode & 0o777
                    ),
                });
            }
        }

        #[cfg(not(unix))]
        {
            // On non-Unix systems, we can't check file permissions in the same way
            // Just log a warning but don't fail
            tracing::warn!("File permission validation not available on this platform for: {}", path);
        }

        Ok(())
    }

    /// Clear the environment variable cache
    pub fn clear_cache(&mut self) {
        self.env_cache.clear();
    }
}

/// Common validators for different types of secrets
pub mod validators {

    /// Validate that a secret meets minimum length requirements
    pub fn min_length(min_len: usize) -> impl Fn(&str) -> Result<(), String> {
        move |secret: &str| {
            if secret.len() < min_len {
                Err(format!(
                    "Secret too short: {} characters (minimum: {})",
                    secret.len(),
                    min_len
                ))
            } else {
                Ok(())
            }
        }
    }

    /// Validate that a secret is a valid base64 string
    pub fn base64() -> impl Fn(&str) -> Result<(), String> {
        |secret: &str| {
            use base64::{Engine as _, engine::general_purpose::STANDARD};
            STANDARD.decode(secret.trim()).map_err(|e| format!("Invalid base64: {}", e))?;
            Ok(())
        }
    }

    /// Validate that a secret is a valid hexadecimal string
    pub fn hex() -> impl Fn(&str) -> Result<(), String> {
        |secret: &str| {
            if secret.trim().chars().all(|c| c.is_ascii_hexdigit()) {
                Ok(())
            } else {
                Err("Invalid hexadecimal string".to_string())
            }
        }
    }

    /// Validate that a secret matches a specific pattern
    pub fn pattern(regex: &'static str) -> impl Fn(&str) -> Result<(), String> {
        move |secret: &str| {
            // Simple pattern matching without regex dependency
            // For now, just check basic patterns
            match regex {
                r"^[A-Za-z0-9+/]*={0,2}$" => base64()(secret), // Base64 pattern
                r"^[0-9a-fA-F]+$" => hex()(secret),             // Hex pattern
                _ => Ok(()), // For now, accept any other pattern
            }
        }
    }

    /// Validate that a secret contains only printable ASCII characters
    pub fn ascii_printable() -> impl Fn(&str) -> Result<(), String> {
        |secret: &str| {
            if secret.chars().all(|c| c.is_ascii() && !c.is_control()) {
                Ok(())
            } else {
                Err("Secret contains non-printable characters".to_string())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_key_source_security() {
        assert!(KeySource::env("TEST_KEY").is_secure_for_production());
        assert!(KeySource::file("/path/to/key").is_secure_for_production());
        assert!(!KeySource::inline("secret").is_secure_for_production());
    }

    #[test]
    fn test_key_source_description() {
        assert_eq!(KeySource::env("API_KEY").description(), "env:API_KEY");
        assert_eq!(
            KeySource::env_with_fallback("API_KEY", "default").description(),
            "env:API_KEY (with fallback)"
        );
        assert_eq!(KeySource::file("/path/to/key").description(), "file:/path/to/key");
        assert_eq!(KeySource::inline("secret").description(), "inline:***");
    }

    #[test]
    fn test_loaded_secret_properties() {
        let secret = LoadedSecret::new("test-secret".to_string(), "test-source".to_string(), true);

        assert_eq!(secret.expose(), "test-secret");
        assert_eq!(secret.source(), "test-source");
        assert!(secret.is_secure());
        assert_eq!(secret.len(), 11);
        assert!(!secret.is_empty());
    }

    #[test]
    fn test_secret_loader_env() {
        std::env::set_var("TEST_SECRET_LOADER", "test-value");

        let mut loader = SecretLoader::new();
        let source = KeySource::env("TEST_SECRET_LOADER");
        let secret = loader.load(&source).unwrap();

        assert_eq!(secret.expose(), "test-value");
        assert_eq!(secret.source(), "env:TEST_SECRET_LOADER");
        assert!(secret.is_secure());

        std::env::remove_var("TEST_SECRET_LOADER");
    }

    #[test]
    fn test_secret_loader_env_fallback() {
        let mut loader = SecretLoader::new();
        let source = KeySource::env_with_fallback("NONEXISTENT_VAR", "fallback-value");
        let secret = loader.load(&source).unwrap();

        assert_eq!(secret.expose(), "fallback-value");
        assert_eq!(secret.source(), "env:NONEXISTENT_VAR(fallback)");
        assert!(secret.is_secure());
    }

    #[test]
    fn test_secret_loader_file() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "  file-secret-content  ").unwrap();

        // Set secure permissions (Unix only)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let permissions = std::fs::Permissions::from_mode(0o600);
            std::fs::set_permissions(file.path(), permissions).unwrap();
        }

        let mut loader = SecretLoader::new();
        let source = KeySource::file(file.path().to_string_lossy().to_string());
        let secret = loader.load(&source).unwrap();

        assert_eq!(secret.expose(), "file-secret-content"); // Trimmed
        assert!(secret.source().starts_with("file:"));
        assert!(secret.is_secure());
    }

    #[test]
    fn test_secret_loader_inline_secure_mode() {
        let mut loader = SecretLoader::new(); // Secure mode (default)
        let source = KeySource::inline("inline-secret");
        let result = loader.load(&source);

        assert!(result.is_err());
        match result.unwrap_err() {
            KeyLoadingError::InsecureConfiguration { .. } => {} // Expected
            _ => panic!("Expected InsecureConfiguration error"),
        }
    }

    #[test]
    fn test_secret_loader_inline_allow_insecure() {
        let mut loader = SecretLoader::allow_insecure();
        let source = KeySource::inline("inline-secret");
        let secret = loader.load(&source).unwrap();

        assert_eq!(secret.expose(), "inline-secret");
        assert_eq!(secret.source(), "inline:[REDACTED]");
        assert!(!secret.is_secure());
    }

    #[test]
    fn test_validators() {
        use validators::*;

        // Test min_length validator
        let min_len_validator = min_length(8);
        assert!(min_len_validator("12345678").is_ok());
        assert!(min_len_validator("1234567").is_err());

        // Test base64 validator
        let base64_validator = base64();
        assert!(base64_validator("SGVsbG8gV29ybGQ=").is_ok());
        assert!(base64_validator("invalid base64!").is_err());

        // Test hex validator
        let hex_validator = hex();
        assert!(hex_validator("deadbeef").is_ok());
        assert!(hex_validator("not-hex").is_err());

        // Test ASCII printable validator
        let ascii_validator = ascii_printable();
        assert!(ascii_validator("Hello World 123!").is_ok());
        assert!(ascii_validator("Hello\x00World").is_err());
    }

    #[test]
    fn test_loaded_secret_validation() {
        let secret = LoadedSecret::new("test123".to_string(), "test".to_string(), true);

        // Should pass min length validation
        assert!(secret.validate(validators::min_length(5)).is_ok());

        // Should fail min length validation
        assert!(secret.validate(validators::min_length(10)).is_err());
    }

    #[test]
    fn test_loaded_secret_debug() {
        let secret = LoadedSecret::new("secret-value".to_string(), "test-source".to_string(), true);
        let debug_output = format!("{:?}", secret);

        // Should not contain the actual secret
        assert!(!debug_output.contains("secret-value"));
        // Should contain redacted placeholder
        assert!(debug_output.contains("[REDACTED]"));
        // Should contain metadata
        assert!(debug_output.contains("test-source"));
        assert!(debug_output.contains("12")); // length
    }
}