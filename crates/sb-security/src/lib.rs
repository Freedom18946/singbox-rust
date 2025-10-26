//! Security utilities for SingBox
//!
//! This crate provides security-focused utilities including:
//! - Credential redaction for logging
//! - Secure key loading strategies
//! - Memory-safe secret handling
//! - Constant-time credential verification (timing-attack resistant)
//!
//! # Examples
//!
//! ## Constant-time credential verification
//!
//! ```
//! use sb_security::verify_credentials;
//!
//! let valid = verify_credentials(
//!     Some("admin"),
//!     Some("secret"),
//!     "admin",
//!     "secret"
//! );
//! assert!(valid);
//! ```
//!
//! ## Secure credential redaction
//!
//! ```
//! use sb_security::redact_token;
//!
//! let token = "Bearer abc123def456ghi789";
//! let redacted = redact_token(token);
//! assert_eq!(redacted, "Bear********i789");
//! ```
//!
//! ## Secure key loading
//!
//! ```no_run
//! use sb_security::{KeySource, SecretLoader};
//!
//! let mut loader = SecretLoader::new();
//! let source = KeySource::env("API_KEY");
//! let secret = loader.load(&source).expect("Failed to load key");
//!
//! // Use secret.expose() only when needed for actual operations
//! println!("Loaded from: {}", secret.source());
//! ```

#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

pub mod credentials;
pub mod key_loading;
pub mod redact;

pub use credentials::{verify_credentials, verify_credentials_required, verify_secret};
pub use key_loading::{KeySource, LoadedSecret, SecretLoader};
pub use redact::{redact_credential, redact_key, redact_token};
