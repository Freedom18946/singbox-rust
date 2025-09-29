//! Security utilities for SingBox
//!
//! This crate provides security-focused utilities including:
//! - Credential redaction for logging
//! - Secure key loading strategies
//! - Memory-safe secret handling

#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

pub mod key_loading;
pub mod redact;

pub use key_loading::{KeySource, LoadedSecret, SecretLoader};
pub use redact::{redact_credential, redact_key, redact_token};
