//! Security utilities for SingBox
//!
//! This crate provides security-focused utilities including:
//! - Credential redaction for logging
//! - Secure key loading strategies
//! - Memory-safe secret handling

#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

pub mod redact;
pub mod key_loading;

pub use redact::{redact_token, redact_key, redact_credential};
pub use key_loading::{KeySource, SecretLoader, LoadedSecret};