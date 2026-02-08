//! TLS utilities and unified configuration
//!
//! Most TLS infrastructure has been moved to the `sb-tls` crate. This module
//! provides backward-compatible re-exports and sb-core-specific integration
//! (e.g., CertificateIR handling from sb-config).

pub mod danger;
pub mod global;
pub mod trust;

pub use trust::{alpn_from_env, mk_client, pins_from_env, TlsOpts};

/// Ensure the rustls crypto provider is installed.
///
/// Delegates to `sb_tls::ensure_crypto_provider()`.
pub(crate) fn ensure_rustls_crypto_provider() {
    sb_tls::ensure_crypto_provider();
}
