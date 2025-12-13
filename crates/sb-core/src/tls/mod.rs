//! TLS utilities and unified configuration

pub mod danger;
pub mod global;
pub mod trust;

pub use trust::{alpn_from_env, mk_client, pins_from_env, TlsOpts};

use std::sync::OnceLock;

static RUSTLS_CRYPTO_PROVIDER_INSTALLED: OnceLock<()> = OnceLock::new();

pub(crate) fn ensure_rustls_crypto_provider() {
    RUSTLS_CRYPTO_PROVIDER_INSTALLED.get_or_init(|| {
        // rustls 0.23 requires selecting a process-level CryptoProvider when multiple providers
        // are present (e.g. ring + aws-lc-rs via transitive deps). Prefer ring for consistency.
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}
