//! Global TLS configuration utilities.
//!
//! Provides a base root certificate store from webpki roots, and a process-wide
//! global certificate override mechanism. This centralizes TLS trust configuration
//! so that all components (DNS, transports, outbounds) share a consistent trust store.

use parking_lot::RwLock;
use rustls::{ClientConfig, RootCertStore};
use std::sync::Arc;

static TLS_OVERRIDE: once_cell::sync::Lazy<RwLock<Option<Arc<ClientConfig>>>> =
    once_cell::sync::Lazy::new(|| RwLock::new(None));

static EXTRA_CA_PATHS: once_cell::sync::Lazy<RwLock<Vec<String>>> =
    once_cell::sync::Lazy::new(|| RwLock::new(Vec::new()));

static EXTRA_CA_PEMS: once_cell::sync::Lazy<RwLock<Vec<String>>> =
    once_cell::sync::Lazy::new(|| RwLock::new(Vec::new()));

/// Return a base `RootCertStore` from webpki roots plus any configured extra CAs.
pub fn base_root_store() -> RootCertStore {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    // Add extra CA paths
    for path in EXTRA_CA_PATHS.read().iter() {
        if let Ok(bytes) = std::fs::read(path) {
            let mut rd = std::io::BufReader::new(&bytes[..]);
            for der in rustls_pemfile::certs(&mut rd).flatten() {
                let _ = roots.add(der);
            }
        }
    }
    // Add extra inline PEMs
    for pem in EXTRA_CA_PEMS.read().iter() {
        let mut rd = std::io::BufReader::new(pem.as_bytes());
        for der in rustls_pemfile::certs(&mut rd).flatten() {
            let _ = roots.add(der);
        }
    }

    roots
}

/// Apply extra CA certificates (paths and inline PEMs) to the global store.
///
/// After calling this, `base_root_store()` will include these CAs.
/// Also rebuilds the global override config.
pub fn apply_extra_cas(ca_paths: &[String], ca_pems: &[String]) {
    *EXTRA_CA_PATHS.write() = ca_paths.to_vec();
    *EXTRA_CA_PEMS.write() = ca_pems.to_vec();

    // Rebuild override config
    let roots = base_root_store();
    let cfg = Arc::new(
        ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    );
    *TLS_OVERRIDE.write() = Some(cfg);
}

/// Get the effective global TLS client configuration.
///
/// Returns the override config if set, otherwise builds a default from webpki roots.
pub fn get_effective() -> Arc<ClientConfig> {
    if let Some(cfg) = TLS_OVERRIDE.read().as_ref() {
        return Arc::clone(cfg);
    }
    default_config()
}

/// Build a default TLS client configuration from webpki roots.
fn default_config() -> Arc<ClientConfig> {
    super::ensure_crypto_provider();
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    Arc::new(
        ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    )
}
