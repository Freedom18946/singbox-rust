//! Global TLS client configuration
//!
//! Provides a process-wide TLS client configuration built from defaults plus
//! optional additional CA certificates from configuration. Transport builders
//! and outbounds can use this to share a consistent trust store.

use std::sync::Arc;

use once_cell::sync::OnceCell;
use rustls::{ClientConfig, RootCertStore};

static TLS_CLIENT_CONFIG: OnceCell<Arc<ClientConfig>> = OnceCell::new();
static TLS_CERT_IR: once_cell::sync::Lazy<RwLock<Option<sb_config::ir::CertificateIR>>> =
    once_cell::sync::Lazy::new(|| RwLock::new(None));

/// Return the global TLS client configuration, falling back to defaults.
pub fn client_config() -> Arc<ClientConfig> {
    if let Some(cfg) = TLS_CLIENT_CONFIG.get() {
        return Arc::clone(cfg);
    }
    default_config()
}

/// Apply TLS client config from IR certificate settings.
/// Safe to call multiple times; last applied wins.
pub fn apply_from_ir(cert: Option<&sb_config::ir::CertificateIR>) {
    let cfg = build_config(cert);
    // Replace if already set by creating a new OnceCell? OnceCell cannot be reset,
    // so we store latest into a static parking_lot RwLock? Work around: store into OnceCell on first call,
    // subsequent calls use a hidden global RwLock. To keep dependencies minimal, we rebuild only once;
    // if already set, just ignore. Hot-reload still updates transport mapping via ALPN/SNI.
    // For better hot-reload, also store into a static mutable under RwLock.
    // Simpler: use OnceCell only as lazy default, but expose an override via a separate static.
    *TLS_OVERRIDE.write() = Some(cfg);
    *TLS_CERT_IR.write() = cert.cloned();
}

// Override slot backed by RwLock so we can update on reloads.
use parking_lot::RwLock;
static TLS_OVERRIDE: once_cell::sync::Lazy<RwLock<Option<Arc<ClientConfig>>>> =
    once_cell::sync::Lazy::new(|| RwLock::new(None));

/// Internal: get current effective config (override or default)
fn effective() -> Arc<ClientConfig> {
    if let Some(cfg) = TLS_OVERRIDE.read().as_ref() {
        return Arc::clone(cfg);
    }
    client_config()
}

/// Default TLS client configuration using webpki roots.
fn default_config() -> Arc<ClientConfig> {
    super::ensure_rustls_crypto_provider();

    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    Arc::new(
        ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    )
}

/// Build client config from optional IR certificate settings.
fn build_config(cert: Option<&sb_config::ir::CertificateIR>) -> Arc<ClientConfig> {
    super::ensure_rustls_crypto_provider();

    let mut roots = base_root_store();

    if let Some(c) = cert {
        // Load CA from file paths
        for path in &c.ca_paths {
            match std::fs::read(path) {
                Ok(bytes) => {
                    let mut rd = std::io::BufReader::new(&bytes[..]);
                    for item in rustls_pemfile::certs(&mut rd) {
                        match item {
                            Ok(der) => {
                                let _ = roots.add(der);
                            }
                            Err(e) => {
                                tracing::warn!(target: "sb_core::tls", file=%path, error=%e, "failed to parse CA PEM item")
                            }
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!(target: "sb_core::tls", file=%path, error=%e, "failed to read CA file")
                }
            }
        }
        // Load inline PEM blocks
        for pem in &c.ca_pem {
            let mut rd = std::io::BufReader::new(pem.as_bytes());
            for item in rustls_pemfile::certs(&mut rd) {
                match item {
                    Ok(der) => {
                        let _ = roots.add(der);
                    }
                    Err(e) => {
                        tracing::warn!(target: "sb_core::tls", "failed to parse inline CA PEM item: {}", e)
                    }
                }
            }
        }
    }

    Arc::new(
        ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    )
}

/// Get effective config (override if set) — used by transport mapping
pub fn get_effective() -> Arc<ClientConfig> {
    effective()
}

/// Build a base RootCertStore from webpki roots and current top-level IR certificate settings.
pub fn base_root_store() -> RootCertStore {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    if let Some(ir) = TLS_CERT_IR.read().as_ref() {
        // Re-apply the same logic used in build_config
        for path in &ir.ca_paths {
            if let Ok(bytes) = std::fs::read(path) {
                let mut rd = std::io::BufReader::new(&bytes[..]);
                for der in rustls_pemfile::certs(&mut rd).flatten() {
                    let _ = roots.add(der);
                }
            }
        }
        for pem in &ir.ca_pem {
            let mut rd = std::io::BufReader::new(pem.as_bytes());
            for der in rustls_pemfile::certs(&mut rd).flatten() {
                let _ = roots.add(der);
            }
        }
    }
    roots
}
