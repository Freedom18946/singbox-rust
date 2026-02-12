//! Global TLS configuration utilities.
//!
//! Provides certificate store modes (System/Mozilla/None) and a process-wide
//! global certificate override mechanism. This centralizes TLS trust configuration
//! so that all components (DNS, transports, outbounds) share a consistent trust store.

use parking_lot::RwLock;
use rustls::{ClientConfig, RootCertStore};
use std::sync::{Arc, LazyLock};

static TLS_OVERRIDE: LazyLock<RwLock<Option<Arc<ClientConfig>>>> =
    LazyLock::new(|| RwLock::new(None));

static EXTRA_CA_PATHS: LazyLock<RwLock<Vec<String>>> = LazyLock::new(|| RwLock::new(Vec::new()));

static EXTRA_CA_PEMS: LazyLock<RwLock<Vec<String>>> = LazyLock::new(|| RwLock::new(Vec::new()));

static CERT_DIRS: LazyLock<RwLock<Vec<String>>> = LazyLock::new(|| RwLock::new(Vec::new()));

static STORE_MODE: LazyLock<RwLock<CertificateStoreMode>> =
    LazyLock::new(|| RwLock::new(CertificateStoreMode::System));

/// Certificate store mode (Go parity: system/mozilla/none).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertificateStoreMode {
    /// Load OS-native certificate pool (default, Go parity)
    System,
    /// Use built-in Mozilla/webpki root certificates
    Mozilla,
    /// Empty pool — only custom CAs will be trusted
    None,
}

impl CertificateStoreMode {
    /// Parse from string (case-insensitive).
    pub fn from_str_opt(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "mozilla" => Self::Mozilla,
            "none" => Self::None,
            _ => Self::System, // default
        }
    }
}

/// Set the global certificate store mode.
pub fn set_store_mode(mode: CertificateStoreMode) {
    *STORE_MODE.write() = mode;
}

/// Set certificate directory paths for recursive PEM loading.
pub fn set_cert_directories(dirs: Vec<String>) {
    *CERT_DIRS.write() = dirs;
}

/// Return a base `RootCertStore` according to the configured mode plus any extra CAs.
pub fn base_root_store() -> RootCertStore {
    let mode = *STORE_MODE.read();
    let mut roots = RootCertStore::empty();

    match mode {
        CertificateStoreMode::System => {
            // Try native certs first, fall back to mozilla
            #[cfg(feature = "native-certs")]
            {
                match rustls_native_certs::load_native_certs() {
                    Ok(certs) => {
                        for cert in certs {
                            let _ = roots.add(cert);
                        }
                        if roots.is_empty() {
                            tracing::warn!(
                                "No native certs found, falling back to mozilla roots"
                            );
                            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
                        }
                    }
                    Err(e) => {
                        tracing::warn!(
                            "Failed to load native certs: {}, falling back to mozilla roots",
                            e
                        );
                        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
                    }
                }
            }
            #[cfg(not(feature = "native-certs"))]
            {
                roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            }
        }
        CertificateStoreMode::Mozilla => {
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        }
        CertificateStoreMode::None => {
            // Empty pool — only custom CAs will be added below
        }
    }

    // Add extra CA paths
    for path in EXTRA_CA_PATHS.read().iter() {
        load_pem_file(&mut roots, path);
    }
    // Add extra inline PEMs
    for pem in EXTRA_CA_PEMS.read().iter() {
        let mut rd = std::io::BufReader::new(pem.as_bytes());
        for der in rustls_pemfile::certs(&mut rd).flatten() {
            let _ = roots.add(der);
        }
    }
    // Add certificate directories (recursive PEM loading)
    for dir in CERT_DIRS.read().iter() {
        load_pem_directory(&mut roots, dir);
    }

    roots
}

/// Load PEM certificates from a single file.
fn load_pem_file(roots: &mut RootCertStore, path: &str) {
    if let Ok(bytes) = std::fs::read(path) {
        let mut rd = std::io::BufReader::new(&bytes[..]);
        for der in rustls_pemfile::certs(&mut rd).flatten() {
            let _ = roots.add(der);
        }
    }
}

/// Recursively load PEM certificates from a directory.
fn load_pem_directory(roots: &mut RootCertStore, dir_path: &str) {
    let Ok(entries) = std::fs::read_dir(dir_path) else {
        tracing::warn!("Cannot read certificate directory: {}", dir_path);
        return;
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            load_pem_directory(roots, &path.to_string_lossy());
        } else if path
            .extension()
            .map(|e| e == "pem" || e == "crt" || e == "cer")
            .unwrap_or(false)
        {
            load_pem_file(roots, &path.to_string_lossy());
        }
    }
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

/// Apply full certificate configuration from IR.
pub fn apply_certificate_config(
    store_mode: Option<&str>,
    ca_paths: &[String],
    ca_pems: &[String],
    cert_dir: Option<&str>,
) {
    if let Some(mode_str) = store_mode {
        set_store_mode(CertificateStoreMode::from_str_opt(mode_str));
    }
    if let Some(dir) = cert_dir {
        set_cert_directories(vec![dir.to_string()]);
    }
    apply_extra_cas(ca_paths, ca_pems);
}

/// Get the effective global TLS client configuration.
///
/// Returns the override config if set, otherwise builds a default from configured roots.
pub fn get_effective() -> Arc<ClientConfig> {
    if let Some(cfg) = TLS_OVERRIDE.read().as_ref() {
        return Arc::clone(cfg);
    }
    default_config()
}

/// Build a default TLS client configuration from configured roots.
fn default_config() -> Arc<ClientConfig> {
    super::ensure_crypto_provider();
    let roots = base_root_store();
    Arc::new(
        ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    )
}

// ---------------------------------------------------------------------------
// Certificate File Watcher (L14.1.2 — Hot Reload)
// ---------------------------------------------------------------------------

/// Certificate file watcher that triggers TLS config reload on changes.
///
/// Uses the `notify` crate to monitor certificate files and directories. When
/// a file is modified, created, or removed, the global TLS config is rebuilt
/// via `apply_extra_cas()`. Dropping the watcher cancels the shutdown token
/// and stops watching.
#[cfg(feature = "cert-watch")]
pub struct CertificateWatcher {
    _watcher: notify::RecommendedWatcher,
    shutdown: tokio_util::sync::CancellationToken,
}

#[cfg(feature = "cert-watch")]
impl CertificateWatcher {
    /// Start watching certificate paths for changes.
    ///
    /// On any file modification / creation / removal event, rebuilds the
    /// global TLS config by calling `apply_extra_cas` with the originally
    /// supplied `ca_paths` and `ca_pems`.
    ///
    /// # Arguments
    /// * `ca_paths`  - Individual CA certificate file paths to watch.
    /// * `ca_pems`   - Inline PEM strings (not watched, but passed to reload).
    /// * `cert_dirs` - Directories watched recursively for certificate changes.
    /// * `shutdown`  - Cancellation token; when cancelled the callback becomes a no-op.
    pub fn start(
        ca_paths: Vec<String>,
        ca_pems: Vec<String>,
        cert_dirs: Vec<String>,
        shutdown: tokio_util::sync::CancellationToken,
    ) -> Result<Self, notify::Error> {
        use notify::{Event, RecursiveMode, Watcher};

        let ca_paths_reload = ca_paths.clone();
        let ca_pems_reload = ca_pems.clone();
        let shutdown_cb = shutdown.clone();

        let mut watcher =
            notify::recommended_watcher(move |res: Result<Event, notify::Error>| {
                if shutdown_cb.is_cancelled() {
                    return;
                }
                match res {
                    Ok(event) => {
                        if event.kind.is_modify()
                            || event.kind.is_create()
                            || event.kind.is_remove()
                        {
                            tracing::info!(
                                paths = ?event.paths,
                                "Certificate file change detected, reloading TLS config"
                            );
                            apply_extra_cas(&ca_paths_reload, &ca_pems_reload);
                        }
                    }
                    Err(e) => {
                        tracing::warn!("Certificate watch error: {}", e);
                    }
                }
            })?;

        // Watch individual CA file paths (non-recursive).
        for path in &ca_paths {
            if let Err(e) =
                watcher.watch(std::path::Path::new(path), RecursiveMode::NonRecursive)
            {
                tracing::warn!("Cannot watch certificate path {}: {}", path, e);
            }
        }

        // Watch certificate directories recursively.
        for dir in &cert_dirs {
            if let Err(e) =
                watcher.watch(std::path::Path::new(dir), RecursiveMode::Recursive)
            {
                tracing::warn!("Cannot watch certificate directory {}: {}", dir, e);
            }
        }

        tracing::info!(
            ca_paths = ca_paths.len(),
            cert_dirs = cert_dirs.len(),
            "Certificate watcher started"
        );

        Ok(Self {
            _watcher: watcher,
            shutdown,
        })
    }

    /// Stop the certificate watcher by cancelling the shutdown token.
    pub fn stop(&self) {
        self.shutdown.cancel();
        tracing::info!("Certificate watcher stopped");
    }
}

#[cfg(feature = "cert-watch")]
impl Drop for CertificateWatcher {
    fn drop(&mut self) {
        self.shutdown.cancel();
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_store_mode_parsing() {
        assert_eq!(
            CertificateStoreMode::from_str_opt("system"),
            CertificateStoreMode::System
        );
        assert_eq!(
            CertificateStoreMode::from_str_opt("mozilla"),
            CertificateStoreMode::Mozilla
        );
        assert_eq!(
            CertificateStoreMode::from_str_opt("none"),
            CertificateStoreMode::None
        );
        assert_eq!(
            CertificateStoreMode::from_str_opt("System"),
            CertificateStoreMode::System
        );
        assert_eq!(
            CertificateStoreMode::from_str_opt("MOZILLA"),
            CertificateStoreMode::Mozilla
        );
        assert_eq!(
            CertificateStoreMode::from_str_opt("unknown"),
            CertificateStoreMode::System
        );
    }

    #[test]
    fn test_mozilla_mode_non_empty() {
        set_store_mode(CertificateStoreMode::Mozilla);
        let roots = base_root_store();
        assert!(!roots.is_empty(), "Mozilla root store should not be empty");
        // Reset
        set_store_mode(CertificateStoreMode::System);
    }

    #[test]
    fn test_none_mode_empty() {
        set_store_mode(CertificateStoreMode::None);
        // Clear any extras
        *EXTRA_CA_PATHS.write() = Vec::new();
        *EXTRA_CA_PEMS.write() = Vec::new();
        *CERT_DIRS.write() = Vec::new();
        let roots = base_root_store();
        assert!(roots.is_empty(), "None mode should produce empty root store");
        // Reset
        set_store_mode(CertificateStoreMode::System);
    }

    #[test]
    fn test_system_mode_non_empty() {
        set_store_mode(CertificateStoreMode::System);
        let roots = base_root_store();
        // On macOS/Linux, system mode should find certs (or fall back to mozilla)
        assert!(!roots.is_empty(), "System mode should have certificates");
    }

    #[test]
    fn test_directory_loading_nonexistent() {
        let mut roots = RootCertStore::empty();
        // Should not panic on nonexistent directory
        load_pem_directory(&mut roots, "/nonexistent/path");
        assert!(roots.is_empty());
    }
}

#[cfg(test)]
#[cfg(feature = "cert-watch")]
mod cert_watch_tests {
    use super::*;

    #[test]
    fn test_watcher_starts_and_stops() {
        let shutdown = tokio_util::sync::CancellationToken::new();
        let dir = tempfile::tempdir().expect("tempdir creation should succeed");
        let cert_path = dir.path().join("test.pem");
        std::fs::write(&cert_path, "").expect("write should succeed");

        let watcher = CertificateWatcher::start(
            vec![cert_path.to_string_lossy().to_string()],
            vec![],
            vec![],
            shutdown.clone(),
        );
        assert!(watcher.is_ok(), "Watcher should start successfully");

        let w = watcher.expect("watcher already asserted ok");
        w.stop();
        assert!(shutdown.is_cancelled());
    }

    #[test]
    fn test_watcher_handles_nonexistent_path() {
        let shutdown = tokio_util::sync::CancellationToken::new();
        // Starting with nonexistent paths should not panic.
        // The watcher itself succeeds; individual watch registrations emit warnings.
        let watcher = CertificateWatcher::start(
            vec!["/nonexistent/path.pem".to_string()],
            vec![],
            vec![],
            shutdown,
        );
        // May succeed or fail depending on OS, but must not panic.
        let _ = watcher;
    }

    #[test]
    fn test_watcher_drop_cancels() {
        let shutdown = tokio_util::sync::CancellationToken::new();
        let dir = tempfile::tempdir().expect("tempdir creation should succeed");
        let cert_path = dir.path().join("test.pem");
        std::fs::write(&cert_path, "").expect("write should succeed");

        let shutdown_clone = shutdown.clone();
        {
            let _watcher = CertificateWatcher::start(
                vec![cert_path.to_string_lossy().to_string()],
                vec![],
                vec![],
                shutdown,
            )
            .expect("watcher should start");
            // watcher dropped here
        }
        assert!(
            shutdown_clone.is_cancelled(),
            "Drop should cancel the shutdown token"
        );
    }

    #[test]
    fn test_watcher_with_directory() {
        let shutdown = tokio_util::sync::CancellationToken::new();
        let dir = tempfile::tempdir().expect("tempdir creation should succeed");

        let watcher = CertificateWatcher::start(
            vec![],
            vec![],
            vec![dir.path().to_string_lossy().to_string()],
            shutdown.clone(),
        );
        assert!(
            watcher.is_ok(),
            "Watcher should start with directory watch"
        );

        shutdown.cancel();
    }
}
