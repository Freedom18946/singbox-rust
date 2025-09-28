//! Unified TLS trust and certificate pinning
//!
//! Provides unified TLS client configuration for all outbound protocols with
//! support for certificate pinning, environment-controlled insecure bypass,
//! and metrics reporting.

#[cfg(feature = "tls_rustls")]
use rustls::{ClientConfig, RootCertStore};
use std::sync::Arc;

#[derive(Clone, Debug)]
pub struct TlsOpts {
    /// Allow insecure TLS (skip certificate verification)
    pub allow_insecure: bool,
    /// SPKI SHA256 pins for certificate pinning
    pub pin_sha256: Vec<[u8; 32]>,
    /// ALPN protocol list
    pub alpn: Vec<Vec<u8>>,
    /// Server Name Indication
    pub sni: String,
}

impl Default for TlsOpts {
    fn default() -> Self {
        Self {
            allow_insecure: false,
            pin_sha256: Vec::new(),
            alpn: Vec::new(),
            sni: String::new(),
        }
    }
}

impl TlsOpts {
    pub fn new(sni: String) -> Self {
        Self {
            sni,
            ..Default::default()
        }
    }

    pub fn with_allow_insecure(mut self, allow: bool) -> Self {
        self.allow_insecure = allow;
        self
    }

    pub fn with_pins(mut self, pins: Vec<[u8; 32]>) -> Self {
        self.pin_sha256 = pins;
        self
    }

    pub fn with_alpn(mut self, alpn: Vec<Vec<u8>>) -> Self {
        self.alpn = alpn;
        self
    }
}

/// Create a unified TLS client configuration
#[cfg(feature = "tls_rustls")]
pub fn mk_client(opts: &TlsOpts) -> Result<Arc<ClientConfig>, crate::error::SbError> {
    // Initialize root certificate store
    let mut roots = RootCertStore::empty();

    #[cfg(feature = "tls_rustls")]
    {
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    }

    let mut config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();

    // Set ALPN protocols if specified
    if !opts.alpn.is_empty() {
        config.alpn_protocols = opts.alpn.clone();
    }

    // Configure certificate verification
    if opts.allow_insecure {
        #[cfg(feature = "metrics")]
        {
            use crate::metrics::labels::record_tls_verify;
            record_tls_verify(crate::metrics::labels::Proto::Shadowsocks, "skip");
        }

        config
            .dangerous()
            .set_certificate_verifier(Arc::new(super::danger::NoVerify));
    } else if !opts.pin_sha256.is_empty() {
        #[cfg(feature = "metrics")]
        {
            use crate::metrics::labels::record_tls_verify;
            record_tls_verify(crate::metrics::labels::Proto::Shadowsocks, "pin");
        }

        config
            .dangerous()
            .set_certificate_verifier(Arc::new(super::danger::PinVerify::new(
                opts.pin_sha256.clone(),
            )));
    } else {
        #[cfg(feature = "metrics")]
        {
            use crate::metrics::labels::record_tls_verify;
            record_tls_verify(crate::metrics::labels::Proto::Shadowsocks, "ok");
        }
    }

    Ok(Arc::new(config))
}

#[cfg(not(feature = "tls_rustls"))]
pub fn mk_client(_opts: &TlsOpts) -> Result<Arc<()>, crate::error::SbError> {
    Err(crate::error::SbError::config(
        crate::error::IssueCode::MissingRequired,
        "/tls/enabled",
        "TLS support not enabled. Enable 'tls_rustls' feature to use TLS functionality"
    ))
}

/// Parse SHA256 pins from environment variable (comma-separated hex)
pub fn pins_from_env(env_var: &str) -> Vec<[u8; 32]> {
    std::env::var(env_var)
        .ok()
        .map(|pins_str| {
            pins_str
                .split(',')
                .filter_map(|pin| {
                    let pin = pin.trim();
                    if pin.len() == 64 {
                        hex::decode(pin).ok().and_then(|bytes| {
                            if bytes.len() == 32 {
                                let mut array = [0u8; 32];
                                array.copy_from_slice(&bytes);
                                Some(array)
                            } else {
                                None
                            }
                        })
                    } else {
                        None
                    }
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Parse ALPN protocols from environment variable (comma-separated)
pub fn alpn_from_env(env_var: &str) -> Vec<Vec<u8>> {
    std::env::var(env_var)
        .ok()
        .map(|alpn_str| {
            alpn_str
                .split(',')
                .map(|proto| proto.trim().as_bytes().to_vec())
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pins_from_env() {
        std::env::set_var("TEST_PINS", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef,fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210");
        let pins = pins_from_env("TEST_PINS");
        assert_eq!(pins.len(), 2);
    }

    #[test]
    fn test_alpn_from_env() {
        std::env::set_var("TEST_ALPN", "h2,http/1.1");
        let alpn = alpn_from_env("TEST_ALPN");
        assert_eq!(alpn, vec![b"h2".to_vec(), b"http/1.1".to_vec()]);
    }
}
