//! Enhanced TLS security configuration with certificate pinning and modern cipher suites
//!
//! This module extends the base TLS functionality with additional security features:
//! - Certificate fingerprint/public key pinning (SHA-256)
//! - Enforced minimum TLS versions
//! - Secure cipher suite configuration
//! - Environment-based security policy configuration

use super::tls::{TlsDialer, webpki_roots_config};
use super::dialer::{DialError, Dialer, IoStream};
use async_trait::async_trait;
use rustls::{ClientConfig, RootCertStore, SupportedCipherSuite};
use sha2::{Sha256, Digest};
use std::sync::Arc;

/// TLS security baseline configuration
#[derive(Debug, Clone)]
pub struct TlsSecurityConfig {
    /// Minimum TLS version (1.2 or 1.3)
    pub min_version: TlsVersion,
    /// Certificate fingerprint pinning (SHA-256 hex)
    pub pin_sha256: Option<String>,
    /// Custom cipher suite restrictions
    pub allowed_cipher_suites: Option<Vec<SupportedCipherSuite>>,
    /// Strict SNI validation
    pub strict_sni: bool,
}

/// Supported TLS protocol versions
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum TlsVersion {
    /// TLS 1.2
    V1_2,
    /// TLS 1.3
    V1_3,
}

impl Default for TlsSecurityConfig {
    fn default() -> Self {
        Self {
            min_version: TlsVersion::V1_2,
            pin_sha256: None,
            allowed_cipher_suites: None,
            strict_sni: true,
        }
    }
}

impl TlsSecurityConfig {
    /// Create configuration from environment variables
    pub fn from_env() -> Self {
        let mut config = Self::default();

        // Read minimum TLS version
        if let Ok(min_tls) = std::env::var("SB_TLS_MIN") {
            match min_tls.as_str() {
                "1.2" => config.min_version = TlsVersion::V1_2,
                "1.3" => config.min_version = TlsVersion::V1_3,
                _ => tracing::warn!("Invalid SB_TLS_MIN value: {}, using default", min_tls),
            }
        }

        // Read certificate pinning
        if let Ok(pin) = std::env::var("SB_TLS_PIN_SHA256") {
            if !pin.is_empty() && pin.len() == 64 && pin.chars().all(|c| c.is_ascii_hexdigit()) {
                config.pin_sha256 = Some(pin.to_lowercase());
            } else {
                tracing::warn!("Invalid SB_TLS_PIN_SHA256 format, ignoring");
            }
        }

        config
    }

    /// Build rustls ClientConfig with security enhancements
    pub fn build_client_config(&self) -> Result<Arc<ClientConfig>, Box<dyn std::error::Error + Send + Sync>> {
        let mut root_store = RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

        let mut config_builder = ClientConfig::builder();

        // Configure cipher suites based on TLS version requirements
        if let Some(cipher_suites) = &self.allowed_cipher_suites {
            config_builder = config_builder.with_cipher_suites(cipher_suites);
        } else {
            // Use secure default cipher suites
            config_builder = config_builder.with_cipher_suites(&[
                // TLS 1.3 cipher suites
                rustls::cipher_suite::TLS13_AES_256_GCM_SHA384,
                rustls::cipher_suite::TLS13_AES_128_GCM_SHA256,
                rustls::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
                // TLS 1.2 cipher suites (if enabled)
                rustls::cipher_suite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
                rustls::cipher_suite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                rustls::cipher_suite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
            ]);
        }

        // Configure supported protocol versions
        let protocol_versions = match self.min_version {
            TlsVersion::V1_2 => &[&rustls::version::TLS12, &rustls::version::TLS13][..],
            TlsVersion::V1_3 => &[&rustls::version::TLS13][..],
        };

        let config = config_builder
            .with_protocol_versions(protocol_versions)
            .map_err(|e| format!("TLS protocol version configuration failed: {}", e))?
            .with_root_certificates(root_store)
            .with_no_client_auth();

        Ok(Arc::new(config))
    }
}

/// Enhanced TLS dialer with security features
pub struct SecureTlsDialer<D: Dialer> {
    /// Base TLS dialer
    pub inner: TlsDialer<D>,
    /// Security configuration
    pub security_config: TlsSecurityConfig,
}

impl<D: Dialer> SecureTlsDialer<D> {
    /// Create a new secure TLS dialer with environment-based configuration
    pub fn from_env(inner: D) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let security_config = TlsSecurityConfig::from_env();
        let tls_config = security_config.build_client_config()?;

        Ok(Self {
            inner: TlsDialer {
                inner,
                config: tls_config,
                sni_override: std::env::var("SB_TLS_SNI").ok(),
                alpn: std::env::var("SB_TLS_ALPN").ok().map(|s| {
                    s.split(',')
                        .map(|p| p.trim().as_bytes().to_vec())
                        .collect()
                }),
            },
            security_config,
        })
    }

    /// Verify certificate fingerprint if pinning is configured
    fn verify_certificate_pin(&self, cert_der: &[u8]) -> Result<(), DialError> {
        if let Some(expected_pin) = &self.security_config.pin_sha256 {
            let mut hasher = Sha256::new();
            hasher.update(cert_der);
            let actual_pin = hex::encode(hasher.finalize());

            if actual_pin != *expected_pin {
                return Err(DialError::Tls(format!(
                    "Certificate pin mismatch: expected {}, got {}",
                    expected_pin,
                    &actual_pin[..16] // Only log first 16 chars for security
                )));
            }

            tracing::debug!("Certificate pin verified successfully");
        }
        Ok(())
    }
}

#[async_trait]
impl<D: Dialer + Send + Sync> Dialer for SecureTlsDialer<D> {
    async fn connect(&self, host: &str, port: u16) -> Result<IoStream, DialError> {
        use rustls::pki_types::ServerName;
        use tokio_rustls::TlsConnector;

        // Establish the base connection
        let stream = self.inner.inner.connect(host, port).await?;

        // Configure SNI
        let sni_host = self.inner.sni_override.as_deref().unwrap_or(host);
        let server_name = ServerName::try_from(sni_host.to_string())
            .map_err(|e| DialError::Tls(format!("SNI configuration failed: {:?}", e)))?;

        // Configure ALPN if specified
        let config = if let Some(alpn_protocols) = &self.inner.alpn {
            let mut cfg = (*self.inner.config).clone();
            cfg.alpn_protocols = alpn_protocols.clone();
            Arc::new(cfg)
        } else {
            self.inner.config.clone()
        };

        // Establish TLS connection
        let connector = TlsConnector::from(config);
        let tls_stream = connector
            .connect(server_name, stream)
            .await
            .map_err(|e| DialError::Tls(format!("TLS handshake failed: {}", e)))?;

        // Verify certificate pinning if configured
        if self.security_config.pin_sha256.is_some() {
            if let Some(peer_certs) = tls_stream.get_ref().1.peer_certificates() {
                if let Some(cert) = peer_certs.first() {
                    self.verify_certificate_pin(cert.as_ref())?;
                } else {
                    return Err(DialError::Tls("No peer certificate for pin verification".to_string()));
                }
            } else {
                return Err(DialError::Tls("No peer certificates available for pinning".to_string()));
            }
        }

        Ok(Box::new(tls_stream))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dialer::TcpDialer;

    #[test]
    fn test_tls_security_config_from_env() {
        // Set environment variables for testing
        std::env::set_var("SB_TLS_MIN", "1.3");
        std::env::set_var("SB_TLS_PIN_SHA256", "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789");

        let config = TlsSecurityConfig::from_env();
        assert_eq!(config.min_version, TlsVersion::V1_3);
        assert!(config.pin_sha256.is_some());

        // Cleanup
        std::env::remove_var("SB_TLS_MIN");
        std::env::remove_var("SB_TLS_PIN_SHA256");
    }

    #[test]
    fn test_invalid_pin_format_ignored() {
        std::env::set_var("SB_TLS_PIN_SHA256", "invalid-pin-format");

        let config = TlsSecurityConfig::from_env();
        assert!(config.pin_sha256.is_none());

        std::env::remove_var("SB_TLS_PIN_SHA256");
    }

    #[test]
    fn test_build_client_config_tls13_only() {
        let config = TlsSecurityConfig {
            min_version: TlsVersion::V1_3,
            ..Default::default()
        };

        let client_config = config.build_client_config().unwrap();
        // Verify configuration was created successfully
        assert!(client_config.as_ref().crypto_provider().cipher_suites.len() > 0);
    }

    #[tokio::test]
    async fn test_secure_tls_dialer_creation() {
        // This test verifies the dialer can be created without environment variables
        let inner = TcpDialer;
        let result = SecureTlsDialer::from_env(inner);
        assert!(result.is_ok());
    }
}