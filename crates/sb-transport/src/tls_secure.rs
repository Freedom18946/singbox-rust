//! # Enhanced TLS Security Configuration / 增强的 TLS 安全配置
//!
//! This module extends the base TLS functionality with additional security features:
//! 该模块使用额外的安全功能扩展了基础 TLS 功能：
//! - Certificate fingerprint/public key pinning (SHA-256)
//!   证书指纹/公钥固定 (SHA-256)
//! - Enforced minimum TLS versions
//!   强制最低 TLS 版本
//! - Environment-based security policy configuration
//!   基于环境的安全策略配置
//!
//! ## Strategic Relevance / 战略关联
//! - **Security Hardening**: Provides defense-in-depth against MITM attacks and weak crypto.
//!   **安全加固**: 提供针对中间人攻击和弱加密的纵深防御。
//! - **Compliance**: Helps meet security standards requiring specific TLS versions or ciphers.
//!   **合规性**: 帮助满足要求特定 TLS 版本或密码的安全标准。

use super::dialer::{DialError, Dialer, IoStream};
use super::tls::TlsDialer;
use async_trait::async_trait;
use rustls::{ClientConfig, RootCertStore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::Arc;

const TLS12_AND_TLS13: &[&rustls::SupportedProtocolVersion] =
    &[&rustls::version::TLS13, &rustls::version::TLS12];
const TLS13_ONLY: &[&rustls::SupportedProtocolVersion] = &[&rustls::version::TLS13];

/// TLS security baseline configuration
/// TLS 安全基线配置
#[derive(Debug, Clone)]
pub struct TlsSecurityConfig {
    /// Minimum TLS version (1.2 or 1.3)
    /// 最低 TLS 版本（1.2 或 1.3）
    pub min_version: TlsVersion,
    /// Certificate fingerprint pinning (SHA-256 hex)
    /// 证书指纹固定 (SHA-256 十六进制)
    pub pin_sha256: Option<String>,
    /// Strict SNI validation
    /// 严格的 SNI 验证。启用后，`SB_TLS_SNI` 不能覆盖为与拨号 host 不同的名称。
    pub strict_sni: bool,
}

/// Supported TLS protocol versions
/// 支持的 TLS 协议版本
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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
            strict_sni: true,
        }
    }
}

impl TlsSecurityConfig {
    /// Create configuration from environment variables
    /// 从环境变量创建配置
    pub fn from_env() -> Self {
        let mut config = Self::default();

        // Read minimum TLS version
        // 读取最低 TLS 版本
        if let Ok(min_tls) = std::env::var("SB_TLS_MIN") {
            match min_tls.as_str() {
                "1.2" => config.min_version = TlsVersion::V1_2,
                "1.3" => config.min_version = TlsVersion::V1_3,
                _ => tracing::warn!("Invalid SB_TLS_MIN value: {}, using default", min_tls),
            }
        }

        // Read certificate pinning
        // 读取证书固定
        if let Ok(pin) = std::env::var("SB_TLS_PIN_SHA256") {
            if !pin.is_empty() && pin.len() == 64 && pin.chars().all(|c| c.is_ascii_hexdigit()) {
                config.pin_sha256 = Some(pin.to_lowercase());
            } else {
                tracing::warn!("Invalid SB_TLS_PIN_SHA256 format, ignoring");
            }
        }

        if let Ok(strict_sni) = std::env::var("SB_TLS_STRICT_SNI") {
            match strict_sni.to_ascii_lowercase().as_str() {
                "1" | "true" | "yes" => config.strict_sni = true,
                "0" | "false" | "no" => config.strict_sni = false,
                _ => tracing::warn!(
                    "Invalid SB_TLS_STRICT_SNI value: {}, using default",
                    strict_sni
                ),
            }
        }

        config
    }

    /// Build rustls ClientConfig with security enhancements
    /// 构建具有安全增强功能的 rustls ClientConfig
    pub fn build_client_config(
        &self,
    ) -> Result<Arc<ClientConfig>, Box<dyn std::error::Error + Send + Sync>> {
        if rustls::crypto::CryptoProvider::get_default().is_none() {
            let _ = rustls::crypto::ring::default_provider().install_default();
        }
        let mut root_store = RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

        let config = ClientConfig::builder_with_protocol_versions(self.enabled_protocol_versions())
            .with_root_certificates(root_store)
            .with_no_client_auth();

        Ok(Arc::new(config))
    }

    fn enabled_protocol_versions(&self) -> &'static [&'static rustls::SupportedProtocolVersion] {
        match self.min_version {
            TlsVersion::V1_2 => TLS12_AND_TLS13,
            TlsVersion::V1_3 => TLS13_ONLY,
        }
    }
}

/// Enhanced TLS dialer with security features
/// 具有安全特性的增强型 TLS 拨号器
pub struct SecureTlsDialer<D: Dialer> {
    /// Base TLS dialer
    /// 基础 TLS 拨号器
    pub inner: TlsDialer<D>,
    /// Security configuration
    /// 安全配置
    pub security_config: TlsSecurityConfig,
}

impl<D: Dialer> SecureTlsDialer<D> {
    /// Create a new secure TLS dialer with environment-based configuration
    /// 使用基于环境的配置创建新的安全 TLS 拨号器
    pub fn from_env(inner: D) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let security_config = TlsSecurityConfig::from_env();
        let tls_config = security_config.build_client_config()?;

        Ok(Self {
            inner: TlsDialer {
                inner,
                config: tls_config,
                sni_override: std::env::var("SB_TLS_SNI").ok(),
                alpn: std::env::var("SB_TLS_ALPN")
                    .ok()
                    .map(|s| s.split(',').map(|p| p.trim().as_bytes().to_vec()).collect()),
            },
            security_config,
        })
    }

    /// Verify certificate fingerprint if pinning is configured
    /// 如果配置了固定，则验证证书指纹
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
impl<D: Dialer + Send + Sync + 'static> Dialer for SecureTlsDialer<D> {
    async fn connect(&self, host: &str, port: u16) -> Result<IoStream, DialError> {
        use rustls::pki_types::ServerName;
        use tokio_rustls::TlsConnector;

        // Configure SNI
        // 配置 SNI
        let sni_host = self.inner.sni_override.as_deref().unwrap_or(host);
        if self.security_config.strict_sni && sni_host != host {
            return Err(DialError::Tls(format!(
                "Strict SNI validation rejected override '{}' for host '{}'",
                sni_host, host
            )));
        }
        let server_name = ServerName::try_from(sni_host.to_string())
            .map_err(|e| DialError::Tls(format!("SNI configuration failed: {:?}", e)))?;

        // Establish the base connection
        // 建立基础连接
        let stream = self.inner.inner.connect(host, port).await?;

        // Configure ALPN if specified
        // 如果指定，则配置 ALPN
        let config = if let Some(alpn_protocols) = &self.inner.alpn {
            let mut cfg = (*self.inner.config).clone();
            cfg.alpn_protocols = alpn_protocols.clone();
            Arc::new(cfg)
        } else {
            self.inner.config.clone()
        };

        // Establish TLS connection
        // 建立 TLS 连接
        let connector = TlsConnector::from(config);
        let tls_stream = connector
            .connect(server_name, stream)
            .await
            .map_err(|e| DialError::Tls(format!("TLS handshake failed: {}", e)))?;

        // Verify certificate pinning if configured
        // 如果配置，则验证证书固定
        if self.security_config.pin_sha256.is_some() {
            if let Some(peer_certs) = tls_stream.get_ref().1.peer_certificates() {
                if let Some(cert) = peer_certs.first() {
                    self.verify_certificate_pin(cert.as_ref())?;
                } else {
                    return Err(DialError::Tls(
                        "No peer certificate for pin verification".to_string(),
                    ));
                }
            } else {
                return Err(DialError::Tls(
                    "No peer certificates available for pinning".to_string(),
                ));
            }
        }

        Ok(Box::new(tls_stream))
    }

    fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dialer::TcpDialer;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
    use rustls::{
        client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
        DigitallySignedStruct, SignatureScheme,
    };
    use std::sync::Mutex;
    use tokio::io::AsyncWriteExt;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn test_tls_security_config_from_env() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        let _ = rustls::crypto::ring::default_provider().install_default();
        // Set environment variables for testing
        std::env::set_var("SB_TLS_MIN", "1.3");
        std::env::set_var(
            "SB_TLS_PIN_SHA256",
            "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
        );
        std::env::set_var("SB_TLS_STRICT_SNI", "false");

        let config = TlsSecurityConfig::from_env();
        assert_eq!(config.min_version, TlsVersion::V1_3);
        assert!(config.pin_sha256.is_some());
        assert!(!config.strict_sni);

        // Cleanup
        std::env::remove_var("SB_TLS_MIN");
        std::env::remove_var("SB_TLS_PIN_SHA256");
        std::env::remove_var("SB_TLS_STRICT_SNI");
    }

    #[test]
    fn test_invalid_pin_format_ignored() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        std::env::remove_var("SB_TLS_MIN");
        std::env::set_var("SB_TLS_PIN_SHA256", "invalid-pin-format");

        let config = TlsSecurityConfig::from_env();
        assert!(config.pin_sha256.is_none());

        std::env::remove_var("SB_TLS_PIN_SHA256");
    }

    #[test]
    fn test_build_client_config_installs_provider_and_enables_tls13() {
        let config = TlsSecurityConfig {
            min_version: TlsVersion::V1_3,
            ..Default::default()
        };

        let client_config = config.build_client_config().unwrap();
        assert!(rustls::crypto::CryptoProvider::get_default().is_some());
        // Verify configuration was created successfully
        assert!(!client_config
            .as_ref()
            .crypto_provider()
            .cipher_suites
            .is_empty());
    }

    #[tokio::test]
    async fn tls13_minimum_rejects_tls12_only_server() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let client_config = test_client_config(TlsSecurityConfig {
            min_version: TlsVersion::V1_3,
            ..Default::default()
        });

        let server_config = tls12_only_server_config();
        let (client_io, server_io) = tokio::io::duplex(1024);
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));
        let server = tokio::spawn(async move {
            let _ = acceptor.accept(server_io).await;
        });

        let connector = tokio_rustls::TlsConnector::from(client_config);
        let err = connector
            .connect(
                ServerName::try_from("localhost").expect("server name"),
                client_io,
            )
            .await
            .expect_err("TLS 1.3 minimum must reject a TLS 1.2-only server");
        let err_text = err.to_string().to_ascii_lowercase();
        assert!(
            err_text.contains("protocol")
                || err_text.contains("version")
                || err_text.contains("handshake"),
            "unexpected TLS error: {err}"
        );

        server.await.expect("server task");
    }

    #[tokio::test]
    async fn tls12_minimum_allows_tls12_only_server() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let client_config = test_client_config(TlsSecurityConfig {
            min_version: TlsVersion::V1_2,
            ..Default::default()
        });

        let server_config = tls12_only_server_config();
        let (client_io, server_io) = tokio::io::duplex(1024);
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));
        let server = tokio::spawn(async move {
            let mut stream = acceptor.accept(server_io).await.expect("server accept");
            stream.write_all(b"ok").await.expect("server write");
        });

        let connector = tokio_rustls::TlsConnector::from(client_config);
        let stream = connector
            .connect(
                ServerName::try_from("localhost").expect("server name"),
                client_io,
            )
            .await
            .expect("TLS 1.2 minimum should allow TLS 1.2-only server");
        assert_eq!(
            stream.get_ref().1.protocol_version(),
            Some(rustls::ProtocolVersion::TLSv1_2)
        );

        server.await.expect("server task");
    }

    #[tokio::test]
    async fn strict_sni_rejects_mismatched_override_before_dialing() {
        let security_config = TlsSecurityConfig::default();
        let tls_config = security_config
            .build_client_config()
            .expect("secure TLS client config");
        let dialer = SecureTlsDialer {
            inner: TlsDialer {
                inner: TcpDialer::default(),
                config: tls_config,
                sni_override: Some("front.example".to_string()),
                alpn: None,
            },
            security_config,
        };
        let result = dialer.connect("origin.example", 443).await;

        let err = match result {
            Ok(_) => panic!("strict SNI should reject mismatched override"),
            Err(err) => err,
        };
        assert!(
            err.to_string()
                .contains("Strict SNI validation rejected override"),
            "unexpected error: {err}"
        );
    }

    fn tls12_only_server_config() -> rustls::ServerConfig {
        let rcgen::CertifiedKey { cert, key_pair } =
            rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
                .expect("self-signed cert");
        let cert_der = CertificateDer::from(cert.der().to_vec());
        let key_der = PrivateKeyDer::try_from(key_pair.serialize_der()).expect("private key der");

        rustls::ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS12])
            .with_no_client_auth()
            .with_single_cert(vec![cert_der], key_der)
            .expect("TLS 1.2-only server config")
    }

    fn test_client_config(config: TlsSecurityConfig) -> Arc<rustls::ClientConfig> {
        Arc::new(
            rustls::ClientConfig::builder_with_protocol_versions(
                config.enabled_protocol_versions(),
            )
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerifier))
            .with_no_client_auth(),
        )
    }

    #[derive(Debug)]
    struct NoVerifier;

    impl ServerCertVerifier for NoVerifier {
        fn verify_server_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp_response: &[u8],
            _now: rustls::pki_types::UnixTime,
        ) -> Result<ServerCertVerified, rustls::Error> {
            Ok(ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            vec![
                SignatureScheme::ECDSA_NISTP256_SHA256,
                SignatureScheme::RSA_PSS_SHA256,
                SignatureScheme::RSA_PKCS1_SHA256,
            ]
        }
    }

    #[tokio::test]
    async fn test_secure_tls_dialer_creation() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        // This test verifies the dialer can be created without environment variables
        let dialer = TcpDialer::default();
        let result = SecureTlsDialer::from_env(dialer);
        assert!(result.is_ok());
    }
}
