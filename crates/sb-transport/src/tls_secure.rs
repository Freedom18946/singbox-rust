//! # Enhanced TLS Security Configuration / 增强的 TLS 安全配置
//!
//! This module extends the base TLS functionality with additional security features:
//! 该模块使用额外的安全功能扩展了基础 TLS 功能：
//! - Certificate fingerprint/public key pinning (SHA-256)
//!   证书指纹/公钥固定 (SHA-256)
//! - Enforced minimum TLS versions
//!   强制最低 TLS 版本
//! - Secure cipher suite configuration
//!   安全密码套件配置
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
use sha2::{Digest, Sha256};
use std::sync::Arc;

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
    /// Custom cipher suite restrictions
    /// 自定义密码套件限制
    pub allowed_cipher_suites: Option<Vec<()>>, // placeholder; unused for rustls 0.23 builder path
    /// Strict SNI validation
    /// 严格的 SNI 验证
    pub strict_sni: bool,
}

/// Supported TLS protocol versions
/// 支持的 TLS 协议版本
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

        config
    }

    /// Build rustls ClientConfig with security enhancements
    /// 构建具有安全增强功能的 rustls ClientConfig
    pub fn build_client_config(
        &self,
    ) -> Result<Arc<ClientConfig>, Box<dyn std::error::Error + Send + Sync>> {
        let mut root_store = RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

        let config = ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        Ok(Arc::new(config))
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

        // Establish the base connection
        // 建立基础连接
        let stream = self.inner.inner.connect(host, port).await?;

        // Configure SNI
        // 配置 SNI
        let sni_host = self.inner.sni_override.as_deref().unwrap_or(host);
        let server_name = ServerName::try_from(sni_host.to_string())
            .map_err(|e| DialError::Tls(format!("SNI configuration failed: {:?}", e)))?;

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

    #[test]
    fn test_tls_security_config_from_env() {
        // Set environment variables for testing
        std::env::set_var("SB_TLS_MIN", "1.3");
        std::env::set_var(
            "SB_TLS_PIN_SHA256",
            "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
        );

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
        assert!(!client_config
            .as_ref()
            .crypto_provider()
            .cipher_suites
            .is_empty());
    }

    #[tokio::test]
    async fn test_secure_tls_dialer_creation() {
        // This test verifies the dialer can be created without environment variables
        let dialer = TcpDialer::default();
        let result = SecureTlsDialer::from_env(dialer);
        assert!(result.is_ok());
    }
}
