//! REALITY client implementation

use super::config::RealityClientConfig;
use super::handshake::RealityHandshake;
use super::{RealityError, RealityResult};
use crate::TlsConnector;
use async_trait::async_trait;
use std::io;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use tracing::debug;

/// REALITY client connector
/// REALITY 客户端连接器
///
/// This connector implements the REALITY protocol for anti-censorship.
/// 此连接器实现了用于抗审查的 REALITY 协议。
/// It performs SNI forgery and authentication to bypass DPI and SNI whitelisting.
/// 它执行 SNI 伪造和认证以绕过 DPI 和 SNI 白名单。
///
/// ## How it works:
/// ## 工作原理：
/// 1. Connects with forged SNI (target domain)
/// 1. 使用伪造的 SNI（目标域名）连接
/// 2. Embeds authentication data in TLS `ClientHello`
/// 2. 在 TLS `ClientHello` 中嵌入认证数据
/// 3. Verifies server response (temporary cert vs real cert)
/// 3. 验证服务器响应（临时证书 vs 真实证书）
/// 4. Establishes encrypted tunnel or enters "crawler mode"
/// 4. 建立加密隧道或进入"爬虫模式"
pub struct RealityConnector {
    config: Arc<RealityClientConfig>,
}

impl RealityConnector {
    /// Create new REALITY connector
    /// 创建新的 REALITY 连接器
    ///
    /// # Errors
    /// # 错误
    /// Returns an error if configuration validation or key parsing fails.
    /// 如果配置验证或密钥解析失败，则返回错误。
    pub fn new(config: RealityClientConfig) -> RealityResult<Self> {
        config.validate().map_err(RealityError::InvalidConfig)?;
        config
            .public_key_bytes()
            .map_err(RealityError::InvalidConfig)?;

        debug!(
            "Created REALITY connector for target: {}, server_name: {}",
            config.target, config.server_name
        );

        Ok(Self {
            config: Arc::new(config),
        })
    }

    /// Get configuration
    #[must_use]
    pub fn config(&self) -> &RealityClientConfig {
        &self.config
    }

    /// Perform REALITY handshake
    /// 执行 REALITY 握手
    ///
    /// This is the core REALITY protocol logic:
    /// 这是核心 REALITY 协议逻辑：
    /// 1. Perform X25519 key exchange with server public key
    /// 1. 使用服务器公钥执行 X25519 密钥交换
    /// 2. Build `ClientHello` with forged SNI and embedded auth data
    /// 2. 构建带有伪造 SNI 和嵌入认证数据的 `ClientHello`
    /// 3. Use rustls with custom certificate verifier for TLS handshake
    /// 3. 使用带有自定义证书验证器的 rustls 进行 TLS 握手
    /// 4. Verify server response (temporary cert vs real target cert)
    /// 4. 验证服务器响应（临时证书 vs 真实目标证书）
    async fn reality_handshake<S>(&self, stream: S) -> RealityResult<crate::TlsIoStream>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        RealityHandshake::new(self.config.clone())?
            .perform(stream)
            .await
    }
}

#[async_trait]
impl TlsConnector for RealityConnector {
    async fn connect<S>(&self, stream: S, server_name: &str) -> io::Result<crate::TlsIoStream>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        debug!(
            "REALITY connect: server_name={}, target={}",
            server_name, self.config.target
        );

        self.reality_handshake(stream)
            .await
            .map_err(io::Error::other)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn test_reality_connector_creation() {
        let config = RealityClientConfig {
            target: "www.apple.com".to_string(),
            server_name: "www.apple.com".to_string(),
            public_key: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                .to_string(),
            short_id: Some("01ab".to_string()),
            fingerprint: "chrome".to_string(),
            alpn: vec![],
        };

        let connector = RealityConnector::new(config);
        assert!(connector.is_ok());
    }

    #[test]
    fn test_reality_connector_invalid_config() {
        let config = RealityClientConfig {
            target: String::new(), // Invalid: empty target
            server_name: "www.apple.com".to_string(),
            public_key: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                .to_string(),
            short_id: None,
            fingerprint: "chrome".to_string(),
            alpn: vec![],
        };

        let connector = RealityConnector::new(config);
        assert!(connector.is_err());
    }
}
