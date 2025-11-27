//! Standard TLS 1.3 connector using rustls

use crate::{TlsConnector, TlsResult};
use async_trait::async_trait;
use rustls::{ClientConfig, RootCertStore};
use rustls_pki_types::ServerName;
use std::io;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::TlsConnector as RustlsConnector;

/// Standard TLS 1.3 connector
/// 标准 TLS 1.3 连接器
///
/// This connector provides standard TLS 1.3 connections using rustls.
/// 此连接器使用 rustls 提供标准 TLS 1.3 连接。
/// It supports:
/// 它支持：
/// - TLS 1.3 protocol
/// - TLS 1.3 协议
/// - SNI (Server Name Indication)
/// - SNI (服务器名称指示)
/// - ALPN (Application Layer Protocol Negotiation)
/// - ALPN (应用层协议协商)
/// - Custom root certificates
/// - 自定义根证书
pub struct StandardTlsConnector {
    config: Arc<ClientConfig>,
    alpn_protocols: Option<Vec<Vec<u8>>>,
}

impl StandardTlsConnector {
    /// Create a new standard TLS connector with default configuration
    /// 创建具有默认配置的新标准 TLS 连接器
    ///
    /// # Errors
    /// # 错误
    /// Returns an error if the TLS client configuration cannot be constructed.
    /// 如果无法构建 TLS 客户端配置，则返回错误。
    pub fn new() -> TlsResult<Self> {
        let root_store = RootCertStore::empty();

        // Add system root certificates
        // In production, use webpki-roots or rustls-native-certs
        // For now, use empty store as placeholder

        let config = ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        Ok(Self {
            config: Arc::new(config),
            alpn_protocols: None,
        })
    }

    /// Create connector with custom root certificates
    /// 创建具有自定义根证书的连接器
    #[must_use]
    pub fn with_root_store(root_store: RootCertStore) -> Self {
        let config = ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        Self {
            config: Arc::new(config),
            alpn_protocols: None,
        }
    }

    /// Set ALPN protocols
    /// 设置 ALPN 协议
    #[must_use]
    pub fn with_alpn(mut self, alpn: Vec<Vec<u8>>) -> Self {
        self.alpn_protocols = Some(alpn);
        self
    }
}

impl Default for StandardTlsConnector {
    fn default() -> Self {
        // This is safe because creating a default TLS connector with webpki-roots
        // should never fail in normal circumstances
        #[allow(clippy::expect_used)]
        Self::new().expect("Failed to create default TLS connector with webpki-roots")
    }
}

#[async_trait]
impl TlsConnector for StandardTlsConnector {
    async fn connect<S>(&self, stream: S, server_name: &str) -> io::Result<crate::TlsIoStream>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        // Apply ALPN if configured
        let config = self.alpn_protocols.as_ref().map_or_else(
            || self.config.clone(),
            |alpn| {
                let mut c = (*self.config).clone();
                c.alpn_protocols.clone_from(alpn);
                Arc::new(c)
            },
        );

        // Parse server name
        let server_name =
            ServerName::try_from(server_name.to_string()).map_err(io::Error::other)?;

        // Connect
        let connector = RustlsConnector::from(config);
        let tls_stream = connector
            .connect(server_name, stream)
            .await
            .map_err(io::Error::other)?;

        Ok(Box::new(tls_stream))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn init_crypto() {
        use rustls::crypto::ring;
        let _ = ring::default_provider().install_default();
    }

    #[test]
    fn test_standard_tls_connector_creation() {
        init_crypto();
        let connector = StandardTlsConnector::new();
        assert!(connector.is_ok());
    }

    #[test]
    fn test_standard_tls_connector_with_alpn() {
        init_crypto();
        let connector = StandardTlsConnector::new()
            .unwrap()
            .with_alpn(vec![b"h2".to_vec(), b"http/1.1".to_vec()]);
        assert!(connector.alpn_protocols.is_some());
        assert_eq!(connector.alpn_protocols.as_ref().unwrap().len(), 2);
    }
}
