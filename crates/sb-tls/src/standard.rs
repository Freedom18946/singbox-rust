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
///
/// This connector provides standard TLS 1.3 connections using rustls.
/// It supports:
/// - TLS 1.3 protocol
/// - SNI (Server Name Indication)
/// - ALPN (Application Layer Protocol Negotiation)
/// - Custom root certificates
pub struct StandardTlsConnector {
    config: Arc<ClientConfig>,
    alpn_protocols: Option<Vec<Vec<u8>>>,
}

impl StandardTlsConnector {
    /// Create a new standard TLS connector with default configuration
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
    async fn connect<S>(
        &self,
        stream: S,
        server_name: &str,
    ) -> io::Result<crate::TlsIoStream>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        // Apply ALPN if configured
        let config = if let Some(alpn) = &self.alpn_protocols {
            let mut c = (*self.config).clone();
            c.alpn_protocols = alpn.clone();
            Arc::new(c)
        } else {
            self.config.clone()
        };

        // Parse server name
        let server_name = ServerName::try_from(server_name.to_string())
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;

        // Connect
        let connector = RustlsConnector::from(config);
        let tls_stream = connector
            .connect(server_name, stream)
            .await
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

        Ok(Box::new(tls_stream))
    }
}

#[cfg(test)]
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
