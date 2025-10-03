//! REALITY client implementation

use super::auth::RealityAuth;
use super::config::RealityClientConfig;
use super::{RealityError, RealityResult};
use crate::TlsConnector;
use async_trait::async_trait;
use std::io;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use tracing::{debug, warn};

/// REALITY client connector
///
/// This connector implements the REALITY protocol for anti-censorship.
/// It performs SNI forgery and authentication to bypass DPI and SNI whitelisting.
///
/// ## How it works:
/// 1. Connects with forged SNI (target domain)
/// 2. Embeds authentication data in TLS ClientHello
/// 3. Verifies server response (temporary cert vs real cert)
/// 4. Establishes encrypted tunnel or enters "crawler mode"
pub struct RealityConnector {
    config: Arc<RealityClientConfig>,
    auth: RealityAuth,
}

impl RealityConnector {
    /// Create new REALITY connector
    pub fn new(config: RealityClientConfig) -> RealityResult<Self> {
        // Validate configuration
        config
            .validate()
            .map_err(|e| RealityError::InvalidConfig(e))?;

        // Parse public key for authentication
        let _public_key_bytes = config
            .public_key_bytes()
            .map_err(|e| RealityError::InvalidConfig(e))?;

        // Create client auth (we generate ephemeral private key, only need server's public key)
        let auth = RealityAuth::generate();

        debug!(
            "Created REALITY connector for target: {}, server_name: {}",
            config.target, config.server_name
        );

        Ok(Self {
            config: Arc::new(config),
            auth,
        })
    }

    /// Get configuration
    pub fn config(&self) -> &RealityClientConfig {
        &self.config
    }

    /// Perform REALITY handshake
    ///
    /// This is the core REALITY protocol logic:
    /// 1. Send ClientHello with forged SNI and auth data
    /// 2. Receive ServerHello and verify certificate type
    /// 3. Complete handshake based on certificate type
    ///
    /// TODO: Implement full REALITY handshake
    /// - Custom ClientHello generation with embedded auth
    /// - Certificate type detection (temporary vs real)
    /// - Fallback to crawler mode if needed
    async fn reality_handshake<S>(
        &self,
        stream: S,
    ) -> RealityResult<crate::TlsIoStream>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        debug!("Starting REALITY handshake");

        // TODO: Implement REALITY-specific handshake
        // For now, this is a placeholder that shows the structure

        // Step 1: Prepare auth data
        let server_public_key = self
            .config
            .public_key_bytes()
            .map_err(|e| RealityError::InvalidConfig(e))?;

        let short_id = self.config.short_id_bytes().unwrap_or_default();

        // Step 2: Compute authentication hash
        // In real implementation, this would be embedded in ClientHello
        let session_data = b"reality_session"; // Should be random per session
        let _auth_hash = self
            .auth
            .compute_auth_hash(&server_public_key, &short_id, session_data);

        // Step 3: Perform TLS handshake with modified ClientHello
        // TODO: Use custom TLS implementation that allows ClientHello modification
        // For now, fall back to standard TLS (this won't actually work as REALITY)

        warn!("REALITY handshake stub: falling back to standard TLS (NOT SECURE)");

        // Placeholder: In production, this would be the REALITY-modified handshake
        use rustls::ClientConfig;
        use rustls_pki_types::ServerName;
        use tokio_rustls::TlsConnector as RustlsConnector;

        let config = ClientConfig::builder()
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_no_client_auth();

        let server_name = ServerName::try_from(self.config.server_name.clone())
            .map_err(|e| {
                RealityError::HandshakeFailed(format!("Invalid server name: {:?}", e))
            })?;

        let connector = RustlsConnector::from(Arc::new(config));
        let tls_stream = connector.connect(server_name, stream).await.map_err(|e| {
            RealityError::HandshakeFailed(format!("TLS handshake failed: {}", e))
        })?;

        debug!("REALITY handshake completed (stub)");

        Ok(Box::new(tls_stream))
    }
}

#[async_trait]
impl TlsConnector for RealityConnector {
    async fn connect<S>(
        &self,
        stream: S,
        server_name: &str,
    ) -> io::Result<crate::TlsIoStream>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        debug!(
            "REALITY connect: server_name={}, target={}",
            server_name, self.config.target
        );

        self.reality_handshake(stream)
            .await
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))
    }
}

// Implementation notes for full REALITY:
//
// 1. ClientHello Modification:
//    - Embed client public key in extension
//    - Embed short_id in extension
//    - Embed auth_hash in extension
//    - Use forged SNI (target domain)
//    - Optionally emulate browser fingerprint
//
// 2. Certificate Verification:
//    - Check if certificate is "temporary trusted" (proxy mode)
//    - Check if certificate is from real target (crawler mode)
//    - Reject invalid certificates
//
// 3. Key Exchange:
//    - Use X25519 for ECDH
//    - Derive shared secret from server public key
//    - Use shared secret for authentication
//
// 4. Fallback Handling:
//    - If auth fails, server presents real target certificate
//    - Client enters "crawler mode" and acts as normal browser
//    - This prevents detection by censors

#[cfg(test)]
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
            target: "".to_string(), // Invalid: empty target
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
