//! REALITY server implementation

use super::auth::RealityAuth;
use super::config::RealityServerConfig;
use super::{RealityError, RealityResult};
use std::io;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tracing::{debug, info, warn};

/// REALITY server acceptor
///
/// This acceptor implements the REALITY protocol server side.
/// It verifies client authentication and either:
/// - Establishes proxy connection (auth success)
/// - Falls back to target website (auth failure)
///
/// ## How it works:
/// 1. Receives TLS ClientHello with embedded auth data
/// 2. Verifies authentication using shared secret
/// 3. If valid: issues temporary certificate and proxies traffic
/// 4. If invalid: proxies to real target website (disguise)
pub struct RealityAcceptor {
    config: Arc<RealityServerConfig>,
    auth: RealityAuth,
}

impl RealityAcceptor {
    /// Create new REALITY acceptor
    pub fn new(config: RealityServerConfig) -> RealityResult<Self> {
        // Validate configuration
        config
            .validate()
            .map_err(|e| RealityError::InvalidConfig(e))?;

        // Parse private key for authentication
        let private_key_bytes = config
            .private_key_bytes()
            .map_err(|e| RealityError::InvalidConfig(e))?;

        let auth = RealityAuth::from_private_key(private_key_bytes);

        info!(
            "Created REALITY acceptor for target: {}, server_names: {:?}",
            config.target, config.server_names
        );

        Ok(Self {
            config: Arc::new(config),
            auth,
        })
    }

    /// Get configuration
    pub fn config(&self) -> &RealityServerConfig {
        &self.config
    }

    /// Accept and handle REALITY connection
    ///
    /// This is the core server-side REALITY logic:
    /// 1. Parse ClientHello and extract auth data
    /// 2. Verify authentication
    /// 3. Either proxy or fallback based on auth result
    pub async fn accept<S>(
        &self,
        stream: S,
    ) -> RealityResult<RealityConnection<S>>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let handshake_timeout = Duration::from_secs(self.config.handshake_timeout);

        timeout(handshake_timeout, self.handle_handshake(stream))
            .await
            .map_err(|_| RealityError::HandshakeFailed("handshake timeout".to_string()))?
    }

    /// Handle REALITY handshake
    async fn handle_handshake<S>(
        &self,
        mut stream: S,
    ) -> RealityResult<RealityConnection<S>>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        debug!("Handling REALITY handshake");

        // TODO: Implement full REALITY server handshake
        // For now, this is a placeholder showing the structure

        // Step 1: Read ClientHello and extract REALITY extensions
        // - Client public key
        // - Short ID
        // - Auth hash
        // - SNI
        let (client_public_key, short_id, auth_hash, sni) =
            self.parse_client_hello(&mut stream).await?;

        debug!(
            "Parsed ClientHello: SNI={}, short_id={:?}",
            sni,
            hex::encode(&short_id)
        );

        // Step 2: Verify SNI is in accepted list
        if !self.config.server_names.contains(&sni) {
            warn!("SNI not in accepted list: {}", sni);
            return self.fallback_to_target(stream).await;
        }

        // Step 3: Verify short ID
        if !self.config.accepts_short_id(&short_id) {
            warn!("Short ID not accepted: {:?}", hex::encode(&short_id));
            return self.fallback_to_target(stream).await;
        }

        // Step 4: Verify authentication hash
        let session_data = b"reality_session"; // Should match client's session data
        if !self
            .auth
            .verify_auth_hash(&client_public_key, &short_id, session_data, &auth_hash)
        {
            warn!("Authentication failed");
            return self.fallback_to_target(stream).await;
        }

        info!("REALITY authentication successful");

        // Step 5: Issue temporary certificate and establish proxy connection
        // TODO: Generate temporary certificate signed by temporary CA
        // TODO: Complete TLS handshake with temporary certificate
        // TODO: Return encrypted stream for proxying

        warn!("REALITY server handshake stub: using placeholder connection");

        Ok(RealityConnection::Proxy(Box::new(stream)))
    }

    /// Parse ClientHello and extract REALITY data
    ///
    /// TODO: Implement ClientHello parsing
    /// - Extract SNI extension
    /// - Extract REALITY-specific extensions
    /// - Validate TLS version and cipher suites
    async fn parse_client_hello<S>(
        &self,
        _stream: &mut S,
    ) -> RealityResult<([u8; 32], Vec<u8>, [u8; 32], String)>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        // Placeholder: In production, parse actual ClientHello
        let client_public_key = [0u8; 32];
        let short_id = vec![0x01, 0xab];
        let auth_hash = [0u8; 32];
        let sni = self.config.server_names[0].clone();

        Ok((client_public_key, short_id, auth_hash, sni))
    }

    /// Fallback to target website
    ///
    /// When authentication fails, proxy the connection to the real target
    /// to make it appear as legitimate traffic.
    async fn fallback_to_target<S>(
        &self,
        stream: S,
    ) -> RealityResult<RealityConnection<S>>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        if !self.config.enable_fallback {
            return Err(RealityError::AuthFailed(
                "authentication failed and fallback disabled".to_string(),
            ));
        }

        debug!("Falling back to target: {}", self.config.target);

        // Connect to real target
        let target_stream = TcpStream::connect(&self.config.target)
            .await
            .map_err(|e| RealityError::TargetFailed(format!("failed to connect: {}", e)))?;

        info!("Fallback connection established to {}", self.config.target);

        Ok(RealityConnection::Fallback {
            client: Box::new(stream),
            target: Box::new(target_stream),
        })
    }
}

/// REALITY connection type
pub enum RealityConnection<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    /// Authenticated proxy connection
    Proxy(crate::TlsIoStream),

    /// Fallback connection (proxy to real target)
    Fallback {
        client: Box<S>,
        target: Box<TcpStream>,
    },
}

impl<S> RealityConnection<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    /// Check if this is a proxy connection
    pub fn is_proxy(&self) -> bool {
        matches!(self, RealityConnection::Proxy(_))
    }

    /// Check if this is a fallback connection
    pub fn is_fallback(&self) -> bool {
        matches!(self, RealityConnection::Fallback { .. })
    }

    /// Handle the connection based on type
    ///
    /// - Proxy: return the encrypted stream for application layer
    /// - Fallback: bidirectionally copy traffic between client and target
    pub async fn handle(self) -> io::Result<Option<crate::TlsIoStream>>
    {
        match self {
            RealityConnection::Proxy(stream) => Ok(Some(stream)),
            RealityConnection::Fallback { mut client, mut target } => {
                // Bidirectional copy between client and target
                debug!("Starting fallback traffic relay");

                match tokio::io::copy_bidirectional(&mut *client, &mut *target).await {
                    Ok((client_to_target, target_to_client)) => {
                        debug!(
                            "Fallback relay complete: client->target={}, target->client={}",
                            client_to_target, target_to_client
                        );
                    }
                    Err(e) => {
                        warn!("Fallback relay error: {}", e);
                        return Err(e);
                    }
                }

                Ok(None)
            }
        }
    }
}

// Implementation notes for full REALITY server:
//
// 1. ClientHello Parsing:
//    - Parse TLS record layer
//    - Extract handshake message
//    - Parse ClientHello structure
//    - Extract extensions (SNI, REALITY-specific)
//
// 2. Certificate Generation:
//    - Create temporary CA certificate
//    - Sign with temporary private key
//    - Include in ServerHello
//    - Client validates against shared secret
//
// 3. Target Certificate Stealing:
//    - Connect to real target
//    - Perform TLS handshake
//    - Extract certificate chain
//    - Present to client (if fallback)
//
// 4. Fallback Mechanism:
//    - On auth failure, become transparent proxy
//    - Copy traffic bidirectionally
//    - Maintain connection state
//    - Ensure indistinguishable from real target

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reality_acceptor_creation() {
        let config = RealityServerConfig {
            target: "www.apple.com:443".to_string(),
            server_names: vec!["example.com".to_string()],
            private_key: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                .to_string(),
            short_ids: vec!["01ab".to_string()],
            handshake_timeout: 5,
            enable_fallback: true,
        };

        let acceptor = RealityAcceptor::new(config);
        assert!(acceptor.is_ok());
    }

    #[test]
    fn test_reality_acceptor_invalid_config() {
        let config = RealityServerConfig {
            target: "".to_string(), // Invalid: empty target
            server_names: vec!["example.com".to_string()],
            private_key: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                .to_string(),
            short_ids: vec![],
            handshake_timeout: 5,
            enable_fallback: true,
        };

        let acceptor = RealityAcceptor::new(config);
        assert!(acceptor.is_err());
    }
}
