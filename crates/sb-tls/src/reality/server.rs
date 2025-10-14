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

/// Combined trait for stream types used in fallback
pub trait FallbackStream: AsyncRead + AsyncWrite + Unpin + Send {}

// Blanket implementation for all types that satisfy the bounds
impl<T> FallbackStream for T where T: AsyncRead + AsyncWrite + Unpin + Send {}

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
    pub async fn accept<S>(&self, stream: S) -> RealityResult<RealityConnection>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + Sync + 'static,
    {
        let handshake_timeout = Duration::from_secs(self.config.handshake_timeout);

        timeout(handshake_timeout, self.handle_handshake(stream))
            .await
            .map_err(|_| RealityError::HandshakeFailed("handshake timeout".to_string()))?
    }

    /// Handle REALITY handshake
    async fn handle_handshake<S>(&self, mut stream: S) -> RealityResult<RealityConnection>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + Sync + 'static,
    {
        debug!("Handling REALITY handshake");

        // Step 1: Read and parse ClientHello to extract REALITY extensions
        // We need to buffer the data so we can replay it for the TLS handshake
        let (client_public_key, short_id, auth_hash, sni, client_hello_data) =
            self.parse_and_buffer_client_hello(&mut stream).await?;

        debug!(
            "Parsed ClientHello: SNI={}, short_id={}",
            sni,
            hex::encode(&short_id)
        );

        // Step 2: Verify SNI is in accepted list
        if !self.config.server_names.contains(&sni) {
            warn!("SNI not in accepted list: {}", sni);
            // Replay the ClientHello data and fallback
            let replay_stream = ReplayStream::new(stream, client_hello_data);
            return self.fallback_to_target(replay_stream).await;
        }

        // Step 3: Verify short ID
        if !self.config.accepts_short_id(&short_id) {
            warn!("Short ID not accepted: {}", hex::encode(&short_id));
            let replay_stream = ReplayStream::new(stream, client_hello_data);
            return self.fallback_to_target(replay_stream).await;
        }

        // Step 4: Verify authentication hash
        // Note: session_data should be derived from the TLS handshake random values
        // For now, we use a placeholder that matches the client implementation
        let session_data = [0u8; 32];
        if !self
            .auth
            .verify_auth_hash(&client_public_key, &short_id, &session_data, &auth_hash)
        {
            warn!("Authentication failed: invalid auth hash");
            let replay_stream = ReplayStream::new(stream, client_hello_data);
            return self.fallback_to_target(replay_stream).await;
        }

        info!("REALITY authentication successful");

        // Step 5: Complete TLS handshake with temporary certificate
        // Replay the ClientHello data for rustls
        let replay_stream = ReplayStream::new(stream, client_hello_data);
        let tls_stream = self.complete_tls_handshake(replay_stream, &sni).await?;

        Ok(RealityConnection::Proxy(tls_stream))
    }

    /// Parse ClientHello and buffer the data for replay
    ///
    /// Returns: (client_public_key, short_id, auth_hash, sni, buffered_data)
    async fn parse_and_buffer_client_hello<S>(
        &self,
        stream: &mut S,
    ) -> RealityResult<([u8; 32], Vec<u8>, [u8; 32], String, Vec<u8>)>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        use super::tls_record::{ClientHello, ContentType, ExtensionType};
        use tokio::io::AsyncReadExt;

        // Read TLS record header (5 bytes)
        let mut header_buf = [0u8; 5];
        stream.read_exact(&mut header_buf).await.map_err(|e| {
            RealityError::HandshakeFailed(format!("Failed to read TLS record header: {}", e))
        })?;

        let content_type = ContentType::try_from(header_buf[0])
            .map_err(|e| RealityError::HandshakeFailed(format!("Invalid content type: {}", e)))?;
        let version = u16::from_be_bytes([header_buf[1], header_buf[2]]);
        let length = u16::from_be_bytes([header_buf[3], header_buf[4]]);

        debug!(
            "TLS record: type={:?}, version=0x{:04x}, length={}",
            content_type, version, length
        );

        // Verify this is a handshake record
        if content_type != ContentType::Handshake {
            return Err(RealityError::HandshakeFailed(format!(
                "Expected Handshake record, got {:?}",
                content_type
            )));
        }

        // Read handshake data
        let mut handshake_data = vec![0u8; length as usize];
        stream.read_exact(&mut handshake_data).await.map_err(|e| {
            RealityError::HandshakeFailed(format!("Failed to read handshake: {}", e))
        })?;

        // Parse ClientHello
        let client_hello = ClientHello::parse(&handshake_data).map_err(|e| {
            RealityError::HandshakeFailed(format!("Failed to parse ClientHello: {}", e))
        })?;

        debug!(
            "Parsed ClientHello: version=0x{:04x}, {} extensions",
            client_hello.version,
            client_hello.extensions.len()
        );

        // Extract SNI
        let sni = client_hello
            .get_sni()
            .ok_or_else(|| RealityError::HandshakeFailed("No SNI in ClientHello".to_string()))?;

        debug!("SNI: {}", sni);

        // Extract REALITY authentication extension
        let reality_ext = client_hello
            .find_extension(ExtensionType::RealityAuth as u16)
            .ok_or_else(|| RealityError::AuthFailed("No REALITY auth extension".to_string()))?;

        let (client_public_key, short_id, auth_hash) =
            reality_ext.parse_reality_auth().map_err(|e| {
                RealityError::HandshakeFailed(format!("Failed to parse REALITY extension: {}", e))
            })?;

        debug!(
            "REALITY auth: public_key={}, short_id={}, auth_hash={}",
            hex::encode(&client_public_key[..8]),
            hex::encode(&short_id),
            hex::encode(&auth_hash[..8])
        );

        // Combine header and handshake data for replay
        let mut buffered_data = Vec::with_capacity(5 + handshake_data.len());
        buffered_data.extend_from_slice(&header_buf);
        buffered_data.extend_from_slice(&handshake_data);

        Ok((client_public_key, short_id, auth_hash, sni, buffered_data))
    }

    /// Complete TLS handshake with temporary certificate
    async fn complete_tls_handshake<S>(
        &self,
        stream: S,
        server_name: &str,
    ) -> RealityResult<crate::TlsIoStream>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + Sync + 'static,
    {
        use rustls::pki_types::{CertificateDer, PrivateKeyDer};
        use std::sync::Arc;

        debug!("Completing TLS handshake for REALITY connection");

        // Generate a temporary self-signed certificate
        // In a production implementation, this would be derived from the shared secret
        let cert =
            rcgen::generate_simple_self_signed(vec![server_name.to_string()]).map_err(|e| {
                RealityError::HandshakeFailed(format!("Failed to generate certificate: {}", e))
            })?;

        let cert_der = CertificateDer::from(cert.cert.der().to_vec());

        let key_der = PrivateKeyDer::try_from(cert.key_pair.serialize_der()).map_err(|_| {
            RealityError::HandshakeFailed("Failed to serialize private key".to_string())
        })?;

        // Create TLS server config with the temporary certificate
        let config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der], key_der)
            .map_err(|e| {
                RealityError::HandshakeFailed(format!("Failed to create TLS config: {}", e))
            })?;

        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));

        // Perform TLS handshake
        let tls_stream = acceptor
            .accept(stream)
            .await
            .map_err(|e| RealityError::HandshakeFailed(format!("TLS handshake failed: {}", e)))?;

        debug!("REALITY TLS handshake completed successfully");

        Ok(Box::new(tls_stream))
    }

    /// Fallback to target website
    ///
    /// When authentication fails, proxy the connection to the real target
    /// to make it appear as legitimate traffic.
    async fn fallback_to_target<S>(&self, stream: S) -> RealityResult<RealityConnection>
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
            target: target_stream,
        })
    }
}

/// REALITY connection type
pub enum RealityConnection {
    /// Authenticated proxy connection
    Proxy(crate::TlsIoStream),

    /// Fallback connection (proxy to real target)
    Fallback {
        client: Box<dyn FallbackStream>,
        target: TcpStream,
    },
}

impl RealityConnection {
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
    pub async fn handle(self) -> io::Result<Option<crate::TlsIoStream>> {
        match self {
            RealityConnection::Proxy(stream) => Ok(Some(stream)),
            RealityConnection::Fallback {
                mut client,
                mut target,
            } => {
                // Bidirectional copy between client and target
                debug!("Starting fallback traffic relay");

                match tokio::io::copy_bidirectional(&mut client, &mut target).await {
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

/// Stream wrapper that replays buffered data before reading from underlying stream
struct ReplayStream<S> {
    inner: S,
    buffer: Vec<u8>,
    position: usize,
}

impl<S> ReplayStream<S> {
    fn new(inner: S, buffer: Vec<u8>) -> Self {
        Self {
            inner,
            buffer,
            position: 0,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for ReplayStream<S> {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        // First, return buffered data
        if self.position < self.buffer.len() {
            let remaining = &self.buffer[self.position..];
            let to_copy = std::cmp::min(remaining.len(), buf.remaining());
            buf.put_slice(&remaining[..to_copy]);
            self.position += to_copy;
            return std::task::Poll::Ready(Ok(()));
        }

        // Then read from underlying stream
        std::pin::Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for ReplayStream<S> {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        std::pin::Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
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
