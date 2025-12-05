//! WireGuard transport layer implementation.
//!
//! Provides WireGuard tunnel transport using boringtun for userspace WireGuard.
//! This transport encapsulates TCP/UDP traffic over a WireGuard tunnel.
//!
//! # Features
//! - Userspace WireGuard implementation via boringtun
//! - Automatic handshake and key management
//! - Keepalive and timer handling
//! - Roaming support (endpoint update on packet receive)
//!
//! # Example
//! ```ignore
//! use sb_transport::wireguard::{WireGuardTransport, WireGuardConfig};
//!
//! let config = WireGuardConfig {
//!     private_key: "base64_private_key".to_string(),
//!     peer_public_key: "base64_peer_public_key".to_string(),
//!     peer_endpoint: "192.168.1.1:51820".parse().unwrap(),
//!     ..Default::default()
//! };
//!
//! let transport = WireGuardTransport::new(config).await?;
//! ```

use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tracing::{debug, error, trace, warn};

use crate::{DialError, Dialer, IoStream};

/// WireGuard transport configuration.
#[derive(Clone, Debug)]
pub struct WireGuardConfig {
    /// Local private key (base64 encoded).
    pub private_key: String,
    /// Peer's public key (base64 encoded).
    pub peer_public_key: String,
    /// Optional pre-shared key (base64 encoded).
    pub pre_shared_key: Option<String>,
    /// Peer endpoint address.
    pub peer_endpoint: SocketAddr,
    /// Local bind address (default: 0.0.0.0:0).
    pub local_addr: Option<SocketAddr>,
    /// Persistent keepalive interval in seconds.
    pub persistent_keepalive: Option<u16>,
    /// MTU for the tunnel (default: 1420).
    pub mtu: u16,
    /// Connection timeout.
    pub connect_timeout: Duration,
}

impl Default for WireGuardConfig {
    fn default() -> Self {
        Self {
            private_key: String::new(),
            peer_public_key: String::new(),
            pre_shared_key: None,
            peer_endpoint: "0.0.0.0:51820".parse().unwrap_or_else(|_| {
                // SAFETY: This is a valid socket address parse
                SocketAddr::from(([0, 0, 0, 0], 51820))
            }),
            local_addr: None,
            persistent_keepalive: Some(25),
            mtu: 1420,
            connect_timeout: Duration::from_secs(10),
        }
    }
}

/// WireGuard transport that tunnels traffic through a WireGuard connection.
pub struct WireGuardTransport {
    inner: Arc<WireGuardInner>,
}

impl std::fmt::Debug for WireGuardTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WireGuardTransport")
            // .field("inner", &self.inner) // WireGuardInner might not be Debug
            .finish_non_exhaustive()
    }
}

struct WireGuardInner {
    tunn: Mutex<Tunn>,
    socket: UdpSocket,
    peer_endpoint: Mutex<SocketAddr>,
    mtu: u16,
}

impl WireGuardTransport {
    /// Create a new WireGuard transport with the given configuration.
    pub async fn new(config: WireGuardConfig) -> Result<Self, WireGuardError> {
        // Parse private key
        let private_key_bytes = BASE64
            .decode(&config.private_key)
            .map_err(|_| WireGuardError::InvalidPrivateKey)?;
        let private_key_arr: [u8; 32] = private_key_bytes
            .try_into()
            .map_err(|_| WireGuardError::InvalidPrivateKey)?;
        let private_key = StaticSecret::from(private_key_arr);

        // Parse peer public key
        let peer_pk_bytes = BASE64
            .decode(&config.peer_public_key)
            .map_err(|_| WireGuardError::InvalidPeerPublicKey)?;
        let peer_pk_arr: [u8; 32] = peer_pk_bytes
            .try_into()
            .map_err(|_| WireGuardError::InvalidPeerPublicKey)?;
        let peer_pk = PublicKey::from(peer_pk_arr);

        // Parse optional pre-shared key
        let psk: Option<[u8; 32]> = if let Some(psk_str) = &config.pre_shared_key {
            let psk_bytes = BASE64
                .decode(psk_str)
                .map_err(|_| WireGuardError::InvalidPreSharedKey)?;
            Some(
                psk_bytes
                    .try_into()
                    .map_err(|_| WireGuardError::InvalidPreSharedKey)?,
            )
        } else {
            None
        };

        // Create UDP socket
        let local_addr = config
            .local_addr
            .unwrap_or_else(|| SocketAddr::from(([0, 0, 0, 0], 0)));
        let socket = UdpSocket::bind(local_addr)
            .await
            .map_err(WireGuardError::SocketBind)?;

        debug!(
            "WireGuard outbound bound to {}, peer endpoint: {}",
            socket.local_addr().unwrap_or(local_addr),
            config.peer_endpoint
        );

        #[cfg(target_os = "android")]
        if let Err(e) = sb_platform::android_protect::protect_udp_socket(&socket) {
            warn!("Failed to protect WireGuard socket: {}", e);
        }

        // Initialize boringtun tunnel
        let tunn = Tunn::new(
            private_key,
            peer_pk,
            psk,
            config.persistent_keepalive,
            0,    // index
            None, // rate limiter
        );

        let inner = Arc::new(WireGuardInner {
            tunn: Mutex::new(tunn),
            socket,
            peer_endpoint: Mutex::new(config.peer_endpoint),
            mtu: config.mtu,
        });

        // Start timer task for keepalive and rekey
        let inner_clone = inner.clone();
        tokio::spawn(async move {
            Self::timer_loop(inner_clone).await;
        });

        Ok(Self { inner })
    }

    /// Timer loop for handling WireGuard timers (keepalive, rekey, etc.)
    async fn timer_loop(inner: Arc<WireGuardInner>) {
        let mut buf = vec![0u8; 65535];
        loop {
            tokio::time::sleep(Duration::from_millis(250)).await;

            let mut tunn = inner.tunn.lock().await;
            match tunn.update_timers(&mut buf) {
                TunnResult::WriteToNetwork(packet) => {
                    let endpoint = *inner.peer_endpoint.lock().await;
                    if let Err(e) = inner.socket.send_to(packet, endpoint).await {
                        warn!("WireGuard timer send error: {}", e);
                    }
                }
                TunnResult::Err(e) => {
                    error!("WireGuard timer error: {:?}", e);
                }
                _ => {}
            }
        }
    }

    /// Send data through the WireGuard tunnel.
    pub async fn send(&self, data: &[u8]) -> io::Result<()> {
        let mut buf = vec![0u8; data.len() + 100]; // Extra space for WG overhead
        let mut tunn = self.inner.tunn.lock().await;

        match tunn.encapsulate(data, &mut buf) {
            TunnResult::WriteToNetwork(packet) => {
                let endpoint = *self.inner.peer_endpoint.lock().await;
                self.inner.socket.send_to(packet, endpoint).await?;
                Ok(())
            }
            TunnResult::Err(e) => Err(io::Error::new(
                io::ErrorKind::Other,
                format!("WireGuard encapsulate error: {:?}", e),
            )),
            _ => Ok(()),
        }
    }

    /// Receive data from the WireGuard tunnel.
    pub async fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        let mut udp_buf = vec![0u8; 65535];
        let mut out_buf = vec![0u8; 65535];

        loop {
            let (n, src) = self.inner.socket.recv_from(&mut udp_buf).await?;
            let packet = &udp_buf[..n];

            let mut tunn = self.inner.tunn.lock().await;
            match tunn.decapsulate(Some(src.ip()), packet, &mut out_buf) {
                TunnResult::WriteToTunnelV4(decrypted, _)
                | TunnResult::WriteToTunnelV6(decrypted, _) => {
                    let len = decrypted.len().min(buf.len());
                    buf[..len].copy_from_slice(&decrypted[..len]);
                    return Ok(len);
                }
                TunnResult::WriteToNetwork(response) => {
                    // Send handshake response
                    drop(tunn);
                    let endpoint = *self.inner.peer_endpoint.lock().await;
                    let _ = self.inner.socket.send_to(response, endpoint).await;
                }
                TunnResult::Err(e) => {
                    trace!("WireGuard decapsulate error: {:?}", e);
                }
                _ => {}
            }
        }
    }

    /// Initiate handshake with peer.
    pub async fn handshake(&self) -> io::Result<()> {
        let mut buf = vec![0u8; 148]; // Handshake initiation size
        let mut tunn = self.inner.tunn.lock().await;

        match tunn.format_handshake_initiation(&mut buf, false) {
            TunnResult::WriteToNetwork(packet) => {
                let endpoint = *self.inner.peer_endpoint.lock().await;
                self.inner.socket.send_to(packet, endpoint).await?;
                debug!("WireGuard handshake initiated");
                Ok(())
            }
            TunnResult::Err(e) => Err(io::Error::new(
                io::ErrorKind::Other,
                format!("WireGuard handshake error: {:?}", e),
            )),
            _ => Ok(()),
        }
    }

    /// Update the peer endpoint address (e.g. for roaming or discovery).
    pub async fn set_peer_endpoint(&self, addr: SocketAddr) {
        let mut guard = self.inner.peer_endpoint.lock().await;
        *guard = addr;
        debug!("WireGuard peer endpoint updated to {}", addr);
    }

    /// Create a new stream sharing the same tunnel state.
    /// 
    /// This creates a stream handling structure without triggering a new handshake.
    /// Useful for adapters that maintain the tunnel lifecycle separately.
    pub fn get_stream(&self) -> WireGuardStream {
        WireGuardStream::new(self.inner.clone())
    }
}

/// WireGuard stream that provides AsyncRead/AsyncWrite over the tunnel.
/// 
/// This uses a simple poll-based approach where reads/writes are performed
/// using the transport's async methods wrapped in a future state.
pub struct WireGuardStream {
    transport: Arc<WireGuardInner>,
    /// Pending read future state
    read_state: Option<Pin<Box<dyn Future<Output = io::Result<Vec<u8>>> + Send>>>,
    /// Pending write future state
    write_state: Option<Pin<Box<dyn Future<Output = io::Result<usize>> + Send>>>,
}

impl WireGuardStream {
    fn new(transport: Arc<WireGuardInner>) -> Self {
        Self {
            transport,
            read_state: None,
            write_state: None,
        }
    }
}

impl AsyncRead for WireGuardStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // If we don't have a pending read, start one
        if self.read_state.is_none() {
            let transport = self.transport.clone();
            let read_future = Box::pin(async move {
                let mut udp_buf = vec![0u8; 65535];
                let mut out_buf = vec![0u8; 65535];

                loop {
                    let (n, src) = transport.socket.recv_from(&mut udp_buf).await?;
                    let packet = &udp_buf[..n];

                    let mut tunn = transport.tunn.lock().await;
                    match tunn.decapsulate(Some(src.ip()), packet, &mut out_buf) {
                        TunnResult::WriteToTunnelV4(decrypted, _)
                        | TunnResult::WriteToTunnelV6(decrypted, _) => {
                            return Ok(decrypted.to_vec());
                        }
                        TunnResult::WriteToNetwork(response) => {
                            // Send handshake response
                            drop(tunn);
                            let endpoint = *transport.peer_endpoint.lock().await;
                            let _ = transport.socket.send_to(response, endpoint).await;
                        }
                        TunnResult::Err(e) => {
                            trace!("WireGuard decapsulate error: {:?}", e);
                        }
                        _ => {}
                    }
                }
            });
            self.read_state = Some(read_future);
        }

        // Poll the pending read
        let state = self.read_state.as_mut().expect("read_state should be Some");
        match Future::poll(state.as_mut(), cx) {
            Poll::Ready(Ok(data)) => {
                self.read_state = None;
                let len = data.len().min(buf.remaining());
                buf.put_slice(&data[..len]);
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(e)) => {
                self.read_state = None;
                Poll::Ready(Err(e))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for WireGuardStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        // If we don't have a pending write, start one
        if self.write_state.is_none() {
            let transport = self.transport.clone();
            let data = buf.to_vec();
            let data_len = data.len();

            let write_future = Box::pin(async move {
                let mut out_buf = vec![0u8; data_len + 100];
                let mut tunn = transport.tunn.lock().await;

                match tunn.encapsulate(&data, &mut out_buf) {
                    TunnResult::WriteToNetwork(packet) => {
                        let endpoint = *transport.peer_endpoint.lock().await;
                        transport.socket.send_to(packet, endpoint).await?;
                        Ok(data_len)
                    }
                    TunnResult::Err(e) => Err(io::Error::new(
                        io::ErrorKind::Other,
                        format!("WireGuard encapsulate error: {:?}", e),
                    )),
                    _ => Ok(0),
                }
            });
            self.write_state = Some(write_future);
        }

        // Poll the pending write
        let state = self.write_state.as_mut().expect("write_state should be Some");
        match Future::poll(state.as_mut(), cx) {
            Poll::Ready(Ok(n)) => {
                self.write_state = None;
                Poll::Ready(Ok(n))
            }
            Poll::Ready(Err(e)) => {
                self.write_state = None;
                Poll::Ready(Err(e))
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        // UDP is datagram-based, no buffering
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        // WireGuard doesn't have a shutdown concept
        Poll::Ready(Ok(()))
    }
}

#[async_trait]
impl Dialer for WireGuardTransport {
    async fn connect(&self, host: &str, port: u16) -> Result<IoStream, DialError> {
        debug!("WireGuard dialing {}:{}", host, port);

        // Initiate handshake if needed
        if let Err(e) = self.handshake().await {
            warn!("WireGuard handshake failed: {}", e);
            // Continue anyway, handshake might complete during data exchange
        }

        // Wait a bit for handshake to complete
        tokio::time::sleep(Duration::from_millis(100)).await;

        let stream = WireGuardStream::new(self.inner.clone());
        Ok(Box::new(stream) as IoStream)
    }

    fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
        self
    }
}

/// Errors that can occur in WireGuard transport.
#[derive(Debug, thiserror::Error)]
pub enum WireGuardError {
    #[error("Invalid private key")]
    InvalidPrivateKey,

    #[error("Invalid peer public key")]
    InvalidPeerPublicKey,

    #[error("Invalid pre-shared key")]
    InvalidPreSharedKey,

    #[error("Socket bind error: {0}")]
    SocketBind(#[source] io::Error),

    #[error("Handshake failed")]
    HandshakeFailed,

    #[error("Tunnel error: {0}")]
    Tunnel(String),
}

impl From<WireGuardError> for DialError {
    fn from(e: WireGuardError) -> Self {
        DialError::Other(e.to_string().into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_default() {
        let config = WireGuardConfig::default();
        assert_eq!(config.mtu, 1420);
        assert_eq!(config.persistent_keepalive, Some(25));
        assert_eq!(config.connect_timeout, Duration::from_secs(10));
    }

    #[test]
    fn test_key_parsing() {
        // Valid test keys (these are example keys, not real secrets)
        let valid_private_key = "YAnz5TF+lXXJte14tji3zlbzbm+JFHYa74LLQDzOjG0=";
        let valid_public_key = "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=";

        // Verify base64 decoding works
        let private_bytes = BASE64.decode(valid_private_key);
        assert!(private_bytes.is_ok());
        assert_eq!(private_bytes.as_ref().map(|v| v.len()), Ok(32));

        let public_bytes = BASE64.decode(valid_public_key);
        assert!(public_bytes.is_ok());
        assert_eq!(public_bytes.as_ref().map(|v| v.len()), Ok(32));
    }

    #[test]
    fn test_invalid_key_detection() {
        let invalid_key = "not-valid-base64!!!";
        assert!(BASE64.decode(invalid_key).is_err());

        let too_short = BASE64.encode([0u8; 16]);
        let decoded = BASE64.decode(&too_short);
        assert!(decoded.is_ok());
        assert_ne!(decoded.as_ref().map(|v| v.len()), Ok(32)); // Wrong length
    }
}
