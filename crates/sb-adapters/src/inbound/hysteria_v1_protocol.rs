//! Hysteria v1 server protocol relocated from sb-core.

use quinn::{Endpoint, RecvStream, SendStream};
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::Mutex;

/// Hysteria v1 stream wrapper
pub struct HysteriaV1Stream {
    send: SendStream,
    recv: RecvStream,
}

impl AsyncRead for HysteriaV1Stream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.recv).poll_read(cx, buf)
    }
}

impl AsyncWrite for HysteriaV1Stream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        std::pin::Pin::new(&mut self.send)
            .poll_write(cx, buf)
            .map_err(io::Error::other)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.send)
            .poll_flush(cx)
            .map_err(io::Error::other)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.send)
            .poll_shutdown(cx)
            .map_err(io::Error::other)
    }
}

/// Hysteria v1 inbound server
#[derive(Debug)]
pub struct HysteriaV1Inbound {
    config: HysteriaV1ServerConfig,
    endpoint: Arc<Mutex<Option<Endpoint>>>,
}

impl HysteriaV1Inbound {
    pub fn new(config: HysteriaV1ServerConfig) -> Self {
        Self {
            config,
            endpoint: Arc::new(Mutex::new(None)),
        }
    }

    /// Start the Hysteria v1 server
    pub async fn start(&self) -> io::Result<()> {
        use quinn::ServerConfig;
        use rustls_pemfile;
        use std::sync::Arc;

        // Helper: Read file with context
        let read_file = |path: &str, file_type: &str| {
            std::fs::read(path).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("Failed to read {}: {}", file_type, e),
                )
            })
        };

        // Load TLS certificate and key
        let cert_chain = read_file(&self.config.cert_path, "cert")?;
        let key = read_file(&self.config.key_path, "key")?;

        // Parse certificate and key
        let cert_chain = rustls_pemfile::certs(&mut &cert_chain[..])
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| {
                io::Error::new(io::ErrorKind::InvalidData, format!("Invalid cert: {}", e))
            })?;

        let key = rustls_pemfile::private_key(&mut &key[..])
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("Invalid key: {}", e)))?
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "No private key found"))?;

        // Build TLS config
        sb_tls::ensure_crypto_provider();

        let mut tls_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(cert_chain, key)
            .map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("TLS config error: {}", e),
                )
            })?;

        tls_config.alpn_protocols = vec![b"hysteria".to_vec()];

        // Build QUIC server config
        let mut server_config = ServerConfig::with_crypto(Arc::new(
            quinn::crypto::rustls::QuicServerConfig::try_from(tls_config).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("QUIC config error: {}", e),
                )
            })?,
        ));

        // Configure transport
        let mut transport_config = quinn::TransportConfig::default();
        if let Some(recv_window) = self.config.recv_window_conn {
            if let Ok(streams) = quinn::VarInt::from_u64(recv_window) {
                transport_config.max_concurrent_bidi_streams(streams);
            }
        }
        server_config.transport_config(Arc::new(transport_config));

        // Create endpoint
        let endpoint = Endpoint::server(server_config, self.config.listen).map_err(|e| {
            io::Error::new(io::ErrorKind::AddrInUse, format!("Failed to bind: {}", e))
        })?;

        let mut ep_lock = self.endpoint.lock().await;
        *ep_lock = Some(endpoint);

        Ok(())
    }

    /// Get the local address the server is bound to
    pub async fn local_addr(&self) -> io::Result<SocketAddr> {
        let endpoint = self.endpoint.lock().await;
        if let Some(ep) = &*endpoint {
            ep.local_addr()
        } else {
            Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "Server not started",
            ))
        }
    }

    /// Accept incoming connections
    pub async fn accept(&self) -> io::Result<(HysteriaV1Stream, SocketAddr)> {
        let endpoint = self
            .endpoint
            .lock()
            .await
            .clone()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "Server not started"))?;

        // Accept QUIC connection
        let connecting = endpoint
            .accept()
            .await
            .ok_or_else(|| io::Error::new(io::ErrorKind::ConnectionAborted, "Endpoint closed"))?;

        let connection = connecting.await.map_err(|e| {
            io::Error::new(
                io::ErrorKind::ConnectionRefused,
                format!("Connection failed: {}", e),
            )
        })?;

        let client_addr = connection.remote_address();

        // Accept handshake stream
        let (send_stream, mut recv_stream) = connection.accept_bi().await.map_err(|e| {
            io::Error::new(
                io::ErrorKind::ConnectionAborted,
                format!("Failed to accept stream: {}", e),
            )
        })?;

        // Read handshake
        let mut handshake_buf = vec![0u8; 1024];
        let n = recv_stream
            .read(&mut handshake_buf)
            .await
            .map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("Handshake read failed: {}", e),
                )
            })?
            .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "Empty handshake"))?;

        handshake_buf.truncate(n);

        // Validate handshake
        if let Err(e) = self.validate_handshake(&handshake_buf) {
            // Send error response
            let mut send = send_stream;
            let _ = send.write_all(&[0x01]).await;
            return Err(e);
        }

        // Send success response
        let mut send = send_stream;
        send.write_all(&[0x00, 0x00]).await.map_err(|e| {
            io::Error::new(
                io::ErrorKind::BrokenPipe,
                format!("Response write failed: {}", e),
            )
        })?;

        // Accept data stream
        let (send_stream, recv_stream) = connection.accept_bi().await.map_err(|e| {
            io::Error::new(
                io::ErrorKind::ConnectionAborted,
                format!("Failed to accept data stream: {}", e),
            )
        })?;

        Ok((
            HysteriaV1Stream {
                send: send_stream,
                recv: recv_stream,
            },
            client_addr,
        ))
    }

    /// Validate handshake data
    fn validate_handshake(&self, data: &[u8]) -> io::Result<()> {
        if data.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Empty handshake",
            ));
        }

        let mut cursor = 0;

        // Check version
        if data[cursor] != 0x01 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Unsupported version: {}", data[cursor]),
            ));
        }
        cursor += 1;

        // Skip bandwidth config (8 bytes)
        if data.len() < cursor + 8 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Incomplete handshake",
            ));
        }
        cursor += 8;

        // Check auth
        if data.len() < cursor + 1 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Missing auth length",
            ));
        }
        let auth_len = data[cursor] as usize;
        cursor += 1;

        if auth_len > 0 {
            if data.len() < cursor + auth_len {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Incomplete auth",
                ));
            }

            let client_auth = std::str::from_utf8(&data[cursor..cursor + auth_len])
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Invalid auth encoding"))?;

            if let Some(ref expected_auth) = self.config.auth {
                if client_auth != expected_auth {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "Authentication failed",
                    ));
                }
            }
        } else if self.config.auth.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Authentication required",
            ));
        }

        Ok(())
    }
}

/// Hysteria v1 server configuration
#[derive(Clone, Debug)]
pub struct HysteriaV1ServerConfig {
    pub listen: SocketAddr,
    pub up_mbps: u32,
    pub down_mbps: u32,
    pub obfs: Option<String>,
    pub auth: Option<String>,
    pub cert_path: String,
    pub key_path: String,
    pub recv_window_conn: Option<u64>,
    pub recv_window: Option<u64>,
}

#[derive(Clone, Debug)]
pub struct UdpSession {
    pub session_id: u32,
    pub client_addr: SocketAddr,
    pub target_addr: SocketAddr,
    pub last_activity: std::time::Instant,
}

pub struct UdpSessionManager {
    sessions: Arc<Mutex<std::collections::HashMap<u32, UdpSession>>>,
    timeout: Duration,
}

impl UdpSessionManager {
    pub fn new(timeout: Duration) -> Self {
        Self {
            sessions: Arc::new(Mutex::new(std::collections::HashMap::new())),
            timeout,
        }
    }

    pub async fn create_session(
        &self,
        session_id: u32,
        client_addr: SocketAddr,
        target_addr: SocketAddr,
    ) {
        self.sessions.lock().await.insert(
            session_id,
            UdpSession {
                session_id,
                client_addr,
                target_addr,
                last_activity: std::time::Instant::now(),
            },
        );
    }

    pub async fn get_session(&self, session_id: u32) -> Option<UdpSession> {
        self.sessions.lock().await.get(&session_id).cloned()
    }

    pub async fn cleanup_expired(&self) {
        let now = std::time::Instant::now();
        self.sessions
            .lock()
            .await
            .retain(|_, session| now.duration_since(session.last_activity) < self.timeout);
    }
}
