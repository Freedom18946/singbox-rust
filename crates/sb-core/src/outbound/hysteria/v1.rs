//! Hysteria v1 protocol implementation
//!
//! Hysteria v1 is a QUIC-based proxy protocol with custom congestion control
//! and UDP relay support.

use async_trait::async_trait;
use bytes::{BufMut, BytesMut};
use quinn::{Connection, Endpoint, RecvStream, SendStream};
use rustls_pemfile;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::Mutex;

use super::super::quic::common::{connect as quic_connect, QuicConfig};
use super::super::types::{HostPort, OutboundTcp};

/// Hysteria v1 configuration
#[derive(Clone, Debug)]
pub struct HysteriaV1Config {
    pub server: String,
    pub port: u16,
    pub protocol: String, // "udp", "wechat-video", "faketcp"
    pub up_mbps: u32,
    pub down_mbps: u32,
    pub obfs: Option<String>,
    pub auth: Option<String>,
    pub alpn: Vec<String>,
    pub recv_window_conn: Option<u64>,
    pub recv_window: Option<u64>,
    pub skip_cert_verify: bool,
    pub sni: Option<String>,
}

impl Default for HysteriaV1Config {
    fn default() -> Self {
        Self {
            server: "127.0.0.1".to_string(),
            port: 443,
            protocol: "udp".to_string(),
            up_mbps: 10,
            down_mbps: 50,
            obfs: None,
            auth: None,
            alpn: vec!["hysteria".to_string()],
            recv_window_conn: None,
            recv_window: None,
            skip_cert_verify: false,
            sni: None,
        }
    }
}

/// Hysteria v1 outbound connector
#[derive(Debug)]
pub struct HysteriaV1Outbound {
    config: HysteriaV1Config,
    quic_config: QuicConfig,
    connection_pool: Arc<Mutex<Option<Connection>>>,
}

impl HysteriaV1Outbound {
    pub fn new(config: HysteriaV1Config) -> anyhow::Result<Self> {
        // Build QUIC configuration
        let mut alpn = config.alpn.clone();
        if alpn.is_empty() {
            alpn.push("hysteria".to_string());
        }

        let alpn_bytes: Vec<Vec<u8>> = alpn.iter().map(|s| s.as_bytes().to_vec()).collect();

        let quic_config = QuicConfig::new(config.server.clone(), config.port)
            .with_alpn(alpn_bytes)
            .with_allow_insecure(config.skip_cert_verify);

        Ok(Self {
            config,
            quic_config,
            connection_pool: Arc::new(Mutex::new(None)),
        })
    }

    /// Get or create a QUIC connection
    async fn get_connection(&self) -> io::Result<Connection> {
        // Check if we have a healthy connection
        if let Some(conn) = {
            let pool = self.connection_pool.lock().await;
            pool.as_ref().cloned()
        } {
            if conn.close_reason().is_none() {
                return Ok(conn);
            }
        }

        // Create new connection
        self.create_new_connection().await
    }

    /// Create a new QUIC connection
    async fn create_new_connection(&self) -> io::Result<Connection> {
        let connection = quic_connect(&self.quic_config)
            .await
            .map_err(|e| io::Error::other(format!("QUIC connection failed: {}", e)))?;

        // Perform Hysteria v1 handshake
        self.hysteria_handshake(&connection).await?;

        // Store in pool
        let mut pool = self.connection_pool.lock().await;
        *pool = Some(connection.clone());

        Ok(connection)
    }

    /// Perform Hysteria v1 handshake
    async fn hysteria_handshake(&self, connection: &Connection) -> io::Result<()> {
        // Open handshake stream
        let (mut send_stream, mut recv_stream) = connection
            .open_bi()
            .await
            .map_err(|e| io::Error::other(format!("Failed to open handshake stream: {}", e)))?;

        // Build handshake packet
        let mut handshake = BytesMut::new();

        // Protocol version (v1)
        handshake.put_u8(0x01);

        // Bandwidth configuration
        handshake.put_u32(self.config.up_mbps);
        handshake.put_u32(self.config.down_mbps);

        // Authentication
        if let Some(ref auth) = self.config.auth {
            handshake.put_u8(auth.len() as u8);
            handshake.put_slice(auth.as_bytes());
        } else {
            handshake.put_u8(0);
        }

        // Obfuscation
        if let Some(ref obfs) = self.config.obfs {
            handshake.put_u8(obfs.len() as u8);
            handshake.put_slice(obfs.as_bytes());
        } else {
            handshake.put_u8(0);
        }

        // Send handshake
        send_stream
            .write_all(&handshake)
            .await
            .map_err(|e| io::Error::other(format!("Handshake write failed: {}", e)))?;

        send_stream
            .finish()
            .map_err(|e| io::Error::other(format!("Handshake finish failed: {}", e)))?;

        // Read handshake response
        let mut response = [0u8; 2];
        recv_stream
            .read_exact(&mut response)
            .await
            .map_err(|e| io::Error::other(format!("Handshake response read failed: {}", e)))?;

        // Check response
        match response[0] {
            0x00 => Ok(()),
            0x01 => Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Hysteria v1 authentication failed",
            )),
            code => Err(io::Error::other(format!(
                "Hysteria v1 handshake failed with code: {}",
                code
            ))),
        }
    }

    /// Create TCP tunnel through Hysteria v1
    async fn create_tcp_tunnel(
        &self,
        connection: &Connection,
        target: &HostPort,
    ) -> io::Result<(SendStream, RecvStream)> {
        // Open bidirectional stream
        let (mut send_stream, recv_stream) = connection
            .open_bi()
            .await
            .map_err(|e| io::Error::other(format!("Failed to open tunnel stream: {}", e)))?;

        // Build connect request
        let mut request = BytesMut::new();

        // Command: TCP connect
        request.put_u8(0x01);

        // Encode target address
        if let Ok(ip) = target.host.parse::<std::net::IpAddr>() {
            match ip {
                std::net::IpAddr::V4(v4) => {
                    request.put_u8(0x01); // IPv4
                    request.put_slice(&v4.octets());
                }
                std::net::IpAddr::V6(v6) => {
                    request.put_u8(0x04); // IPv6
                    request.put_slice(&v6.octets());
                }
            }
        } else {
            request.put_u8(0x03); // Domain
            let domain_bytes = target.host.as_bytes();
            if domain_bytes.len() > 255 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "Domain name too long",
                ));
            }
            request.put_u8(domain_bytes.len() as u8);
            request.put_slice(domain_bytes);
        }

        request.put_u16(target.port);

        // Send connect request
        send_stream
            .write_all(&request)
            .await
            .map_err(|e| io::Error::other(format!("Connect request write failed: {}", e)))?;

        Ok((send_stream, recv_stream))
    }
}

#[async_trait]
impl OutboundTcp for HysteriaV1Outbound {
    type IO = HysteriaV1Stream;

    async fn connect(&self, target: &HostPort) -> io::Result<Self::IO> {
        let connection = self.get_connection().await?;
        let (send_stream, recv_stream) = self.create_tcp_tunnel(&connection, target).await?;

        Ok(HysteriaV1Stream {
            send: send_stream,
            recv: recv_stream,
        })
    }

    fn protocol_name(&self) -> &'static str {
        "hysteria"
    }
}

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
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.send)
            .poll_flush(cx)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.send)
            .poll_shutdown(cx)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))
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
        use std::sync::Arc;

        // Load TLS certificate and key
        let cert_chain = std::fs::read(&self.config.cert_path).map_err(|e| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("Failed to read cert: {}", e),
            )
        })?;
        let key = std::fs::read(&self.config.key_path).map_err(|e| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("Failed to read key: {}", e),
            )
        })?;

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
            let streams =
                quinn::VarInt::from_u64(recv_window).unwrap_or(quinn::VarInt::from_u32(100));
            transport_config.max_concurrent_bidi_streams(streams);
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

    /// Accept incoming connections
    pub async fn accept(&self) -> io::Result<(HysteriaV1Stream, SocketAddr)> {
        let endpoint = {
            let ep_lock = self.endpoint.lock().await;
            ep_lock
                .as_ref()
                .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "Server not started"))?
                .clone()
        };

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

/// UDP session for Hysteria v1
pub struct UdpSession {
    pub session_id: u32,
    pub client_addr: SocketAddr,
    pub target_addr: SocketAddr,
    pub last_activity: std::time::Instant,
}

/// UDP session manager
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
        let mut sessions = self.sessions.lock().await;
        sessions.insert(
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
        let sessions = self.sessions.lock().await;
        sessions.get(&session_id).cloned()
    }

    pub async fn cleanup_expired(&self) {
        let mut sessions = self.sessions.lock().await;
        let now = std::time::Instant::now();
        sessions.retain(|_, session| now.duration_since(session.last_activity) < self.timeout);
    }
}

impl Clone for UdpSession {
    fn clone(&self) -> Self {
        Self {
            session_id: self.session_id,
            client_addr: self.client_addr,
            target_addr: self.target_addr,
            last_activity: self.last_activity,
        }
    }
}

#[cfg(test)]
#[path = "v1_tests.rs"]
mod tests;
