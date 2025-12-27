use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio::time::timeout;
use tracing::{debug, info, trace};

use crate::derp::protocol::{ClientInfoPayload, DerpFrame, PublicKey};

/// Client for DERP (Designated Encrypted Relay for Packets).
///
/// Handles connection establishment, handshake, and packet forwarding
/// through DERP relay servers.
#[derive(Debug)]
pub struct DerpClient {
    /// Server URL or address.
    server_addr: String,
    /// Connection timeout.
    timeout: Duration,
    /// Active connection stream (protected by Mutex).
    stream: Arc<Mutex<Option<TcpStream>>>,
    /// Client's public key.
    public_key: PublicKey,
    /// Optional mesh key for mesh peer authentication.
    mesh_key: Option<String>,
    /// Expected server public key for verification.
    expected_server_key: Option<PublicKey>,
}

impl DerpClient {
    /// Create a new DERP client.
    pub fn new(server_addr: impl Into<String>, public_key: PublicKey) -> Self {
        Self {
            server_addr: server_addr.into(),
            timeout: Duration::from_secs(10),
            stream: Arc::new(Mutex::new(None)),
            public_key,
            mesh_key: None,
            expected_server_key: None,
        }
    }

    /// Set connection timeout.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Set mesh key for mesh peer authentication.
    /// When set, client will send mesh_key in ClientInfo to authenticate as a mesh peer.
    pub fn with_mesh_key(mut self, key: impl Into<String>) -> Self {
        self.mesh_key = Some(key.into());
        self
    }

    /// Set expected server public key for verification.
    pub fn with_expected_key(mut self, key: PublicKey) -> Self {
        self.expected_server_key = Some(key);
        self
    }

    /// Connect to the DERP server and perform handshake.
    pub async fn connect(&self) -> io::Result<()> {
        let addr = self.resolve_addr().await?;
        debug!("Connecting to DERP server at {}", addr);

        let mut stream = timeout(self.timeout, TcpStream::connect(addr))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "Connection timed out"))??;

        // Perform handshake
        self.handshake(&mut stream).await?;

        info!("DERP handshake successful with {}", self.server_addr);

        let mut guard = self.stream.lock().await;
        *guard = Some(stream);

        Ok(())
    }

    /// Resolve server address (naive implementation, assumes IP:Port or simple host:port).
    async fn resolve_addr(&self) -> io::Result<SocketAddr> {
        let mut addr_str = self.server_addr.as_str();
        let mut default_port = 443;

        // Simple scheme parsing
        if let Some(pos) = addr_str.find("://") {
            let scheme = &addr_str[..pos];
            if scheme.eq_ignore_ascii_case("http") {
                default_port = 80;
            }
            addr_str = &addr_str[pos + 3..];
        }

        // Check if port is missing
        let host_port_str = if addr_str.contains(']') {
            // IPv6 [host]:port
             if !addr_str.ends_with(']') && addr_str.rfind(':').map(|c| c > addr_str.rfind(']').unwrap()).unwrap_or(false) {
                 addr_str.to_string()
             } else {
                 format!("{}:{}", addr_str, default_port)
             }
        } else if addr_str.contains(':') {
             // IPv4 or host:port
             // If multiple colons, it might be raw IPv6 without brackets (which is invalid for SocketAddr lookup usually, needs brackets)
             // But assume standard host:port or ipv4:port
             // If it has one colon, it has port.
             // If more than one... could be IPv6? tokio lookup handles raw IPv6 sometimes provided.
             // But standard URL format for IPv6 is [addr]:port.
             // Let's rely on if it parses.
             if addr_str.rfind(':').is_some() {
                 addr_str.to_string()
             } else {
                 format!("{}:{}", addr_str, default_port)
             }
        } else {
            format!("{}:{}", addr_str, default_port)
        };

        // Use tokio lookup
        let mut addrs = tokio::net::lookup_host(&host_port_str).await?;
        addrs.next().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                "Could not resolve DERP server address",
            )
        })
    }

    /// Perform DERP handshake.
    /// Perform DERP handshake.
    async fn handshake(&self, stream: &mut TcpStream) -> io::Result<()> {
        // 1. Read ServerKey
        let frame = timeout(self.timeout, DerpFrame::read_from_async(stream))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "Handshake timed out"))?
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;

        match frame {
            DerpFrame::ServerKey { key } => {
                trace!("Received DERP server key: {:02x?}", key);
                if let Some(expected) = self.expected_server_key {
                    if key != expected {
                         return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("Server key mismatch: expected {:02x?}, got {:02x?}", expected, key),
                        ));
                    }
                }
            }
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Expected ServerKey frame",
                ));
            }
        }

        // 2. Send ClientInfo with optional mesh_key in encrypted_info
        let encrypted_info = if let Some(mesh_key) = self.mesh_key.as_deref() {
            // NOTE: This is not a NaCl box yet; DERP wire protocol parity work will
            // switch this to crypto_box encryption.
            let payload = ClientInfoPayload::new(crate::derp::protocol::PROTOCOL_VERSION as u32)
                .with_mesh_key(mesh_key)
                .with_can_ack_pings(true);
            payload.to_json()
        } else {
            vec![]
        };

        let client_info = DerpFrame::ClientInfo {
            key: self.public_key,
            encrypted_info,
        };
        client_info
            .write_to_async(stream)
            .await
            .map_err(|e| io::Error::other(e.to_string()))?;

        if self.mesh_key.is_some() {
            debug!("Sent ClientInfo with mesh_key for mesh peer authentication");
        } else {
            debug!("Sent ClientInfo with key: {:02x?}", self.public_key);
        }

        Ok(())
    }

    /// Send a packet to a destination peer.
    pub async fn send_packet(&self, dst_key: PublicKey, packet: &[u8]) -> io::Result<()> {
        let mut guard = self.stream.lock().await;
        if let Some(stream) = guard.as_mut() {
            let frame = DerpFrame::SendPacket {
                dst_key,
                packet: packet.to_vec(),
            };
            frame
                .write_to_async(stream)
                .await
                .map_err(|e| io::Error::other(format!("Failed to send packet: {}", e)))?;
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "DERP client not connected",
            ))
        }
    }

    /// Receive the next frame from the server (packet or control).
    /// Returns (src_key, packet_data) for data packets.
    /// Handles control frames internaly (Ping/Pong/KeepAlive).
    pub async fn recv_packet(&self) -> io::Result<(PublicKey, Vec<u8>)> {
        let mut guard = self.stream.lock().await;
        if let Some(stream) = guard.as_mut() {
            loop {
                // Read next frame
                let frame = DerpFrame::read_from_async(stream)
                    .await
                    .map_err(|e| io::Error::other(e.to_string()))?;

                match frame {
                    DerpFrame::RecvPacket { src_key, packet } => {
                        return Ok((src_key, packet));
                    }
                    DerpFrame::Ping { data } => {
                        trace!("Received Ping, sending Pong");
                        let pong = DerpFrame::Pong { data };
                        pong.write_to_async(stream)
                            .await
                            .map_err(io::Error::other)?;
                    }
                    DerpFrame::KeepAlive => {
                        trace!("Received KeepAlive");
                    }
                    DerpFrame::PeerGone { key, .. } => {
                        debug!("Peer gone: {:02x?}", key);
                    }
                    DerpFrame::PeerPresent { key, .. } => {
                        debug!("Peer present: {:02x?}", key);
                    }
                    _ => {
                        trace!("Received other frame: {:?}", frame.frame_type());
                    }
                }
            }
        } else {
            Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "DERP client not connected",
            ))
        }
    }

    /// Close the connection.
    pub async fn close(&self) {
        let mut guard = self.stream.lock().await;
        *guard = None;
    }
}
