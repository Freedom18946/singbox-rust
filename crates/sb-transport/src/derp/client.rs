use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio::time::timeout;
use tracing::{debug, info, trace};

use crate::derp::protocol::{DerpFrame, PublicKey};

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
}

impl DerpClient {
    /// Create a new DERP client.
    pub fn new(server_addr: impl Into<String>, public_key: PublicKey) -> Self {
        Self {
            server_addr: server_addr.into(),
            timeout: Duration::from_secs(10),
            stream: Arc::new(Mutex::new(None)),
            public_key,
        }
    }

    /// Set connection timeout.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
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
        // TODO: Proper URL parsing and DNS resolution
        // For now, assume it's "host:port"
        let addr_str = if self.server_addr.contains("://") {
             self.server_addr.split("://").nth(1).unwrap_or(&self.server_addr)
        } else {
            &self.server_addr
        };
        
        // Use tokio lookup
        let mut addrs = tokio::net::lookup_host(addr_str).await?;
        addrs.next().ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, "Could not resolve DERP server address")
        })
    }

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
                // TODO: Verify server key if we have expected one
            }
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Expected ServerKey frame",
                ));
            }
        }

        // 2. Send ClientInfo
        let client_info = DerpFrame::ClientInfo {
            key: self.public_key,
        };
        client_info
            .write_to_async(stream)
            .await
            .map_err(|e| io::Error::other(e.to_string()))?;
        
        debug!("Sent ClientInfo with key: {:02x?}", self.public_key);
        
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
            frame.write_to_async(stream).await.map_err(|e| {
                io::Error::other(format!("Failed to send packet: {}", e))
            })?;
            Ok(())
        } else {
            Err(io::Error::new(io::ErrorKind::NotConnected, "DERP client not connected"))
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
                        pong.write_to_async(stream).await.map_err(io::Error::other)?;
                    }
                    DerpFrame::KeepAlive => {
                        trace!("Received KeepAlive");
                    }
                    DerpFrame::PeerGone { key } => {
                        debug!("Peer gone: {:02x?}", key);
                    }
                    DerpFrame::PeerPresent { key } => {
                        debug!("Peer present: {:02x?}", key);
                    }
                    _ => {
                        trace!("Received other frame: {:?}", frame.frame_type());
                    }
                }
            }
        } else {
            Err(io::Error::new(io::ErrorKind::NotConnected, "DERP client not connected"))
        }
    }
    
    /// Close the connection.
    pub async fn close(&self) {
        let mut guard = self.stream.lock().await;
        *guard = None;
    }
}
