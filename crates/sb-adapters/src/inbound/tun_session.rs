//! TUN TCP session management and forwarding
//!
//! Manages TCP sessions between TUN interface and outbound connectors.
//! Each session tracks: source/dest address, outbound connection, and relay tasks.
//!
//! NOTE: Skeleton/WIP code - warnings suppressed.
#![allow(unused, dead_code)]

use bytes::Bytes;
use dashmap::DashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Instant;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tracing::{debug, trace, warn};

/// Four-tuple identifying a unique TCP connection
#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq)]
pub struct FourTuple {
    pub src_ip: IpAddr,
    pub src_port: u16,
    pub dst_ip: IpAddr,
    pub dst_port: u16,
}

impl FourTuple {
    pub fn new(src_ip: IpAddr, src_port: u16, dst_ip: IpAddr, dst_port: u16) -> Self {
        Self {
            src_ip,
            src_port,
            dst_ip,
            dst_port,
        }
    }

    /// Reverse the tuple (useful for reply packets)
    pub fn reverse(&self) -> Self {
        Self {
            src_ip: self.dst_ip,
            src_port: self.dst_port,
            dst_ip: self.src_ip,
            dst_port: self.src_port,
        }
    }
}

/// Active TCP session state
pub struct TcpSession {
    /// Four-tuple identifying this session
    pub tuple: FourTuple,
    /// When the session was created
    pub created_at: Instant,
    /// Channel to send data from TUN to outbound
    pub to_outbound_tx: mpsc::Sender<Bytes>,
    /// Outbound connection (kept for reference/cleanup)
    pub outbound_addr: SocketAddr,
}

impl TcpSession {
    /// Send data from TUN to outbound connection
    pub async fn send_to_outbound(&self, data: Bytes) -> Result<(), mpsc::error::SendError<Bytes>> {
        self.to_outbound_tx.send(data).await
    }
}

/// Manager for all active TCP sessions
pub struct TcpSessionManager {
    /// Active sessions indexed by four-tuple
    sessions: Arc<DashMap<FourTuple, Arc<TcpSession>>>,
}

impl TcpSessionManager {
    pub fn new() -> Self {
        Self {
            sessions: Arc::new(DashMap::new()),
        }
    }

    /// Get existing session or None
    pub fn get(&self, tuple: &FourTuple) -> Option<Arc<TcpSession>> {
        self.sessions.get(tuple).map(|entry| Arc::clone(&entry))
    }

    /// Create a new session and spawn relay tasks
    pub fn create_session(
        &self,
        tuple: FourTuple,
        outbound: TcpStream,
        tun_writer: Arc<dyn TunWriter + Send + Sync>,
    ) -> Arc<TcpSession> {
        let (to_outbound_tx, to_outbound_rx) = mpsc::channel::<Bytes>(64);
        
        let outbound_addr = outbound
            .peer_addr()
            .unwrap_or_else(|_| SocketAddr::from(([0, 0, 0, 0], 0)));

        let session = Arc::new(TcpSession {
            tuple,
            created_at: Instant::now(),
            to_outbound_tx,
            outbound_addr,
        });

        // Spawn relay tasks
        let tuple_copy = tuple;
        let sessions = Arc::clone(&self.sessions);
        
        // TUN -> Outbound relay
        tokio::spawn(relay_tun_to_outbound(
            to_outbound_rx,
            outbound,
            tuple_copy,
            Arc::clone(&tun_writer),
            Arc::clone(&sessions),
        ));

        // Insert into session map
        self.sessions.insert(tuple, Arc::clone(&session));
        
        debug!(
            "TCP session created: {}:{} -> {}:{}",
            tuple.src_ip, tuple.src_port, tuple.dst_ip, tuple.dst_port
        );

        session
    }

    /// Remove a session
    pub fn remove(&self, tuple: &FourTuple) {
        if self.sessions.remove(tuple).is_some() {
            debug!(
                "TCP session removed: {}:{} -> {}:{}",
                tuple.src_ip, tuple.src_port, tuple.dst_ip, tuple.dst_port
            );
        }
    }

    /// Get number of active sessions
    pub fn count(&self) -> usize {
        self.sessions.len()
    }
}

impl Default for TcpSessionManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Relay data from TUN to outbound (and spawn outbound->TUN relay)
async fn relay_tun_to_outbound(
    mut to_outbound_rx: mpsc::Receiver<Bytes>,
    outbound: TcpStream,
    tuple: FourTuple,
    tun_writer: Arc<dyn TunWriter + Send + Sync>,
    sessions: Arc<DashMap<FourTuple, Arc<TcpSession>>>,
) {
    // Split outbound stream for bidirectional relay
    // Use into_split() to take ownership instead of borrowing
    let (mut outbound_read, mut outbound_write) = outbound.into_split();

    // Spawn Outbound -> TUN relay
    let tuple_copy = tuple;
    let tun_writer_copy = Arc::clone(&tun_writer);
    let sessions_copy = Arc::clone(&sessions);
    
    tokio::spawn(async move {
        relay_outbound_to_tun(
            &mut outbound_read,
            tuple_copy,
            tun_writer_copy,
            sessions_copy,
        )
        .await;
    });

    // TUN -> Outbound relay (this task)
    while let Some(chunk) = to_outbound_rx.recv().await {
        if let Err(e) = outbound_write.write_all(&chunk).await {
            warn!(
                "TCP session {}:{} -> {}:{} write error: {}",
                tuple.src_ip, tuple.src_port, tuple.dst_ip, tuple.dst_port, e
            );
            break;
        }
        trace!(
            "TUN->Outbound: {} bytes for {}:{} -> {}:{}",
            chunk.len(),
            tuple.src_ip,
            tuple.src_port,
            tuple.dst_ip,
            tuple.dst_port
        );
    }

    // Cleanup on connection close
    sessions.remove(&tuple);
    debug!(
        "TCP relay TUN->Outbound closed: {}:{} -> {}:{}",
        tuple.src_ip, tuple.src_port, tuple.dst_ip, tuple.dst_port
    );
}

/// Relay data from outbound to TUN
async fn relay_outbound_to_tun(
    outbound_read: &mut tokio::net::tcp::OwnedReadHalf,
    tuple: FourTuple,
    tun_writer: Arc<dyn TunWriter + Send + Sync>,
    sessions: Arc<DashMap<FourTuple, Arc<TcpSession>>>,
) {
    let mut buf = vec![0u8; 8192];
    let mut seq = 1000u32; // Simplified: real impl should track actual seq
    let mut ack = 1000u32;
    
    loop {
        match outbound_read.read(&mut buf).await {
            Ok(0) => {
                // EOF - connection closed by remote
                debug!(
                    "TCP session EOF: {}:{} -> {}:{}",
                    tuple.src_ip, tuple.src_port, tuple.dst_ip, tuple.dst_port
                );
                
                // Send FIN packet
                if let Ok(fin_packet) = build_tcp_response_packet(tuple.reverse(), &[], seq, ack, 0x11) {
                    let _ = tun_writer.write_packet(&fin_packet).await;
                }
                break;
            }
            Ok(n) => {
                trace!(
                    "Outbound->TUN: {} bytes for {}:{} -> {}:{}",
                    n,
                    tuple.src_ip,
                    tuple.src_port,
                    tuple.dst_ip,
                    tuple.dst_port
                );
                
                // Build response packet (reversed tuple for reply direction)
                match build_tcp_response_packet(tuple.reverse(), &buf[..n], seq, ack, 0x18) {
                    Ok(packet) => {
                        if let Err(e) = tun_writer.write_packet(&packet).await {
                            warn!(
                                "Failed to write to TUN for {}:{}: {}",
                                tuple.src_ip, tuple.src_port, e
                            );
                            break;
                        }
                        seq = seq.wrapping_add(n as u32);
                    }
                    Err(e) => {
                        warn!("Failed to build TCP packet: {}", e);
                        break;
                    }
                }
            }
            Err(e) => {
                warn!(
                    "TCP session read error {}:{} -> {}:{}: {}",
                    tuple.src_ip, tuple.src_port, tuple.dst_ip, tuple.dst_port, e
                );
                break;
            }
        }
    }

    // Cleanup session
    sessions.remove(&tuple);
    debug!(
        "TCP relay Outbound->TUN closed: {}:{} -> {}:{}",
        tuple.src_ip, tuple.src_port, tuple.dst_ip, tuple.dst_port
    );
}

/// Trait for writing packets back to TUN interface
#[async_trait::async_trait]
pub trait TunWriter: Send + Sync {
    /// Write a raw IP packet back to TUN
    async fn write_packet(&self, packet: &[u8]) -> std::io::Result<()>;
}

/// Build TCP response packet for writing to TUN
pub fn build_tcp_response_packet(
    tuple: FourTuple,
    payload: &[u8],
    seq: u32,
    ack: u32,
    flags: u8,
) -> std::io::Result<Vec<u8>> {
    use std::net::Ipv4Addr;
    
    match (tuple.src_ip, tuple.dst_ip) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => {
            // Use external packet construction module
            Ok(super::tun_packet::build_ipv4_tcp_packet(
                src,
                tuple.src_port,
                dst,
                tuple.dst_port,
                payload,
                seq,
                ack,
                flags,
            ))
        }
        _ => {
            // IPv6 not yet implemented
            Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "IPv6 not yet supported",
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_four_tuple_reverse() {
        let tuple = FourTuple::new(
            "192.168.1.2".parse().unwrap(),
            12345,
            "93.184.216.34".parse().unwrap(),
            80,
        );
        
        let reversed = tuple.reverse();
        assert_eq!(reversed.src_ip, tuple.dst_ip);
        assert_eq!(reversed.src_port, tuple.dst_port);
        assert_eq!(reversed.dst_ip, tuple.src_ip);
        assert_eq!(reversed.dst_port, tuple.src_port);
    }

    #[test]
    fn test_session_manager_create() {
        let mgr = TcpSessionManager::new();
        assert_eq!(mgr.count(), 0);
        
        // Session creation requires actual TcpStream, skip in unit test
        // Integration test will cover this
    }

    #[test]
    fn test_tcp_response_packet_construction() {
        let tuple = FourTuple::new(
            "192.168.1.2".parse().unwrap(),
            12345,
            "93.184.216.34".parse().unwrap(),
            80,
        );
        
        let packet = build_tcp_response_packet(tuple, b"Hello", 1000, 2000, 0x18);
        assert!(packet.is_ok());
        let packet = packet.unwrap();
        assert!(packet.len() >= 40); // IP + TCP headers minimum
    }
}

