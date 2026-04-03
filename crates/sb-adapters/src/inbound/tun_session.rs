//! TUN TCP session management and forwarding
//!
//! Manages TCP sessions between TUN interface and outbound connectors.
//! Each session tracks: source/dest address, outbound connection, and relay tasks.
//!
//! NOTE: Skeleton/WIP code - warnings suppressed.
#![allow(unused, dead_code)]

use bytes::Bytes;
use dashmap::DashMap;
use sb_core::net::metered::TrafficRecorder;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc::error::TryRecvError;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
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
#[derive(Debug)]
pub struct TcpSession {
    /// Four-tuple identifying this session
    pub tuple: FourTuple,
    /// When the session was created
    pub created_at: Instant,
    /// Channel to send data from TUN to outbound
    pub to_outbound_tx: mpsc::Sender<Bytes>,
    /// Outbound connection (kept for reference/cleanup)
    pub outbound_addr: SocketAddr,
    /// Next sequence number expected from the TUN-side peer
    client_next_seq: AtomicU32,
    /// Next sequence number to use for synthetic server-side packets
    server_next_seq: AtomicU32,
    /// Highest server-side sequence acknowledged by the TUN-side peer
    server_acked_seq: AtomicU32,
    /// Signal for actively shutting down the outbound relay
    shutdown_tx: parking_lot::Mutex<Option<oneshot::Sender<()>>>,
    /// Owned relay tasks; aborted when the session is explicitly closed.
    tasks: parking_lot::Mutex<Vec<JoinHandle<()>>>,
}

impl TcpSession {
    /// Send data from TUN to outbound connection
    pub async fn send_to_outbound(&self, data: Bytes) -> Result<(), mpsc::error::SendError<Bytes>> {
        self.to_outbound_tx.send(data).await
    }

    pub fn observe_client_segment(&self, next_seq: u32) {
        let mut current = self.client_next_seq.load(Ordering::Relaxed);
        while tcp_seq_is_newer(next_seq, current) {
            match self.client_next_seq.compare_exchange_weak(
                current,
                next_seq,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(observed) => current = observed,
            }
        }
    }

    pub fn client_next_seq(&self) -> u32 {
        self.client_next_seq.load(Ordering::Relaxed)
    }

    pub fn server_next_seq(&self) -> u32 {
        self.server_next_seq.load(Ordering::Relaxed)
    }

    pub fn observe_server_ack(&self, ack: u32) {
        let capped_ack = if tcp_seq_is_newer(ack, self.server_next_seq()) {
            self.server_next_seq()
        } else {
            ack
        };
        let mut current = self.server_acked_seq.load(Ordering::Relaxed);
        while tcp_seq_is_newer(capped_ack, current) {
            match self.server_acked_seq.compare_exchange_weak(
                current,
                capped_ack,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(observed) => current = observed,
            }
        }
    }

    pub fn server_acked_seq(&self) -> u32 {
        self.server_acked_seq.load(Ordering::Relaxed)
    }

    pub fn reserve_server_seq(&self, consumed: u32) -> u32 {
        if consumed == 0 {
            self.server_next_seq()
        } else {
            self.server_next_seq.fetch_add(consumed, Ordering::Relaxed)
        }
    }

    pub fn request_shutdown(&self) {
        if let Some(tx) = self.shutdown_tx.lock().take() {
            let _ = tx.send(());
        }
    }

    pub fn initiate_close(&self) {
        self.request_shutdown();
        self.abort_tracked_tasks();
    }

    fn track_task(&self, task: JoinHandle<()>) {
        self.tasks.lock().push(task);
    }

    fn abort_tracked_tasks(&self) {
        let mut tasks = self.tasks.lock();
        for task in tasks.drain(..) {
            task.abort();
        }
    }
}

fn tcp_seq_is_newer(candidate: u32, current: u32) -> bool {
    candidate != current && candidate.wrapping_sub(current) < (1 << 31)
}

/// Manager for all active TCP sessions
#[derive(Debug)]
pub struct TcpSessionManager {
    /// Active sessions indexed by four-tuple
    active_sessions: Arc<DashMap<FourTuple, Arc<TcpSession>>>,
    /// Sessions that already observed a local FIN and are draining/shutting down.
    detached_sessions: Arc<DashMap<FourTuple, Arc<TcpSession>>>,
}

impl TcpSessionManager {
    pub fn new() -> Self {
        Self {
            active_sessions: Arc::new(DashMap::new()),
            detached_sessions: Arc::new(DashMap::new()),
        }
    }

    /// Get existing session or None
    pub fn get(&self, tuple: &FourTuple) -> Option<Arc<TcpSession>> {
        self.active_sessions
            .get(tuple)
            .map(|entry| Arc::clone(&entry))
    }

    pub fn get_detached(&self, tuple: &FourTuple) -> Option<Arc<TcpSession>> {
        self.detached_sessions
            .get(tuple)
            .map(|entry| Arc::clone(&entry))
    }

    /// Create a new session and spawn relay tasks
    pub fn create_session(
        &self,
        tuple: FourTuple,
        outbound: TcpStream,
        tun_writer: Arc<dyn TunWriter + Send + Sync>,
        traffic: Option<Arc<dyn TrafficRecorder>>,
    ) -> Arc<TcpSession> {
        self.create_session_with_state(tuple, outbound, tun_writer, traffic, 1000, 1000)
    }

    pub fn create_session_with_state(
        &self,
        tuple: FourTuple,
        outbound: TcpStream,
        tun_writer: Arc<dyn TunWriter + Send + Sync>,
        traffic: Option<Arc<dyn TrafficRecorder>>,
        client_next_seq: u32,
        server_next_seq: u32,
    ) -> Arc<TcpSession> {
        let (to_outbound_tx, to_outbound_rx) = mpsc::channel::<Bytes>(64);
        let (shutdown_tx, shutdown_rx) = oneshot::channel();

        let outbound_addr = outbound
            .peer_addr()
            .unwrap_or_else(|_| SocketAddr::from(([0, 0, 0, 0], 0)));

        let session = Arc::new(TcpSession {
            tuple,
            created_at: Instant::now(),
            to_outbound_tx,
            outbound_addr,
            client_next_seq: AtomicU32::new(client_next_seq),
            server_next_seq: AtomicU32::new(server_next_seq),
            server_acked_seq: AtomicU32::new(server_next_seq),
            shutdown_tx: parking_lot::Mutex::new(Some(shutdown_tx)),
            tasks: parking_lot::Mutex::new(Vec::with_capacity(2)),
        });

        let (outbound_read, outbound_write) = outbound.into_split();

        // Spawn relay tasks and keep the handles on the session owner.
        let tuple_copy = tuple;
        let active_sessions = Arc::clone(&self.active_sessions);
        let detached_sessions = Arc::clone(&self.detached_sessions);
        let traffic_c = traffic.clone();
        let tun_to_outbound = tokio::spawn(relay_tun_to_outbound(
            to_outbound_rx,
            shutdown_rx,
            outbound_write,
            tuple_copy,
            Arc::clone(&active_sessions),
            Arc::clone(&detached_sessions),
            traffic_c,
        ));

        let outbound_to_tun = tokio::spawn(relay_outbound_to_tun(
            outbound_read,
            Arc::clone(&session),
            tuple,
            tun_writer,
            Arc::clone(&self.active_sessions),
            Arc::clone(&self.detached_sessions),
            traffic,
        ));

        session.track_task(tun_to_outbound);
        session.track_task(outbound_to_tun);

        // Insert into session map
        self.active_sessions.insert(tuple, Arc::clone(&session));

        debug!(
            "TCP session created: {}:{} -> {}:{}",
            tuple.src_ip, tuple.src_port, tuple.dst_ip, tuple.dst_port
        );

        session
    }

    /// Remove a session
    pub fn remove(&self, tuple: &FourTuple) {
        if let Some(session) = self.remove_session(tuple) {
            session.initiate_close();
            debug!(
                "TCP session removed: {}:{} -> {}:{}",
                tuple.src_ip, tuple.src_port, tuple.dst_ip, tuple.dst_port
            );
        }
    }

    pub fn detach(&self, tuple: &FourTuple) {
        if let Some((_, session)) = self.active_sessions.remove(tuple) {
            self.detached_sessions.insert(*tuple, session);
            debug!(
                "TCP session detached: {}:{} -> {}:{}",
                tuple.src_ip, tuple.src_port, tuple.dst_ip, tuple.dst_port
            );
        }
    }

    /// Get number of active sessions
    pub fn count(&self) -> usize {
        self.active_sessions.len()
    }

    fn remove_session(&self, tuple: &FourTuple) -> Option<Arc<TcpSession>> {
        self.active_sessions
            .remove(tuple)
            .map(|(_, session)| session)
            .or_else(|| self.detached_sessions.remove(tuple).map(|(_, session)| session))
    }
}

impl Default for TcpSessionManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Relay data from TUN to outbound (and spawn outbound->TUN relay)
#[allow(clippy::too_many_arguments)]
async fn relay_tun_to_outbound(
    mut to_outbound_rx: mpsc::Receiver<Bytes>,
    mut shutdown_rx: oneshot::Receiver<()>,
    mut outbound_write: tokio::net::tcp::OwnedWriteHalf,
    tuple: FourTuple,
    active_sessions: Arc<DashMap<FourTuple, Arc<TcpSession>>>,
    detached_sessions: Arc<DashMap<FourTuple, Arc<TcpSession>>>,
    traffic: Option<Arc<dyn TrafficRecorder>>,
) {
    // TUN -> Outbound relay (this task)
    let mut closing = false;
    loop {
        if closing {
            match to_outbound_rx.try_recv() {
                Ok(chunk) => {
                    if let Err(e) = outbound_write.write_all(&chunk).await {
                        warn!(
                            "TCP session {}:{} -> {}:{} write error during shutdown drain: {}",
                            tuple.src_ip, tuple.src_port, tuple.dst_ip, tuple.dst_port, e
                        );
                        break;
                    }
                    if let Some(ref recorder) = traffic {
                        recorder.record_up(chunk.len() as u64);
                    }
                    continue;
                }
                Err(TryRecvError::Empty) | Err(TryRecvError::Disconnected) => {
                    let _ = outbound_write.shutdown().await;
                    break;
                }
            }
        }

        tokio::select! {
            _ = &mut shutdown_rx => {
                debug!(
                    "TCP session shutdown requested: {}:{} -> {}:{}",
                    tuple.src_ip, tuple.src_port, tuple.dst_ip, tuple.dst_port
                );
                closing = true;
            }
            maybe_chunk = to_outbound_rx.recv() => {
                let Some(chunk) = maybe_chunk else {
                    break;
                };
                if let Err(e) = outbound_write.write_all(&chunk).await {
                    warn!(
                        "TCP session {}:{} -> {}:{} write error: {}",
                        tuple.src_ip, tuple.src_port, tuple.dst_ip, tuple.dst_port, e
                    );
                    break;
                }
                if let Some(ref recorder) = traffic {
                    recorder.record_up(chunk.len() as u64);
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
        }
    }

    // Cleanup on connection close
    active_sessions.remove(&tuple);
    detached_sessions.remove(&tuple);
    debug!(
        "TCP relay TUN->Outbound closed: {}:{} -> {}:{}",
        tuple.src_ip, tuple.src_port, tuple.dst_ip, tuple.dst_port
    );
}

/// Relay data from outbound to TUN
async fn relay_outbound_to_tun(
    mut outbound_read: tokio::net::tcp::OwnedReadHalf,
    session: Arc<TcpSession>,
    tuple: FourTuple,
    tun_writer: Arc<dyn TunWriter + Send + Sync>,
    active_sessions: Arc<DashMap<FourTuple, Arc<TcpSession>>>,
    detached_sessions: Arc<DashMap<FourTuple, Arc<TcpSession>>>,
    traffic: Option<Arc<dyn TrafficRecorder>>,
) {
    let mut buf = vec![0u8; 8192];

    loop {
        match outbound_read.read(&mut buf).await {
            Ok(0) => {
                // EOF - connection closed by remote
                debug!(
                    "TCP session EOF: {}:{} -> {}:{}",
                    tuple.src_ip, tuple.src_port, tuple.dst_ip, tuple.dst_port
                );

                // Send FIN packet
                let seq = session.reserve_server_seq(1);
                let ack = session.client_next_seq();
                if let Ok(fin_packet) =
                    build_tcp_response_packet(tuple.reverse(), &[], seq, ack, 0x11)
                {
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
                let seq = session.reserve_server_seq(n as u32);
                let ack = session.client_next_seq();
                match build_tcp_response_packet(tuple.reverse(), &buf[..n], seq, ack, 0x18) {
                    Ok(packet) => {
                        if let Err(e) = tun_writer.write_packet(&packet).await {
                            warn!(
                                "Failed to write to TUN for {}:{}: {}",
                                tuple.src_ip, tuple.src_port, e
                            );
                            break;
                        }
                        if let Some(ref recorder) = traffic {
                            recorder.record_down(n as u64);
                        }
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
    active_sessions.remove(&tuple);
    detached_sessions.remove(&tuple);
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
    fn test_observe_client_segment_never_regresses_sequence() {
        let session = TcpSession {
            tuple: FourTuple::new(
                "192.168.1.2".parse().unwrap(),
                12345,
                "93.184.216.34".parse().unwrap(),
                80,
            ),
            created_at: Instant::now(),
            to_outbound_tx: mpsc::channel(1).0,
            outbound_addr: SocketAddr::from(([127, 0, 0, 1], 80)),
            client_next_seq: AtomicU32::new(100),
            server_next_seq: AtomicU32::new(1000),
            server_acked_seq: AtomicU32::new(1000),
            shutdown_tx: parking_lot::Mutex::new(None),
            tasks: parking_lot::Mutex::new(Vec::new()),
        };

        session.observe_client_segment(120);
        session.observe_client_segment(110);

        assert_eq!(session.client_next_seq(), 120);
    }

    #[test]
    fn test_observe_server_ack_is_monotonic_and_capped() {
        let session = TcpSession {
            tuple: FourTuple::new(
                "192.168.1.2".parse().unwrap(),
                12345,
                "93.184.216.34".parse().unwrap(),
                80,
            ),
            created_at: Instant::now(),
            to_outbound_tx: mpsc::channel(1).0,
            outbound_addr: SocketAddr::from(([127, 0, 0, 1], 80)),
            client_next_seq: AtomicU32::new(100),
            server_next_seq: AtomicU32::new(1010),
            server_acked_seq: AtomicU32::new(1000),
            shutdown_tx: parking_lot::Mutex::new(None),
            tasks: parking_lot::Mutex::new(Vec::new()),
        };

        session.observe_server_ack(1005);
        session.observe_server_ack(1003);
        session.observe_server_ack(1024);

        assert_eq!(session.server_acked_seq(), 1010);
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

    #[tokio::test]
    async fn test_initiate_close_aborts_tracked_tasks() {
        struct NotifyOnDrop(Option<oneshot::Sender<()>>);

        impl Drop for NotifyOnDrop {
            fn drop(&mut self) {
                if let Some(tx) = self.0.take() {
                    let _ = tx.send(());
                }
            }
        }

        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let (task_done_tx, task_done_rx) = oneshot::channel();
        let session = TcpSession {
            tuple: FourTuple::new(
                "192.168.1.2".parse().unwrap(),
                12345,
                "93.184.216.34".parse().unwrap(),
                80,
            ),
            created_at: Instant::now(),
            to_outbound_tx: mpsc::channel(1).0,
            outbound_addr: SocketAddr::from(([127, 0, 0, 1], 80)),
            client_next_seq: AtomicU32::new(100),
            server_next_seq: AtomicU32::new(1000),
            server_acked_seq: AtomicU32::new(1000),
            shutdown_tx: parking_lot::Mutex::new(Some(shutdown_tx)),
            tasks: parking_lot::Mutex::new(Vec::new()),
        };

        session.track_task(tokio::spawn(async move {
            let _guard = NotifyOnDrop(Some(task_done_tx));
            tokio::time::sleep(std::time::Duration::from_secs(60)).await;
        }));
        tokio::task::yield_now().await;

        session.initiate_close();

        shutdown_rx.await.expect("shutdown signal should be sent");
        tokio::time::timeout(std::time::Duration::from_secs(1), task_done_rx)
            .await
            .expect("tracked task should be aborted quickly")
            .expect("abort drop signal should arrive");
        assert!(session.tasks.lock().is_empty());
    }

    #[tokio::test]
    async fn test_request_shutdown_drains_pending_payload_before_detach() {
        struct NoopTunWriter;

        #[async_trait::async_trait]
        impl TunWriter for NoopTunWriter {
            async fn write_packet(&self, _packet: &[u8]) -> std::io::Result<()> {
                Ok(())
            }
        }

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind listener");
        let addr = listener.local_addr().expect("listener addr");
        let (payload_tx, payload_rx) = oneshot::channel();
        let server_task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept");
            let mut buf = [0u8; 8];
            let n = stream.read(&mut buf).await.expect("read payload");
            let _ = payload_tx.send(buf[..n].to_vec());
        });

        let manager = TcpSessionManager::new();
        let outbound = tokio::net::TcpStream::connect(addr)
            .await
            .expect("connect outbound");
        let tuple = FourTuple::new("10.0.0.2".parse().unwrap(), 34567, addr.ip(), addr.port());
        let session = manager.create_session_with_state(
            tuple,
            outbound,
            Arc::new(NoopTunWriter),
            None,
            100,
            1000,
        );

        session
            .send_to_outbound(Bytes::from_static(b"bye"))
            .await
            .expect("queue payload");
        session.request_shutdown();
        manager.detach(&tuple);

        let received = tokio::time::timeout(std::time::Duration::from_secs(2), payload_rx)
            .await
            .expect("receive within timeout")
            .expect("payload sent");
        assert_eq!(received, b"bye");
        server_task.await.expect("server task should finish");
        assert_eq!(manager.count(), 0);
    }

    #[test]
    fn test_detach_moves_session_into_draining_registry() {
        let manager = TcpSessionManager::new();
        let tuple = FourTuple::new(
            "10.0.0.2".parse().unwrap(),
            34567,
            "93.184.216.34".parse().unwrap(),
            80,
        );
        let session = Arc::new(TcpSession {
            tuple,
            created_at: Instant::now(),
            to_outbound_tx: mpsc::channel(1).0,
            outbound_addr: SocketAddr::from(([127, 0, 0, 1], 80)),
            client_next_seq: AtomicU32::new(100),
            server_next_seq: AtomicU32::new(1000),
            server_acked_seq: AtomicU32::new(1000),
            shutdown_tx: parking_lot::Mutex::new(None),
            tasks: parking_lot::Mutex::new(Vec::new()),
        });

        manager.active_sessions.insert(tuple, Arc::clone(&session));
        manager.detach(&tuple);

        assert!(manager.get(&tuple).is_none());
        assert!(manager.get_detached(&tuple).is_some());
        manager.remove(&tuple);
        assert!(manager.get_detached(&tuple).is_none());
    }
}
