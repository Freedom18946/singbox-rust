//! Direct inbound: a simple TCP/UDP forwarder that listens on a local address
//! and forwards all connections to a fixed override destination.
//!
//! Fields are supplied via IR (listen, port, override_host, override_port, udp).
//! TCP and UDP are both supported; when `udp` is true, UDP packets are forwarded
//! using a session-based NAT model with automatic timeout cleanup.

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::Mutex;
use tokio::time::timeout;

use crate::adapter::InboundService;
use crate::net::metered;
use crate::services::v2ray_api::StatsManager;

#[derive(Debug, Clone)]
pub struct DirectConfig {
    pub timeout_ms: u64,
    pub max_connections: usize,
    pub udp_timeout_sec: u64,
}

impl Default for DirectConfig {
    fn default() -> Self {
        Self {
            timeout_ms: 30000,
            max_connections: 2000,
            udp_timeout_sec: 60,
        }
    }
}

/// UDP session tracking for NAT-like behavior
#[derive(Debug)]
struct UdpSession {
    socket: Arc<UdpSocket>,
    last_activity: Instant,
}

#[derive(Debug)]
pub struct DirectForward {
    listen: SocketAddr,
    dst_host: String,
    dst_port: u16,
    udp_enabled: bool,
    cfg: DirectConfig,
    tag: Option<String>,
    stats: Option<Arc<StatsManager>>,
    shutdown: Arc<AtomicBool>,
    udp_sessions: Arc<Mutex<HashMap<SocketAddr, UdpSession>>>,
    active: Arc<AtomicU64>,
    udp_count: Arc<AtomicU64>,
}

impl DirectForward {
    pub fn new(listen: SocketAddr, dst_host: String, dst_port: u16, udp_enabled: bool) -> Self {
        Self {
            listen,
            dst_host,
            dst_port,
            udp_enabled,
            cfg: DirectConfig::default(),
            tag: None,
            stats: None,
            shutdown: Arc::new(AtomicBool::new(false)),
            udp_sessions: Arc::new(Mutex::new(HashMap::new())),
            active: Arc::new(AtomicU64::new(0)),
            udp_count: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Return the configured listen address (may contain port 0 before binding)
    pub fn listen_addr(&self) -> SocketAddr {
        self.listen
    }

    pub fn with_config(mut self, cfg: DirectConfig) -> Self {
        self.cfg = cfg;
        self
    }

    pub fn with_tag(mut self, tag: Option<String>) -> Self {
        self.tag = tag;
        self
    }

    pub fn with_stats(mut self, stats: Option<Arc<StatsManager>>) -> Self {
        self.stats = stats;
        self
    }

    async fn handle_tcp(&self, mut cli: TcpStream) -> io::Result<()> {
        // Establish upstream connection to fixed target
        let addr = format!("{}:{}", self.dst_host, self.dst_port);
        let mut upstream = timeout(
            Duration::from_millis(self.cfg.timeout_ms),
            TcpStream::connect(&addr),
        )
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "connect timeout"))??;

        let traffic = self
            .stats
            .as_ref()
            .and_then(|stats| stats.traffic_recorder(self.tag.as_deref(), Some("direct"), None));
        let _ = metered::copy_bidirectional_streaming_ctl(
            &mut cli,
            &mut upstream,
            "direct",
            Duration::from_secs(1),
            None,
            None,
            None,
            traffic,
        )
        .await;
        Ok(())
    }

    async fn serve_tcp(&self) -> io::Result<()> {
        let listener = TcpListener::bind(self.listen).await?;
        tracing::info!(
            listen=%self.listen,
            dst=%format!("{}:{}", self.dst_host, self.dst_port),
            "direct inbound TCP listening"
        );
        loop {
            if self.shutdown.load(Ordering::Relaxed) {
                break;
            }
            match listener.accept().await {
                Ok((socket, peer)) => {
                    tracing::debug!(%peer, "direct inbound TCP: accepted");
                    let me = self.clone_for_spawn();
                    let active = self.active.clone();
                    let udp_count = self.udp_count.clone();
                    active.fetch_add(1, Ordering::Relaxed);
                    let sum = active.load(Ordering::Relaxed) + udp_count.load(Ordering::Relaxed);
                    crate::metrics::inbound::set_active_connections("direct", sum);
                    tokio::spawn(async move {
                        if let Err(e) = me.handle_tcp(socket).await {
                            tracing::debug!(error=%e, "direct inbound TCP: session error");
                        }
                        active.fetch_sub(1, Ordering::Relaxed);
                        let sum =
                            active.load(Ordering::Relaxed) + udp_count.load(Ordering::Relaxed);
                        crate::metrics::inbound::set_active_connections("direct", sum);
                    });
                }
                Err(e) => {
                    tracing::warn!(error=%e, "direct inbound TCP: accept error");
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            }
        }
        Ok(())
    }

    async fn serve_udp(&self) -> io::Result<()> {
        let socket = UdpSocket::bind(self.listen).await?;
        let socket = Arc::new(socket);
        tracing::info!(
            listen=%self.listen,
            dst=%format!("{}:{}", self.dst_host, self.dst_port),
            "direct inbound UDP listening"
        );

        let traffic = self
            .stats
            .as_ref()
            .and_then(|stats| stats.traffic_recorder(self.tag.as_deref(), Some("direct"), None));

        let mut buf = vec![0u8; 65536];
        let cleanup_interval = Duration::from_secs(30);
        let mut last_cleanup = Instant::now();

        loop {
            if self.shutdown.load(Ordering::Relaxed) {
                break;
            }

            // Periodic cleanup of expired sessions
            if last_cleanup.elapsed() >= cleanup_interval {
                self.cleanup_expired_udp_sessions().await;
                last_cleanup = Instant::now();
            }

            // Receive packet from client
            let (n, src_addr) =
                match timeout(Duration::from_secs(1), socket.recv_from(&mut buf)).await {
                    Ok(Ok(result)) => result,
                    Ok(Err(e)) => {
                        tracing::warn!(error=%e, "direct inbound UDP: recv error");
                        continue;
                    }
                    Err(_) => continue, // timeout, check shutdown flag
                };

            if let Some(ref recorder) = traffic {
                recorder.record_up(n as u64);
                recorder.record_up_packet(1);
            }

            let packet = &buf[..n];
            tracing::trace!(src=%src_addr, len=n, "direct inbound UDP: received packet");

            // Get or create session for this client
            let upstream_socket = self
                .get_or_create_udp_session(src_addr, socket.clone())
                .await?;

            // Forward packet to destination
            let dst_addr = format!("{}:{}", self.dst_host, self.dst_port);
            if let Err(e) = upstream_socket.send_to(packet, &dst_addr).await {
                tracing::debug!(error=%e, "direct inbound UDP: send to dst failed");
            }
        }
        Ok(())
    }

    async fn get_or_create_udp_session(
        &self,
        client_addr: SocketAddr,
        listen_socket: Arc<UdpSocket>,
    ) -> io::Result<Arc<UdpSocket>> {
        let mut sessions = self.udp_sessions.lock().await;

        // Check if session exists
        if let Some(session) = sessions.get_mut(&client_addr) {
            session.last_activity = Instant::now();
            return Ok(session.socket.clone());
        }

        // Create new session
        let upstream = UdpSocket::bind("0.0.0.0:0").await?;
        let upstream = Arc::new(upstream);

        // Spawn task to relay packets from upstream back to client
        let me = self.clone_for_spawn();
        let upstream_clone = upstream.clone();
        let traffic = self
            .stats
            .as_ref()
            .and_then(|stats| stats.traffic_recorder(self.tag.as_deref(), Some("direct"), None));
        tokio::spawn(async move {
            me.relay_udp_upstream_to_client(upstream_clone, client_addr, listen_socket, traffic)
                .await;
        });

        sessions.insert(
            client_addr,
            UdpSession {
                socket: upstream.clone(),
                last_activity: Instant::now(),
            },
        );
        self.udp_count.fetch_add(1, Ordering::Relaxed);
        let sum = self.active.load(Ordering::Relaxed) + self.udp_count.load(Ordering::Relaxed);
        crate::metrics::inbound::set_active_connections("direct", sum);

        tracing::debug!(client=%client_addr, "direct inbound UDP: created new session");
        Ok(upstream)
    }

    async fn relay_udp_upstream_to_client(
        &self,
        upstream: Arc<UdpSocket>,
        client_addr: SocketAddr,
        listen_socket: Arc<UdpSocket>,
        traffic: Option<Arc<dyn crate::net::metered::TrafficRecorder>>,
    ) {
        let mut buf = vec![0u8; 65536];
        loop {
            if self.shutdown.load(Ordering::Relaxed) {
                break;
            }

            match timeout(Duration::from_secs(1), upstream.recv_from(&mut buf)).await {
                Ok(Ok((n, _src))) => {
                    // Update session activity
                    {
                        let mut sessions = self.udp_sessions.lock().await;
                        if let Some(session) = sessions.get_mut(&client_addr) {
                            session.last_activity = Instant::now();
                        }
                    }

                    // Send packet back to client
                    if let Err(e) = listen_socket.send_to(&buf[..n], client_addr).await {
                        tracing::debug!(error=%e, "direct inbound UDP: send to client failed");
                        break;
                    }
                    if let Some(ref recorder) = traffic {
                        recorder.record_down(n as u64);
                        recorder.record_down_packet(1);
                    }
                }
                Ok(Err(e)) => {
                    tracing::debug!(error=%e, "direct inbound UDP: upstream recv error");
                    break;
                }
                Err(_) => {
                    // Timeout - check if session expired
                    let expired = {
                        let sessions = self.udp_sessions.lock().await;
                        if let Some(session) = sessions.get(&client_addr) {
                            session.last_activity.elapsed()
                                > Duration::from_secs(self.cfg.udp_timeout_sec)
                        } else {
                            true
                        }
                    };

                    if expired {
                        tracing::debug!(client=%client_addr, "direct inbound UDP: session expired");
                        break;
                    }
                }
            }
        }

        // Remove session
        let mut sessions = self.udp_sessions.lock().await;
        if sessions.remove(&client_addr).is_some() {
            self.udp_count.fetch_sub(1, Ordering::Relaxed);
            let sum = self.active.load(Ordering::Relaxed) + self.udp_count.load(Ordering::Relaxed);
            crate::metrics::inbound::set_active_connections("direct", sum);
        }
    }

    async fn cleanup_expired_udp_sessions(&self) {
        let timeout_duration = Duration::from_secs(self.cfg.udp_timeout_sec);
        let mut sessions = self.udp_sessions.lock().await;

        let expired: Vec<SocketAddr> = sessions
            .iter()
            .filter(|(_, session)| session.last_activity.elapsed() > timeout_duration)
            .map(|(addr, _)| *addr)
            .collect();

        let mut removed = 0u64;
        for addr in expired {
            if sessions.remove(&addr).is_some() {
                removed += 1;
            }
            tracing::debug!(client=%addr, "direct inbound UDP: cleaned up expired session");
        }
        if removed > 0 {
            self.udp_count.fetch_sub(removed, Ordering::Relaxed);
            let sum = self.active.load(Ordering::Relaxed) + self.udp_count.load(Ordering::Relaxed);
            crate::metrics::inbound::set_active_connections("direct", sum);
        }
    }

    async fn serve_async(&self) -> io::Result<()> {
        if self.udp_enabled {
            // Run both TCP and UDP servers concurrently
            let tcp_task = self.serve_tcp();
            let udp_task = self.serve_udp();

            tokio::select! {
                result = tcp_task => {
                    tracing::warn!("direct inbound TCP server exited: {:?}", result);
                    result
                }
                result = udp_task => {
                    tracing::warn!("direct inbound UDP server exited: {:?}", result);
                    result
                }
            }
        } else {
            // TCP only
            self.serve_tcp().await
        }
    }

    fn clone_for_spawn(&self) -> Self {
        Self {
            listen: self.listen,
            dst_host: self.dst_host.clone(),
            dst_port: self.dst_port,
            udp_enabled: self.udp_enabled,
            cfg: self.cfg.clone(),
            tag: self.tag.clone(),
            stats: self.stats.clone(),
            shutdown: self.shutdown.clone(),
            udp_sessions: self.udp_sessions.clone(),
            active: self.active.clone(),
            udp_count: self.udp_count.clone(),
        }
    }
}

impl InboundService for DirectForward {
    fn serve(&self) -> std::io::Result<()> {
        // Try current runtime or create one
        match tokio::runtime::Handle::try_current() {
            Ok(handle) => handle.block_on(self.serve_async()),
            Err(_) => {
                let rt = tokio::runtime::Runtime::new().map_err(io::Error::other)?;
                rt.block_on(self.serve_async())
            }
        }
    }

    fn request_shutdown(&self) {
        // Best-effort: set shutdown flag; accept loop will exit upon next accept
        self.shutdown.store(true, Ordering::Relaxed);
    }

    fn active_connections(&self) -> Option<u64> {
        Some(self.active.load(Ordering::Relaxed))
    }

    fn udp_sessions_estimate(&self) -> Option<u64> {
        Some(self.udp_count.load(Ordering::Relaxed))
    }
}
