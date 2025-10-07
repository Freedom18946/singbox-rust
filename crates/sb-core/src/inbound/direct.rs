//! Direct inbound: a simple TCP/UDP forwarder that listens on a local address
//! and forwards all connections to a fixed override destination.
//!
//! Fields are supplied via IR (listen, port, override_host, override_port, udp).
//! TCP and UDP are both supported; when `udp` is true, UDP packets are forwarded
//! using a session-based NAT model with automatic timeout cleanup.

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::Mutex;
use tokio::time::timeout;

use crate::adapter::InboundService;

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
    shutdown: Arc<AtomicBool>,
    udp_sessions: Arc<Mutex<HashMap<SocketAddr, UdpSession>>>,
}

impl DirectForward {
    pub fn new(listen: SocketAddr, dst_host: String, dst_port: u16, udp_enabled: bool) -> Self {
        Self {
            listen,
            dst_host,
            dst_port,
            udp_enabled,
            cfg: DirectConfig::default(),
            shutdown: Arc::new(AtomicBool::new(false)),
            udp_sessions: Arc::new(Mutex::new(HashMap::new())),
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

    async fn handle_tcp(&self, mut cli: TcpStream) -> io::Result<()> {
        // Establish upstream connection to fixed target
        let addr = format!("{}:{}", self.dst_host, self.dst_port);
        let mut upstream = timeout(
            Duration::from_millis(self.cfg.timeout_ms),
            TcpStream::connect(&addr),
        )
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "connect timeout"))??;

        // Bi-directional copy
        let _ = tokio::io::copy_bidirectional(&mut cli, &mut upstream).await;
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
                    tokio::spawn(async move {
                        if let Err(e) = me.handle_tcp(socket).await {
                            tracing::debug!(error=%e, "direct inbound TCP: session error");
                        }
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
            let (n, src_addr) = match timeout(Duration::from_secs(1), socket.recv_from(&mut buf))
                .await
            {
                Ok(Ok(result)) => result,
                Ok(Err(e)) => {
                    tracing::warn!(error=%e, "direct inbound UDP: recv error");
                    continue;
                }
                Err(_) => continue, // timeout, check shutdown flag
            };

            let packet = &buf[..n];
            tracing::trace!(src=%src_addr, len=n, "direct inbound UDP: received packet");

            // Get or create session for this client
            let upstream_socket = self.get_or_create_udp_session(src_addr, socket.clone()).await?;

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
        tokio::spawn(async move {
            me.relay_udp_upstream_to_client(upstream_clone, client_addr, listen_socket)
                .await;
        });

        sessions.insert(
            client_addr,
            UdpSession {
                socket: upstream.clone(),
                last_activity: Instant::now(),
            },
        );

        tracing::debug!(client=%client_addr, "direct inbound UDP: created new session");
        Ok(upstream)
    }

    async fn relay_udp_upstream_to_client(
        &self,
        upstream: Arc<UdpSocket>,
        client_addr: SocketAddr,
        listen_socket: Arc<UdpSocket>,
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
        sessions.remove(&client_addr);
    }

    async fn cleanup_expired_udp_sessions(&self) {
        let timeout_duration = Duration::from_secs(self.cfg.udp_timeout_sec);
        let mut sessions = self.udp_sessions.lock().await;

        let expired: Vec<SocketAddr> = sessions
            .iter()
            .filter(|(_, session)| session.last_activity.elapsed() > timeout_duration)
            .map(|(addr, _)| *addr)
            .collect();

        for addr in expired {
            sessions.remove(&addr);
            tracing::debug!(client=%addr, "direct inbound UDP: cleaned up expired session");
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
            shutdown: self.shutdown.clone(),
            udp_sessions: self.udp_sessions.clone(),
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
}
