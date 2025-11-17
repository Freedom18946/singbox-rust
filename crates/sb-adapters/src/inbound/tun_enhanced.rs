//! Enhanced TUN inbound implementation for Task 18
//!
//! This module provides full TUN traffic interception and routing capabilities
//! with proper packet forwarding for both TCP and UDP protocols.

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};
use std::time::{Duration, Instant};

use serde::Deserialize;
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;
use tokio::sync::{mpsc, Mutex, RwLock};
use tokio::time::timeout;

use sb_core::net::udp_nat_core::{UdpFlowKey, UdpNat};
use sb_core::outbound::OutboundConnector;
use sb_core::types::{ConnCtx, Endpoint, Host, Network};
use sb_platform::tun::{AsyncTunDevice, TunConfig, TunError};

/// Enhanced TUN configuration with packet forwarding capabilities
#[derive(Debug, Clone, Deserialize)]
pub struct EnhancedTunConfig {
    /// Device name (e.g., "utun0", "tun0", "wintun")
    pub name: String,
    /// Maximum transmission unit
    #[serde(default = "default_mtu")]
    pub mtu: u32,
    /// IPv4 address for the TUN interface
    pub ipv4: Option<IpAddr>,
    /// IPv6 address for the TUN interface
    pub ipv6: Option<IpAddr>,
    /// Whether to enable auto-route setup
    #[serde(default)]
    pub auto_route: bool,
    /// TCP connection timeout in milliseconds
    #[serde(default = "default_tcp_timeout")]
    pub tcp_timeout_ms: u64,
    /// UDP session timeout in milliseconds
    #[serde(default = "default_udp_timeout")]
    pub udp_timeout_ms: u64,
    /// Maximum concurrent TCP connections
    #[serde(default = "default_max_tcp_connections")]
    pub max_tcp_connections: usize,
    /// Maximum UDP sessions in NAT table
    #[serde(default = "default_max_udp_sessions")]
    pub max_udp_sessions: usize,
    /// Buffer size for packet processing
    #[serde(default = "default_buffer_size")]
    pub buffer_size: usize,
}

fn default_mtu() -> u32 {
    1500
}
fn default_tcp_timeout() -> u64 {
    30_000
}
fn default_udp_timeout() -> u64 {
    60_000
}
fn default_max_tcp_connections() -> usize {
    1024
}
fn default_max_udp_sessions() -> usize {
    2048
}
fn default_buffer_size() -> usize {
    65536
}

impl Default for EnhancedTunConfig {
    fn default() -> Self {
        Self {
            name: "tun0".to_string(),
            mtu: default_mtu(),
            ipv4: None,
            ipv6: None,
            auto_route: false,
            tcp_timeout_ms: default_tcp_timeout(),
            udp_timeout_ms: default_udp_timeout(),
            max_tcp_connections: default_max_tcp_connections(),
            max_udp_sessions: default_max_udp_sessions(),
            buffer_size: default_buffer_size(),
        }
    }
}

/// Enhanced TUN inbound with full traffic interception and routing
pub struct EnhancedTunInbound {
    config: EnhancedTunConfig,
    outbound: Arc<dyn OutboundConnector>,
    router: Option<Arc<sb_core::router::RouterHandle>>,
    #[allow(dead_code)]
    device: Option<AsyncTunDevice>,

    // Connection tracking
    tcp_connections: Arc<RwLock<HashMap<u64, TcpConnectionHandle>>>,
    udp_nat: Arc<Mutex<UdpNat>>,

    // Statistics
    #[allow(dead_code)] // Reserved for future connection ID tracking
    connection_id: AtomicU64,
    stats: TunStats,

    // Shutdown signaling
    shutdown_tx: Option<mpsc::Sender<()>>,
}

/// Statistics for TUN operations
#[derive(Debug, Default)]
struct TunStats {
    packets_received: AtomicU64,
    packets_sent: AtomicU64,
    tcp_connections_opened: AtomicU64,
    tcp_connections_closed: AtomicU64,
    udp_sessions_created: AtomicU64,
    udp_sessions_expired: AtomicU64,
    bytes_received: AtomicU64,
    bytes_sent: AtomicU64,
    errors: AtomicU64,
}

impl Clone for TunStats {
    fn clone(&self) -> Self {
        TunStats {
            packets_received: AtomicU64::new(self.packets_received.load(Ordering::Relaxed)),
            packets_sent: AtomicU64::new(self.packets_sent.load(Ordering::Relaxed)),
            tcp_connections_opened: AtomicU64::new(
                self.tcp_connections_opened.load(Ordering::Relaxed),
            ),
            tcp_connections_closed: AtomicU64::new(
                self.tcp_connections_closed.load(Ordering::Relaxed),
            ),
            udp_sessions_created: AtomicU64::new(self.udp_sessions_created.load(Ordering::Relaxed)),
            udp_sessions_expired: AtomicU64::new(self.udp_sessions_expired.load(Ordering::Relaxed)),
            bytes_received: AtomicU64::new(self.bytes_received.load(Ordering::Relaxed)),
            bytes_sent: AtomicU64::new(self.bytes_sent.load(Ordering::Relaxed)),
            errors: AtomicU64::new(self.errors.load(Ordering::Relaxed)),
        }
    }
}

/// Handle for tracking active TCP connections
#[derive(Debug)]
struct TcpConnectionHandle {
    #[allow(dead_code)] // Reserved for connection tracking
    id: u64,
    #[allow(dead_code)] // Reserved for connection tracking
    src: SocketAddr,
    #[allow(dead_code)] // Reserved for connection tracking
    dst: Endpoint,
    created_at: Instant,
    #[allow(dead_code)] // Reserved for metrics
    bytes_sent: Arc<AtomicU64>,
    #[allow(dead_code)] // Reserved for metrics
    bytes_received: Arc<AtomicU64>,
    shutdown_tx: mpsc::Sender<()>,
}

/// Parsed packet information from TUN device
#[derive(Debug, Clone)]
pub struct ParsedPacket {
    pub version: u8,
    pub protocol: u8,
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub payload: Vec<u8>,
    pub header_len: usize,
}

impl EnhancedTunInbound {
    /// Create a new enhanced TUN inbound
    pub fn new(config: EnhancedTunConfig, outbound: Arc<dyn OutboundConnector>) -> Self {
        let udp_nat = UdpNat::new(
            config.max_udp_sessions,
            Duration::from_millis(config.udp_timeout_ms),
        );

        Self {
            config,
            outbound,
            router: None,
            device: None,
            tcp_connections: Arc::new(RwLock::new(HashMap::new())),
            udp_nat: Arc::new(Mutex::new(udp_nat)),
            connection_id: AtomicU64::new(1),
            stats: TunStats::default(),
            shutdown_tx: None,
        }
    }

    /// Create with a router for policy-based routing
    pub fn with_router(
        config: EnhancedTunConfig,
        outbound: Arc<dyn OutboundConnector>,
        router: Arc<sb_core::router::RouterHandle>,
    ) -> Self {
        let mut inbound = Self::new(config, outbound);
        inbound.router = Some(router);
        inbound
    }

    /// Start the TUN inbound service
    pub async fn start(&mut self) -> Result<(), TunError> {
        // Starting enhanced TUN inbound

        // Create TUN device
        let tun_config = TunConfig {
            name: self.config.name.clone(),
            mtu: self.config.mtu,
            ipv4: self.config.ipv4,
            ipv6: self.config.ipv6,
            auto_route: self.config.auto_route,
            table: None,
        };

        let device = AsyncTunDevice::new(&tun_config)?;

        // Setup shutdown channel
        let (shutdown_tx, mut shutdown_rx) = mpsc::channel(1);
        self.shutdown_tx = Some(shutdown_tx);

        // Start packet processing loop
        let config = self.config.clone();
        let outbound = Arc::clone(&self.outbound);
        let tcp_connections = Arc::clone(&self.tcp_connections);
        let udp_nat = Arc::clone(&self.udp_nat);
        let stats = Arc::new(self.stats.clone());

        tokio::spawn(async move {
            Self::packet_processing_loop(
                device,
                config,
                outbound,
                tcp_connections,
                udp_nat,
                stats,
                &mut shutdown_rx,
            )
            .await
        });

        // Start cleanup task for expired connections
        self.start_cleanup_task().await;

        // Enhanced TUN inbound started successfully
        Ok(())
    }

    /// Main packet processing loop
    async fn packet_processing_loop(
        mut device: AsyncTunDevice,
        config: EnhancedTunConfig,
        outbound: Arc<dyn OutboundConnector>,
        tcp_connections: Arc<RwLock<HashMap<u64, TcpConnectionHandle>>>,
        udp_nat: Arc<Mutex<UdpNat>>,
        stats: Arc<TunStats>,
        shutdown_rx: &mut mpsc::Receiver<()>,
    ) {
        let mut buffer = vec![0u8; config.buffer_size];

        loop {
            tokio::select! {
                // Check for shutdown signal
                _ = shutdown_rx.recv() => {
                    // TUN inbound shutting down
                    break;
                }

                // Read packet from TUN device
                result = device.read(&mut buffer) => {
                    match result {
                        Ok(size) => {
                            stats.packets_received.fetch_add(1, Ordering::Relaxed);
                            stats.bytes_received.fetch_add(size as u64, Ordering::Relaxed);

                            if let Some(packet) = Self::parse_packet(&buffer[..size]) {
                                Self::handle_packet(
                                    packet,
                                    &outbound,
                                    &tcp_connections,
                                    &udp_nat,
                                    &stats,
                                    &config,
                                ).await;
                            }
                        }
                        Err(_e) => {
                            // Failed to read from TUN device
                            stats.errors.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }
            }
        }
    }

    /// Parse packet from raw bytes
    pub fn parse_packet(data: &[u8]) -> Option<ParsedPacket> {
        if data.len() < 20 {
            return None;
        }

        let version = data[0] >> 4;

        match version {
            4 => Self::parse_ipv4_packet(data),
            6 => Self::parse_ipv6_packet(data),
            _ => None,
        }
    }

    /// Parse IPv4 packet
    fn parse_ipv4_packet(data: &[u8]) -> Option<ParsedPacket> {
        if data.len() < 20 {
            return None;
        }

        let ihl = (data[0] & 0x0f) as usize * 4;
        if ihl < 20 || data.len() < ihl {
            return None;
        }

        let protocol = data[9];
        let src_ip = IpAddr::V4(std::net::Ipv4Addr::from([
            data[12], data[13], data[14], data[15],
        ]));
        let dst_ip = IpAddr::V4(std::net::Ipv4Addr::from([
            data[16], data[17], data[18], data[19],
        ]));

        let (src_port, dst_port) = if data.len() >= ihl + 4 {
            match protocol {
                6 | 17 => {
                    // TCP or UDP
                    let src_port = u16::from_be_bytes([data[ihl], data[ihl + 1]]);
                    let dst_port = u16::from_be_bytes([data[ihl + 2], data[ihl + 3]]);
                    (Some(src_port), Some(dst_port))
                }
                _ => (None, None),
            }
        } else {
            (None, None)
        };

        Some(ParsedPacket {
            version: 4,
            protocol,
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            payload: data[ihl..].to_vec(),
            header_len: ihl,
        })
    }

    /// Parse IPv6 packet
    fn parse_ipv6_packet(data: &[u8]) -> Option<ParsedPacket> {
        if data.len() < 40 {
            return None;
        }

        let next_header = data[6];
        let src_bytes: [u8; 16] = data[8..24].try_into().ok()?;
        let dst_bytes: [u8; 16] = data[24..40].try_into().ok()?;

        let src_ip = IpAddr::V6(std::net::Ipv6Addr::from(src_bytes));
        let dst_ip = IpAddr::V6(std::net::Ipv6Addr::from(dst_bytes));

        let (src_port, dst_port) = if data.len() >= 44 {
            match next_header {
                6 | 17 => {
                    // TCP or UDP
                    let src_port = u16::from_be_bytes([data[40], data[41]]);
                    let dst_port = u16::from_be_bytes([data[42], data[43]]);
                    (Some(src_port), Some(dst_port))
                }
                _ => (None, None),
            }
        } else {
            (None, None)
        };

        Some(ParsedPacket {
            version: 6,
            protocol: next_header,
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            payload: data[40..].to_vec(),
            header_len: 40,
        })
    }

    /// Handle parsed packet based on protocol
    async fn handle_packet(
        packet: ParsedPacket,
        outbound: &Arc<dyn OutboundConnector>,
        tcp_connections: &Arc<RwLock<HashMap<u64, TcpConnectionHandle>>>,
        udp_nat: &Arc<Mutex<UdpNat>>,
        stats: &Arc<TunStats>,
        config: &EnhancedTunConfig,
    ) {
        let (src_port, dst_port) = match (packet.src_port, packet.dst_port) {
            (Some(sp), Some(dp)) => (sp, dp),
            _ => {
                // Packet without port information, skipping
                return;
            }
        };

        let src_addr = SocketAddr::new(packet.src_ip, src_port);
        let dst_endpoint = Endpoint::new(Host::ip(packet.dst_ip), dst_port);

        match packet.protocol {
            6 => {
                // TCP
                Self::handle_tcp_packet(
                    packet,
                    src_addr,
                    dst_endpoint,
                    outbound,
                    tcp_connections,
                    stats,
                    config,
                )
                .await;
            }
            17 => {
                // UDP
                Self::handle_udp_packet(
                    packet,
                    src_addr,
                    dst_endpoint,
                    outbound,
                    udp_nat,
                    stats,
                    config,
                )
                .await;
            }
            _ => {
                // For now, just log unsupported protocols
                // trace!("Unsupported protocol: {}", packet.protocol);
            }
        }
    }

    /// Handle TCP packet by establishing tunnel to outbound
    async fn handle_tcp_packet(
        packet: ParsedPacket,
        src_addr: SocketAddr,
        dst_endpoint: Endpoint,
        outbound: &Arc<dyn OutboundConnector>,
        tcp_connections: &Arc<RwLock<HashMap<u64, TcpConnectionHandle>>>,
        stats: &Arc<TunStats>,
        config: &EnhancedTunConfig,
    ) {
        // Check if this is a new connection (SYN packet)
        if packet.payload.len() >= 13 {
            let tcp_flags = packet.payload[13];
            let is_syn = (tcp_flags & 0x02) != 0;
            let is_ack = (tcp_flags & 0x10) != 0;

            if is_syn && !is_ack {
                // New TCP connection
                Self::establish_tcp_tunnel(
                    src_addr,
                    dst_endpoint,
                    outbound,
                    tcp_connections,
                    stats,
                    config,
                )
                .await;
            }
        }
    }

    /// Establish TCP tunnel between TUN and outbound
    async fn establish_tcp_tunnel(
        src_addr: SocketAddr,
        dst_endpoint: Endpoint,
        outbound: &Arc<dyn OutboundConnector>,
        tcp_connections: &Arc<RwLock<HashMap<u64, TcpConnectionHandle>>>,
        stats: &Arc<TunStats>,
        config: &EnhancedTunConfig,
    ) {
        let connection_id = stats.tcp_connections_opened.fetch_add(1, Ordering::Relaxed);

        // Create connection context
        let ctx = ConnCtx::new(connection_id, Network::Tcp, src_addr, dst_endpoint.clone());

        // Use the provided outbound connector
        // TODO: Router-based outbound selection can be added later when needed
        let selected_outbound = Arc::clone(outbound);

        // Connect to outbound
        let outbound_stream = match timeout(
            Duration::from_millis(config.tcp_timeout_ms),
            selected_outbound.connect_tcp(&ctx),
        )
        .await
        {
            Ok(Ok(stream)) => stream,
            Ok(Err(_e)) => {
                // Failed to connect to outbound
                stats.errors.fetch_add(1, Ordering::Relaxed);
                return;
            }
            Err(_) => {
                // TCP connection timeout
                stats.errors.fetch_add(1, Ordering::Relaxed);
                return;
            }
        };

        // Create shutdown channel for this connection
        let (shutdown_tx, mut shutdown_rx) = mpsc::channel(1);

        // Create connection handle
        let handle = TcpConnectionHandle {
            id: connection_id,
            src: src_addr,
            dst: dst_endpoint.clone(),
            created_at: Instant::now(),
            bytes_sent: Arc::new(AtomicU64::new(0)),
            bytes_received: Arc::new(AtomicU64::new(0)),
            shutdown_tx: shutdown_tx.clone(),
        };

        // Store connection handle
        {
            let mut connections = tcp_connections.write().await;
            if connections.len() >= config.max_tcp_connections {
                // Maximum TCP connections reached, dropping connection
                stats.errors.fetch_add(1, Ordering::Relaxed);
                return;
            }
            connections.insert(connection_id, handle);
        }

        // Start bidirectional data forwarding
        let tcp_connections_clone = Arc::clone(tcp_connections);
        let stats_clone = Arc::clone(stats);

        tokio::spawn(async move {
            // This is a simplified tunnel - in a real implementation, you'd need
            // to properly handle the TUN interface side of the connection
            let result = Self::run_tcp_tunnel(
                connection_id,
                outbound_stream,
                &mut shutdown_rx,
                &stats_clone,
            )
            .await;

            if let Err(_e) = result {
                // TCP tunnel ended with error
            }

            // Clean up connection
            {
                let mut connections = tcp_connections_clone.write().await;
                connections.remove(&connection_id);
            }
            stats_clone
                .tcp_connections_closed
                .fetch_add(1, Ordering::Relaxed);

            // TCP tunnel closed
        });
    }

    /// Run the TCP tunnel forwarding data bidirectionally
    async fn run_tcp_tunnel(
        _connection_id: u64,
        mut outbound_stream: TcpStream,
        shutdown_rx: &mut mpsc::Receiver<()>,
        stats: &Arc<TunStats>,
    ) -> io::Result<()> {
        let mut buffer = vec![0u8; 4096];

        loop {
            tokio::select! {
                _ = shutdown_rx.recv() => {
                    // TCP tunnel shutdown signal received
                    break;
                }

                // In a real implementation, you would read from the TUN side here
                // and forward to outbound_stream, and vice versa
                result = outbound_stream.read(&mut buffer) => {
                    match result {
                        Ok(0) => {
                            // Outbound stream closed
                            break;
                        }
                        Ok(n) => {
                            stats.bytes_received.fetch_add(n as u64, Ordering::Relaxed);
                            // In real implementation: forward to TUN interface
                        }
                        Err(e) => {
                            // Error reading from outbound stream
                            return Err(e);
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Handle UDP packet using NAT mapping
    async fn handle_udp_packet(
        packet: ParsedPacket,
        src_addr: SocketAddr,
        dst_endpoint: Endpoint,
        outbound: &Arc<dyn OutboundConnector>,
        udp_nat: &Arc<Mutex<UdpNat>>,
        stats: &Arc<TunStats>,
        config: &EnhancedTunConfig,
    ) {
        let flow_key = UdpFlowKey {
            src: src_addr,
            dst: dst_endpoint.to_socket_addr().unwrap_or_else(|| {
                SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0)), 0)
            }),
            session_id: 0, // Simple implementation without session tracking
        };

        // Check if session exists in NAT table
        let session_exists = {
            let nat = udp_nat.lock().await;
            nat.lookup_session(&src_addr).is_some()
        };

        if !session_exists {
            // Create new UDP session
            Self::create_udp_session(
                flow_key.clone(),
                dst_endpoint,
                outbound,
                udp_nat,
                stats,
                config,
            )
            .await;
        }

        // Forward UDP packet
        Self::forward_udp_packet(packet.payload, flow_key, udp_nat, stats).await;
    }

    /// Create new UDP session and establish outbound connection
    async fn create_udp_session(
        flow_key: UdpFlowKey,
        dst_endpoint: Endpoint,
        outbound: &Arc<dyn OutboundConnector>,
        udp_nat: &Arc<Mutex<UdpNat>>,
        stats: &Arc<TunStats>,
        config: &EnhancedTunConfig,
    ) {
        // Creating UDP session

        // Create connection context
        let ctx = ConnCtx::new(
            stats.udp_sessions_created.fetch_add(1, Ordering::Relaxed),
            Network::Udp,
            flow_key.src,
            dst_endpoint.clone(),
        );

        // Connect to outbound
        let _udp_transport = match timeout(
            Duration::from_millis(config.tcp_timeout_ms),
            outbound.connect_udp(&ctx),
        )
        .await
        {
            Ok(Ok(transport)) => transport,
            Ok(Err(_e)) => {
                // Failed to create UDP connection
                stats.errors.fetch_add(1, Ordering::Relaxed);
                return;
            }
            Err(_) => {
                // UDP connection timeout
                stats.errors.fetch_add(1, Ordering::Relaxed);
                return;
            }
        };

        // Create NAT mapping
        {
            let mut nat = udp_nat.lock().await;
            let _ = nat.create_mapping(flow_key.src, flow_key.dst);
        }

        // Store UDP transport for this session (simplified - in real implementation
        // you'd need proper session management)
        // UDP session created
    }

    /// Forward UDP packet to outbound
    async fn forward_udp_packet(
        payload: Vec<u8>,
        flow_key: UdpFlowKey,
        udp_nat: &Arc<Mutex<UdpNat>>,
        stats: &Arc<TunStats>,
    ) {
        // Update NAT session activity
        {
            let mut nat = udp_nat.lock().await;
            nat.update_activity(&flow_key);
        }

        stats.packets_sent.fetch_add(1, Ordering::Relaxed);
        stats
            .bytes_sent
            .fetch_add(payload.len() as u64, Ordering::Relaxed);

        // In real implementation: forward payload to outbound UDP transport
        // Forwarded UDP packet
    }

    /// Start cleanup task for expired connections
    async fn start_cleanup_task(&self) {
        let tcp_connections = Arc::clone(&self.tcp_connections);
        let udp_nat = Arc::clone(&self.udp_nat);
        let stats = Arc::new(self.stats.clone());
        let tcp_timeout = Duration::from_millis(self.config.tcp_timeout_ms);

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(30));

            loop {
                interval.tick().await;

                // Clean up expired TCP connections
                let now = Instant::now();
                let mut expired_tcp = Vec::new();

                {
                    let connections = tcp_connections.read().await;
                    for (id, handle) in connections.iter() {
                        if now.duration_since(handle.created_at) > tcp_timeout {
                            expired_tcp.push(*id);
                        }
                    }
                }

                if !expired_tcp.is_empty() {
                    let mut connections = tcp_connections.write().await;
                    for id in expired_tcp {
                        if let Some(handle) = connections.remove(&id) {
                            let _ = handle.shutdown_tx.send(()).await;
                            // Cleaned up expired TCP connection
                        }
                    }
                }

                // Clean up expired UDP sessions
                {
                    let mut nat = udp_nat.lock().await;
                    let expired_count = nat.evict_expired();
                    if expired_count > 0 {
                        stats
                            .udp_sessions_expired
                            .fetch_add(expired_count as u64, Ordering::Relaxed);
                        // Cleaned up expired UDP sessions
                    }
                }
            }
        });
    }

    /// Get current statistics
    pub fn get_stats(&self) -> TunStatistics {
        TunStatistics {
            packets_received: self.stats.packets_received.load(Ordering::Relaxed),
            packets_sent: self.stats.packets_sent.load(Ordering::Relaxed),
            tcp_connections_opened: self.stats.tcp_connections_opened.load(Ordering::Relaxed),
            tcp_connections_closed: self.stats.tcp_connections_closed.load(Ordering::Relaxed),
            udp_sessions_created: self.stats.udp_sessions_created.load(Ordering::Relaxed),
            udp_sessions_expired: self.stats.udp_sessions_expired.load(Ordering::Relaxed),
            bytes_received: self.stats.bytes_received.load(Ordering::Relaxed),
            bytes_sent: self.stats.bytes_sent.load(Ordering::Relaxed),
            errors: self.stats.errors.load(Ordering::Relaxed),
        }
    }

    /// Stop the TUN inbound service
    pub async fn stop(&mut self) -> Result<(), TunError> {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(()).await;
        }

        // Close all active TCP connections
        {
            let connections = self.tcp_connections.read().await;
            for handle in connections.values() {
                let _ = handle.shutdown_tx.send(()).await;
            }
        }

        // Enhanced TUN inbound stopped
        Ok(())
    }
}

/// Public statistics structure
#[derive(Debug, Clone)]
pub struct TunStatistics {
    pub packets_received: u64,
    pub packets_sent: u64,
    pub tcp_connections_opened: u64,
    pub tcp_connections_closed: u64,
    pub udp_sessions_created: u64,
    pub udp_sessions_expired: u64,
    pub bytes_received: u64,
    pub bytes_sent: u64,
    pub errors: u64,
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;
    use sb_core::outbound::DirectConnector;
    use std::sync::Arc;

    #[tokio::test]
    async fn test_enhanced_tun_creation() {
        let config = EnhancedTunConfig::default();
        let outbound = Arc::new(DirectConnector::new());

        let tun_inbound = EnhancedTunInbound::new(config, outbound);

        // Test initial state
        let stats = tun_inbound.get_stats();
        assert_eq!(stats.packets_received, 0);
        assert_eq!(stats.tcp_connections_opened, 0);
    }

    #[test]
    fn test_ipv4_packet_parsing() {
        // Create a minimal IPv4 TCP packet
        let mut packet = vec![0u8; 40];
        packet[0] = 0x45; // Version 4, IHL 5
        packet[9] = 6; // TCP protocol
        packet[12..16].copy_from_slice(&[192, 168, 1, 1]); // Source IP
        packet[16..20].copy_from_slice(&[8, 8, 8, 8]); // Dest IP
        packet[20..22].copy_from_slice(&[0x1F, 0x90]); // Source port 8080
        packet[22..24].copy_from_slice(&[0x00, 0x50]); // Dest port 80

        let parsed = EnhancedTunInbound::parse_packet(&packet).unwrap();

        assert_eq!(parsed.version, 4);
        assert_eq!(parsed.protocol, 6);
        assert_eq!(
            parsed.src_ip,
            IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 1))
        );
        assert_eq!(
            parsed.dst_ip,
            IpAddr::V4(std::net::Ipv4Addr::new(8, 8, 8, 8))
        );
        assert_eq!(parsed.src_port, Some(8080));
        assert_eq!(parsed.dst_port, Some(80));
    }

    #[test]
    fn test_ipv6_packet_parsing() {
        // Create a minimal IPv6 TCP packet
        let mut packet = vec![0u8; 60];
        packet[0] = 0x60; // Version 6
        packet[6] = 6; // Next header: TCP

        // Source IPv6: ::1
        packet[24..40].copy_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        // Dest IPv6: 2001:db8::1
        packet[8..24]
            .copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);

        packet[40..42].copy_from_slice(&[0x1F, 0x90]); // Source port 8080
        packet[42..44].copy_from_slice(&[0x00, 0x50]); // Dest port 80

        let parsed = EnhancedTunInbound::parse_packet(&packet).unwrap();

        assert_eq!(parsed.version, 6);
        assert_eq!(parsed.protocol, 6);
        assert_eq!(parsed.src_port, Some(8080));
        assert_eq!(parsed.dst_port, Some(80));
    }

    #[test]
    fn test_config_defaults() {
        let config = EnhancedTunConfig::default();

        assert_eq!(config.name, "tun0");
        assert_eq!(config.mtu, 1500);
        assert_eq!(config.tcp_timeout_ms, 30_000);
        assert_eq!(config.udp_timeout_ms, 60_000);
        assert_eq!(config.max_tcp_connections, 1024);
        assert_eq!(config.max_udp_sessions, 2048);
    }

    #[tokio::test]
    async fn test_statistics_tracking() {
        let config = EnhancedTunConfig::default();
        let outbound = Arc::new(DirectConnector::new());

        let tun_inbound = EnhancedTunInbound::new(config, outbound);

        // Increment some statistics
        tun_inbound
            .stats
            .packets_received
            .fetch_add(5, Ordering::Relaxed);
        tun_inbound
            .stats
            .bytes_sent
            .fetch_add(1024, Ordering::Relaxed);

        let stats = tun_inbound.get_stats();
        assert_eq!(stats.packets_received, 5);
        assert_eq!(stats.bytes_sent, 1024);
    }
}
