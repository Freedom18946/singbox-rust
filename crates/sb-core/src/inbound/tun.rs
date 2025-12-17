//! TUN inbound service
//!
//! Provides TUN (network TUNnel) interface capabilities for transparent proxying.
//! This implementation handles incoming packets from the TUN device and routes them
//! through the appropriate outbound connections.
//!
//! ## Architecture
//!
//! 1. **Packet Ingress**: Raw IP packets are read from the TUN device
//! 2. **Session Tracking**: TCP/UDP flows are tracked by 5-tuple (proto, src_ip, src_port, dst_ip, dst_port)
//! 3. **Routing Decision**: Each new flow is routed through the engine to select an outbound
//! 4. **Outbound Dispatch**: Packets are forwarded to the selected outbound
//! 5. **Response Path**: Responses from outbounds are written back to the TUN device

use crate::adapter::InboundService;
use sb_platform::tun::{AsyncTunDevice, TunConfig as PlatformTunConfig};
use smoltcp::iface::{Config, Interface, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::time::Instant;
use smoltcp::wire::{HardwareAddress, IpCidr, Ipv4Address};
use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;
use tracing::{debug, error, info, trace, warn};

/// Protocol constants
const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;
const IPPROTO_ICMP: u8 = 1;
const IPPROTO_ICMPV6: u8 = 58;

/// TUN interface configuration
#[derive(Debug, Clone)]
pub struct TunConfig {
    /// Device name (platform specific)
    pub name: String,
    /// Maximum transmission unit
    pub mtu: u32,
    /// Interface IPv4 address
    pub ipv4: Option<std::net::Ipv4Addr>,
    /// Interface IPv6 address
    pub ipv6: Option<std::net::Ipv6Addr>,
    /// Enable auto-route configuration
    pub auto_route: bool,
    /// Stack type (system, gvisor, mixed)
    pub stack: String,
    /// Session timeout in seconds
    pub session_timeout: u64,
    /// Maximum concurrent sessions
    pub max_sessions: usize,
    /// Enable strict routing (drop packets without matching route)
    pub strict_route: bool,
    /// Excluded routes (CIDRs to bypass TUN)
    pub exclude_routes: Vec<String>,
    /// Included routes (CIDRs to capture)
    pub include_routes: Vec<String>,
}

impl Default for TunConfig {
    fn default() -> Self {
        Self {
            name: "tun-sb".to_string(),
            mtu: 1500,
            ipv4: Some(std::net::Ipv4Addr::new(172, 19, 0, 1)),
            ipv6: None,
            auto_route: false,
            stack: "system".to_string(),
            session_timeout: 300,
            max_sessions: 65536,
            strict_route: false,
            exclude_routes: Vec::new(),
            include_routes: Vec::new(),
        }
    }
}

/// 5-tuple flow key for session tracking
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FlowKey {
    /// Protocol (TCP=6, UDP=17)
    pub protocol: u8,
    /// Source address
    pub src: SocketAddr,
    /// Destination address
    pub dst: SocketAddr,
}

impl FlowKey {
    /// Create reverse flow key for response matching
    pub fn reverse(&self) -> Self {
        Self {
            protocol: self.protocol,
            src: self.dst,
            dst: self.src,
        }
    }
}

impl std::fmt::Display for FlowKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let proto = match self.protocol {
            IPPROTO_TCP => "TCP",
            IPPROTO_UDP => "UDP",
            _ => "???",
        };
        write!(f, "{}:{}<->{}", proto, self.src, self.dst)
    }
}

/// TUN session representing a tracked flow
#[derive(Debug)]
pub struct TunSession {
    /// Flow key
    pub key: FlowKey,
    /// Selected outbound tag
    pub outbound: String,
    /// Creation timestamp
    pub created_at: std::time::Instant,
    /// Last activity timestamp
    pub last_activity: std::time::Instant,
    /// Bytes sent
    pub bytes_tx: AtomicU64,
    /// Bytes received
    pub bytes_rx: AtomicU64,
    /// SNI (if detected via sniffing)
    pub sni: Option<String>,
}

impl TunSession {
    pub fn new(key: FlowKey, outbound: String) -> Self {
        let now = std::time::Instant::now();
        Self {
            key,
            outbound,
            created_at: now,
            last_activity: now,
            bytes_tx: AtomicU64::new(0),
            bytes_rx: AtomicU64::new(0),
            sni: None,
        }
    }

    /// Check if session has expired
    pub fn is_expired(&self, timeout: Duration) -> bool {
        self.last_activity.elapsed() > timeout
    }

    /// Update last activity and bytes
    pub fn touch(&mut self, bytes: u64, is_tx: bool) {
        self.last_activity = std::time::Instant::now();
        if is_tx {
            self.bytes_tx.fetch_add(bytes, Ordering::Relaxed);
        } else {
            self.bytes_rx.fetch_add(bytes, Ordering::Relaxed);
        }
    }
}

/// Session table for tracking active flows
pub struct SessionTable {
    sessions: RwLock<HashMap<FlowKey, Arc<RwLock<TunSession>>>>,
    max_sessions: usize,
    timeout: Duration,
}

impl SessionTable {
    pub fn new(max_sessions: usize, timeout_secs: u64) -> Self {
        Self {
            sessions: RwLock::new(HashMap::new()),
            max_sessions,
            timeout: Duration::from_secs(timeout_secs),
        }
    }

    /// Get or create a session for the given flow
    pub fn get_or_create<F>(&self, key: FlowKey, create_fn: F) -> Option<Arc<RwLock<TunSession>>>
    where
        F: FnOnce(&FlowKey) -> Option<TunSession>,
    {
        // Try read-only lookup first
        {
            let sessions = self.sessions.read().unwrap();
            if let Some(session) = sessions.get(&key) {
                return Some(session.clone());
            }
        }

        // Need to create - acquire write lock
        let mut sessions = self.sessions.write().unwrap();

        // Double-check after acquiring write lock
        if let Some(session) = sessions.get(&key) {
            return Some(session.clone());
        }

        // Check capacity
        if sessions.len() >= self.max_sessions {
            // Evict expired sessions
            sessions.retain(|_, v| !v.read().unwrap().is_expired(self.timeout));

            if sessions.len() >= self.max_sessions {
                warn!("TUN session table full ({} sessions)", self.max_sessions);
                return None;
            }
        }

        // Create new session
        if let Some(session) = create_fn(&key) {
            let arc = Arc::new(RwLock::new(session));
            sessions.insert(key, arc.clone());
            Some(arc)
        } else {
            None
        }
    }

    /// Get existing session
    pub fn get(&self, key: &FlowKey) -> Option<Arc<RwLock<TunSession>>> {
        self.sessions.read().unwrap().get(key).cloned()
    }

    /// Remove a session
    pub fn remove(&self, key: &FlowKey) -> Option<Arc<RwLock<TunSession>>> {
        self.sessions.write().unwrap().remove(key)
    }

    /// Get session count
    pub fn len(&self) -> usize {
        self.sessions.read().unwrap().len()
    }

    /// Check if session table is empty
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Clean up expired sessions
    pub fn cleanup_expired(&self) -> usize {
        let mut sessions = self.sessions.write().unwrap();
        let before = sessions.len();
        sessions.retain(|_, v| !v.read().unwrap().is_expired(self.timeout));
        before - sessions.len()
    }
}

/// Parsed IP packet information
#[derive(Debug)]
pub struct ParsedPacket {
    /// IP version (4 or 6)
    pub version: u8,
    /// Protocol (TCP, UDP, ICMP, etc.)
    pub protocol: u8,
    /// Source IP
    pub src_ip: IpAddr,
    /// Destination IP
    pub dst_ip: IpAddr,
    /// Source port (for TCP/UDP)
    pub src_port: Option<u16>,
    /// Destination port (for TCP/UDP)
    pub dst_port: Option<u16>,
    /// Payload offset in original packet
    pub payload_offset: usize,
    /// Payload length
    pub payload_len: usize,
}

impl ParsedPacket {
    /// Get flow key if this is a TCP or UDP packet
    pub fn flow_key(&self) -> Option<FlowKey> {
        match self.protocol {
            IPPROTO_TCP | IPPROTO_UDP => {
                let src_port = self.src_port?;
                let dst_port = self.dst_port?;
                Some(FlowKey {
                    protocol: self.protocol,
                    src: SocketAddr::new(self.src_ip, src_port),
                    dst: SocketAddr::new(self.dst_ip, dst_port),
                })
            }
            _ => None,
        }
    }
}

/// Parse an IP packet to extract header information
pub fn parse_ip_packet(packet: &[u8]) -> Option<ParsedPacket> {
    if packet.is_empty() {
        return None;
    }

    let version = (packet[0] >> 4) & 0x0F;

    match version {
        4 => parse_ipv4_packet(packet),
        6 => parse_ipv6_packet(packet),
        _ => {
            trace!("Unknown IP version: {}", version);
            None
        }
    }
}

fn parse_ipv4_packet(packet: &[u8]) -> Option<ParsedPacket> {
    if packet.len() < 20 {
        return None;
    }

    let ihl = (packet[0] & 0x0F) as usize;
    let header_len = ihl * 4;
    if packet.len() < header_len {
        return None;
    }

    let protocol = packet[9];
    let src_ip = IpAddr::V4(Ipv4Addr::new(
        packet[12], packet[13], packet[14], packet[15],
    ));
    let dst_ip = IpAddr::V4(Ipv4Addr::new(
        packet[16], packet[17], packet[18], packet[19],
    ));

    let (src_port, dst_port, payload_offset) = match protocol {
        IPPROTO_TCP | IPPROTO_UDP if packet.len() >= header_len + 4 => {
            let sp = u16::from_be_bytes([packet[header_len], packet[header_len + 1]]);
            let dp = u16::from_be_bytes([packet[header_len + 2], packet[header_len + 3]]);
            let transport_header_len = if protocol == IPPROTO_TCP && packet.len() >= header_len + 13
            {
                ((packet[header_len + 12] >> 4) as usize) * 4
            } else {
                8 // UDP header is fixed 8 bytes
            };
            (Some(sp), Some(dp), header_len + transport_header_len)
        }
        _ => (None, None, header_len),
    };

    Some(ParsedPacket {
        version: 4,
        protocol,
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        payload_offset,
        payload_len: packet.len().saturating_sub(payload_offset),
    })
}

fn parse_ipv6_packet(packet: &[u8]) -> Option<ParsedPacket> {
    if packet.len() < 40 {
        return None;
    }

    let protocol = packet[6]; // Next Header (simplified - doesn't handle extension headers)

    let mut src_bytes = [0u8; 16];
    let mut dst_bytes = [0u8; 16];
    src_bytes.copy_from_slice(&packet[8..24]);
    dst_bytes.copy_from_slice(&packet[24..40]);

    let src_ip = IpAddr::V6(Ipv6Addr::from(src_bytes));
    let dst_ip = IpAddr::V6(Ipv6Addr::from(dst_bytes));

    let header_len = 40; // Fixed IPv6 header (not handling extension headers)

    let (src_port, dst_port, payload_offset) = match protocol {
        IPPROTO_TCP | IPPROTO_UDP if packet.len() >= header_len + 4 => {
            let sp = u16::from_be_bytes([packet[header_len], packet[header_len + 1]]);
            let dp = u16::from_be_bytes([packet[header_len + 2], packet[header_len + 3]]);
            let transport_header_len = if protocol == IPPROTO_TCP && packet.len() >= header_len + 13
            {
                ((packet[header_len + 12] >> 4) as usize) * 4
            } else {
                8
            };
            (Some(sp), Some(dp), header_len + transport_header_len)
        }
        _ => (None, None, header_len),
    };

    Some(ParsedPacket {
        version: 6,
        protocol,
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        payload_offset,
        payload_len: packet.len().saturating_sub(payload_offset),
    })
}

/// TUN interface inbound service
pub struct TunInboundService {
    config: TunConfig,
    shutdown: Arc<AtomicBool>,
    sniff_enabled: bool,
    sessions: Arc<SessionTable>,
}

impl std::fmt::Debug for TunInboundService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TunInboundService")
            .field("config", &self.config)
            .field("sniff_enabled", &self.sniff_enabled)
            .field("active_sessions", &self.sessions.len())
            .finish()
    }
}

impl Default for TunInboundService {
    fn default() -> Self {
        Self::new()
    }
}

impl TunInboundService {
    /// Create new TUN inbound service with default configuration
    pub fn new() -> Self {
        Self::with_config(TunConfig::default())
    }

    /// Create new TUN inbound service with custom configuration
    pub fn with_config(config: TunConfig) -> Self {
        let sessions = Arc::new(SessionTable::new(
            config.max_sessions,
            config.session_timeout,
        ));
        Self {
            config,
            shutdown: Arc::new(AtomicBool::new(false)),
            sniff_enabled: false,
            sessions,
        }
    }

    /// Get TUN configuration
    pub fn config(&self) -> &TunConfig {
        &self.config
    }

    /// Get session table reference
    pub fn sessions(&self) -> &Arc<SessionTable> {
        &self.sessions
    }

    /// Request graceful shutdown
    pub fn shutdown(&self) {
        self.shutdown.store(true, Ordering::Relaxed);
    }

    /// Enable/disable inbound sniff features (TLS SNI, QUIC ALPN, etc.)
    pub fn with_sniff(mut self, enabled: bool) -> Self {
        self.sniff_enabled = enabled;
        self
    }

    /// Check if shutdown has been requested
    pub fn is_shutdown(&self) -> bool {
        self.shutdown.load(Ordering::Relaxed)
    }

    /// Route a packet and get outbound selection
    fn route_packet(&self, parsed: &ParsedPacket) -> String {
        // Default routing: "direct" for everything
        // TODO: Integrate with Engine for actual routing decisions
        // In full implementation, this would call:
        //   engine.decide(&Input { host: &dst_ip.to_string(), port: dst_port, ... })

        let dst = parsed.dst_ip.to_string();

        // Simple rule: loopback goes to "direct"
        if parsed.dst_ip.is_loopback() {
            return "direct".to_string();
        }

        // Private ranges to bypass (simple check)
        match parsed.dst_ip {
            IpAddr::V4(ip) if ip.is_private() => {
                debug!("TUN: private IP {} -> direct", dst);
                return "direct".to_string();
            }
            _ => {}
        }

        // Use environment variable for default outbound
        std::env::var("SB_TUN_DEFAULT_OUTBOUND").unwrap_or_else(|_| "proxy".to_string())
    }

    /// Handle an incoming packet
    async fn handle_packet(&self, packet: &[u8]) -> io::Result<Option<Vec<u8>>> {
        let parsed = match parse_ip_packet(packet) {
            Some(p) => p,
            None => {
                trace!("TUN: failed to parse packet ({} bytes)", packet.len());
                return Ok(None);
            }
        };

        // Only track TCP/UDP flows
        let flow_key = match parsed.flow_key() {
            Some(k) => k,
            None => {
                // Pass through ICMP and other protocols without session tracking
                if parsed.protocol == IPPROTO_ICMP || parsed.protocol == IPPROTO_ICMPV6 {
                    trace!("TUN: ICMP packet {} -> {}", parsed.src_ip, parsed.dst_ip);
                }
                return Ok(None);
            }
        };

        // Get or create session
        let session = self.sessions.get_or_create(flow_key, |key| {
            let outbound = self.route_packet(&parsed);
            debug!("TUN: new session {} -> outbound={}", key, outbound);
            Some(TunSession::new(*key, outbound))
        });

        match session {
            Some(sess) => {
                let mut s = sess.write().unwrap();
                s.touch(packet.len() as u64, true);
                trace!(
                    "TUN: packet {} ({} bytes) via {}",
                    s.key,
                    packet.len(),
                    s.outbound
                );
                // TODO: Actually forward to outbound
                // In full implementation:
                //   outbound_registry.get(&s.outbound).send(packet).await
            }
            None => {
                warn!("TUN: failed to create session for {}", flow_key);
            }
        }

        Ok(None)
    }

    /// Main packet processing loop using smoltcp
    async fn process_packets(&self) -> io::Result<()> {
        let platform_config = PlatformTunConfig {
            name: self.config.name.clone(),
            mtu: self.config.mtu,
            ipv4: self.config.ipv4.map(Into::into),
            ipv6: self.config.ipv6.map(Into::into),
            auto_route: self.config.auto_route,
            table: None,
        };

        let mut device = AsyncTunDevice::new(&platform_config).map_err(io::Error::other)?;
        info!(
            "TUN device {} initialized (mtu={}, ipv4={:?})",
            device.name(),
            device.mtu(),
            self.config.ipv4
        );

        // Initialize smoltcp interface
        let mut config = Config::new(HardwareAddress::Ip);
        config.random_seed = rand::random();

        let mut iface = Interface::new(config, &mut TunPhy::new(device.mtu()), Instant::now());
        iface.update_ip_addrs(|ip_addrs| {
            if let Some(ipv4) = self.config.ipv4 {
                let _ = ip_addrs.push(IpCidr::new(
                    smoltcp::wire::IpAddress::Ipv4(Ipv4Address::from_bytes(&ipv4.octets())),
                    24,
                ));
            }
        });

        let mut sockets = SocketSet::new(vec![]);
        let mut buf = vec![0u8; self.config.mtu as usize];

        // Session cleanup ticker
        let mut cleanup_counter = 0u64;

        loop {
            if self.is_shutdown() {
                info!("TUN service shutdown requested");
                break;
            }

            // Read packet from TUN
            match device.read(&mut buf) {
                Ok(len) => {
                    if len == 0 {
                        continue;
                    }
                    let packet = &buf[..len];

                    // Handle packet through session system
                    if let Err(e) = self.handle_packet(packet).await {
                        warn!("TUN: packet handling error: {}", e);
                    }

                    // Also feed to smoltcp for stack-level processing
                    let timestamp = Instant::now();
                    let mut phy = TunPhy::new(device.mtu());
                    phy.rx_buf = Some(packet.to_vec());

                    iface.poll(timestamp, &mut phy, &mut sockets);

                    // Write any response packets
                    if let Some(tx_packet) = phy.tx_buf {
                        if let Err(e) = device.write(&tx_packet) {
                            warn!("Failed to write to TUN: {}", e);
                        }
                    }
                }
                Err(e) => {
                    error!("Failed to read from TUN: {}", e);
                    break;
                }
            }

            // Periodic session cleanup
            cleanup_counter += 1;
            #[allow(clippy::manual_is_multiple_of)]
            if cleanup_counter % 10000 == 0 {
                let evicted = self.sessions.cleanup_expired();
                if evicted > 0 {
                    debug!("TUN: evicted {} expired sessions", evicted);
                }
            }
        }

        let _ = device.close();
        info!(
            "TUN service stopped ({} sessions remaining)",
            self.sessions.len()
        );
        Ok(())
    }
}

/// A simple PHY device for smoltcp that buffers a single packet
struct TunPhy {
    mtu: u32,
    rx_buf: Option<Vec<u8>>,
    tx_buf: Option<Vec<u8>>,
}

impl TunPhy {
    fn new(mtu: u32) -> Self {
        Self {
            mtu,
            rx_buf: None,
            tx_buf: None,
        }
    }
}

impl Device for TunPhy {
    type RxToken<'a> = TunRxToken;
    type TxToken<'a> = TunTxToken<'a>;

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        self.rx_buf
            .take()
            .map(|buf| (TunRxToken(buf), TunTxToken(self)))
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        Some(TunTxToken(self))
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.max_transmission_unit = self.mtu as usize;
        caps.medium = Medium::Ip;
        caps
    }
}

struct TunRxToken(Vec<u8>);

impl RxToken for TunRxToken {
    fn consume<R, F>(mut self, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        f(&mut self.0)
    }
}

struct TunTxToken<'a>(&'a mut TunPhy);

impl<'a> TxToken for TunTxToken<'a> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buf = vec![0u8; len];
        let result = f(&mut buf);
        self.0.tx_buf = Some(buf);
        result
    }
}

impl InboundService for TunInboundService {
    fn serve(&self) -> std::io::Result<()> {
        info!("Starting TUN inbound service");
        let rt = tokio::runtime::Runtime::new().map_err(io::Error::other)?;
        rt.block_on(self.process_packets())
    }

    fn request_shutdown(&self) {
        self.shutdown();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ipv4_tcp_packet() {
        // Minimal valid IPv4 TCP packet (SYN)
        let mut packet = vec![0u8; 60];
        packet[0] = 0x45; // Version 4, IHL 5
        packet[9] = IPPROTO_TCP;
        packet[12..16].copy_from_slice(&[192, 168, 1, 100]); // src IP
        packet[16..20].copy_from_slice(&[8, 8, 8, 8]); // dst IP
        packet[20..22].copy_from_slice(&1234u16.to_be_bytes()); // src port
        packet[22..24].copy_from_slice(&443u16.to_be_bytes()); // dst port
        packet[32] = 0x50; // Data offset = 5 (20 bytes)

        let parsed = parse_ip_packet(&packet).unwrap();
        assert_eq!(parsed.version, 4);
        assert_eq!(parsed.protocol, IPPROTO_TCP);
        assert_eq!(parsed.src_ip, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)));
        assert_eq!(parsed.dst_ip, IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)));
        assert_eq!(parsed.src_port, Some(1234));
        assert_eq!(parsed.dst_port, Some(443));
    }

    #[test]
    fn test_parse_ipv4_udp_packet() {
        let mut packet = vec![0u8; 40];
        packet[0] = 0x45;
        packet[9] = IPPROTO_UDP;
        packet[12..16].copy_from_slice(&[10, 0, 0, 1]);
        packet[16..20].copy_from_slice(&[1, 1, 1, 1]);
        packet[20..22].copy_from_slice(&5353u16.to_be_bytes());
        packet[22..24].copy_from_slice(&53u16.to_be_bytes());

        let parsed = parse_ip_packet(&packet).unwrap();
        assert_eq!(parsed.protocol, IPPROTO_UDP);
        assert_eq!(parsed.src_port, Some(5353));
        assert_eq!(parsed.dst_port, Some(53));
    }

    #[test]
    fn test_flow_key_reverse() {
        let key = FlowKey {
            protocol: IPPROTO_TCP,
            src: "192.168.1.1:1234".parse().unwrap(),
            dst: "8.8.8.8:443".parse().unwrap(),
        };
        let rev = key.reverse();
        assert_eq!(rev.src, key.dst);
        assert_eq!(rev.dst, key.src);
        assert_eq!(rev.protocol, key.protocol);
    }

    #[test]
    fn test_session_table_basic() {
        let table = SessionTable::new(100, 60);

        let key = FlowKey {
            protocol: IPPROTO_TCP,
            src: "192.168.1.1:1234".parse().unwrap(),
            dst: "8.8.8.8:443".parse().unwrap(),
        };

        let session = table.get_or_create(key, |k| Some(TunSession::new(*k, "proxy".to_string())));
        assert!(session.is_some());
        assert_eq!(table.len(), 1);

        // Same key should return existing session
        let session2 = table.get_or_create(key, |_| panic!("should not create"));
        assert!(session2.is_some());
        assert_eq!(table.len(), 1);
    }

    #[test]
    fn test_tun_config_default() {
        let config = TunConfig::default();
        assert_eq!(config.mtu, 1500);
        assert_eq!(config.max_sessions, 65536);
        assert_eq!(config.session_timeout, 300);
    }
}
