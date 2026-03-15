//! TUN UDP forwarding — lightweight NAT table + direct socket relay.
//!
//! Each unique (src_ip, src_port, dst_ip, dst_port) tuple gets a dedicated local
//! UDP socket. The outbound socket is bound to `0.0.0.0:0` (ephemeral) and
//! `connect()`-ed to the destination so that responses come back via `recv()`.
//!
//! A background task per session relays responses back by constructing raw
//! IP/UDP packets and writing them to the TUN file descriptor.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use tokio::net::UdpSocket;

use crate::inbound::tun_session::TunWriter;

/// Default NAT entry TTL (5 minutes).
const DEFAULT_UDP_NAT_TTL: Duration = Duration::from_secs(300);
/// Maximum NAT entries before we refuse new ones.
const MAX_NAT_ENTRIES: usize = 4096;

/// Four-tuple key for the UDP NAT table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(super) struct UdpFourTuple {
    pub src_ip: IpAddr,
    pub src_port: u16,
    pub dst_ip: IpAddr,
    pub dst_port: u16,
}

/// A single UDP NAT session.
struct UdpSession {
    /// Outbound UDP socket (connected to destination).
    socket: Arc<UdpSocket>,
    /// Last activity timestamp (for eviction).
    last_active: Instant,
}

/// Lightweight UDP NAT table for TUN.
pub(super) struct UdpNatTable {
    sessions: DashMap<UdpFourTuple, UdpSession>,
    ttl: Duration,
    /// Estimated session count (atomic for cheap reads from InboundService).
    session_count: AtomicU64,
}

impl UdpNatTable {
    pub(super) fn new(ttl: Option<Duration>) -> Self {
        Self {
            sessions: DashMap::new(),
            ttl: ttl.unwrap_or(DEFAULT_UDP_NAT_TTL),
            session_count: AtomicU64::new(0),
        }
    }

    pub(super) fn session_count(&self) -> u64 {
        self.session_count.load(Ordering::Relaxed)
    }

    /// Forward a UDP payload through the NAT.
    ///
    /// If an existing session exists, the payload is forwarded immediately.
    /// If not, a new outbound socket is created, a reverse-relay task is spawned,
    /// and then the payload is forwarded.
    pub(super) async fn forward(
        &self,
        key: UdpFourTuple,
        payload: &[u8],
        writer: Arc<dyn TunWriter>,
    ) -> std::io::Result<()> {
        // Fast path: existing session
        if let Some(mut entry) = self.sessions.get_mut(&key) {
            entry.last_active = Instant::now();
            let sock = entry.socket.clone();
            drop(entry);
            sock.send(payload).await?;
            return Ok(());
        }

        // Slow path: create new session
        if self.sessions.len() >= MAX_NAT_ENTRIES {
            return Err(std::io::Error::other("UDP NAT table full"));
        }

        let dst = SocketAddr::new(key.dst_ip, key.dst_port);
        let bind_addr: SocketAddr = if dst.is_ipv4() {
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
        } else {
            SocketAddr::new(IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED), 0)
        };

        let socket = UdpSocket::bind(bind_addr).await?;
        socket.connect(dst).await?;
        let socket = Arc::new(socket);

        self.sessions.insert(
            key,
            UdpSession {
                socket: socket.clone(),
                last_active: Instant::now(),
            },
        );
        self.session_count.fetch_add(1, Ordering::Relaxed);

        // Spawn reverse relay: outbound → TUN
        spawn_reverse_relay(key, socket.clone(), writer);

        // Send the payload
        socket.send(payload).await?;
        Ok(())
    }

    /// Evict expired sessions. Called periodically from a background task.
    pub(super) fn evict_expired(&self) {
        let deadline = Instant::now() - self.ttl;
        let mut evicted = 0u64;
        self.sessions.retain(|_, session| {
            if session.last_active < deadline {
                evicted += 1;
                false
            } else {
                true
            }
        });
        if evicted > 0 {
            self.session_count.fetch_sub(evicted, Ordering::Relaxed);
            tracing::debug!(evicted, remaining = self.sessions.len(), "tun udp: NAT eviction");
        }
    }
}

/// Spawn a background task that relays inbound UDP responses back through the TUN.
fn spawn_reverse_relay(
    key: UdpFourTuple,
    socket: Arc<UdpSocket>,
    writer: Arc<dyn TunWriter>,
) {
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65536];
        loop {
            let n = match tokio::time::timeout(DEFAULT_UDP_NAT_TTL, socket.recv(&mut buf)).await {
                Ok(Ok(n)) if n > 0 => n,
                _ => break, // timeout or error → stop relay
            };

            // Construct IP/UDP response packet and write to TUN.
            // Source = original destination, Destination = original source (NAT reverse).
            let pkt = build_udp_ip_packet(
                key.dst_ip, key.dst_port, // response source = original dst
                key.src_ip, key.src_port, // response dest = original src
                &buf[..n],
            );
            if let Err(e) = writer.write_packet(&pkt).await {
                tracing::trace!("tun udp reverse relay write error: {}", e);
                break;
            }
        }
        // Session ended — counter will be decremented by eviction
    });
}

/// Spawn a periodic eviction task for the NAT table.
pub(super) fn spawn_eviction_task(nat: Arc<UdpNatTable>) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        loop {
            interval.tick().await;
            nat.evict_expired();
        }
    });
}

// ─── IP/UDP packet construction ───────────────────────────────────────────

/// Build a complete IPv4/UDP packet (with 4-byte AF header for macOS utun).
fn build_udp_ip_packet(
    src_ip: IpAddr,
    src_port: u16,
    dst_ip: IpAddr,
    dst_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    match (src_ip, dst_ip) {
        (IpAddr::V4(s), IpAddr::V4(d)) => build_ipv4_udp(s, src_port, d, dst_port, payload),
        _ => {
            // IPv6 UDP response — not yet implemented
            tracing::trace!("tun udp: IPv6 response not implemented");
            Vec::new()
        }
    }
}

/// Build IPv4/UDP packet with 4-byte AF_INET prefix (macOS utun format).
fn build_ipv4_udp(
    src: Ipv4Addr,
    src_port: u16,
    dst: Ipv4Addr,
    dst_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let udp_len = 8 + payload.len();
    let ip_total = 20 + udp_len;

    // 4 bytes AF prefix + 20 bytes IP header + 8 bytes UDP header + payload
    let mut pkt = vec![0u8; 4 + ip_total];

    // AF_INET prefix (macOS utun)
    #[cfg(target_os = "macos")]
    {
        let af_inet: u32 = 2; // AF_INET
        pkt[0..4].copy_from_slice(&af_inet.to_be_bytes());
    }
    #[cfg(target_os = "linux")]
    {
        // Linux TUN has no AF prefix in TUN_NO_PI mode, but we add PI header
        // For IFF_NO_PI mode, no prefix needed — adjust offset logic accordingly
        // For now, keep the 4 byte prefix as flags(2) + proto(2)
        pkt[2..4].copy_from_slice(&0x0800u16.to_be_bytes()); // ETH_P_IP
    }

    let ip = &mut pkt[4..];

    // IPv4 header (20 bytes, no options)
    ip[0] = 0x45; // version=4, IHL=5
    ip[1] = 0x00; // DSCP/ECN
    ip[2..4].copy_from_slice(&(ip_total as u16).to_be_bytes()); // total length
    ip[4..6].copy_from_slice(&0u16.to_be_bytes()); // identification
    ip[6] = 0x40; // flags: DF
    ip[7] = 0x00; // fragment offset
    ip[8] = 64; // TTL
    ip[9] = 17; // protocol: UDP
    ip[10..12].copy_from_slice(&0u16.to_be_bytes()); // checksum (computed below)
    ip[12..16].copy_from_slice(&src.octets());
    ip[16..20].copy_from_slice(&dst.octets());

    // IP header checksum
    let cksum = ip_checksum(&ip[0..20]);
    ip[10..12].copy_from_slice(&cksum.to_be_bytes());

    // UDP header (8 bytes)
    let udp = &mut ip[20..];
    udp[0..2].copy_from_slice(&src_port.to_be_bytes());
    udp[2..4].copy_from_slice(&dst_port.to_be_bytes());
    udp[4..6].copy_from_slice(&(udp_len as u16).to_be_bytes());
    udp[6..8].copy_from_slice(&0u16.to_be_bytes()); // UDP checksum (optional for IPv4)

    // Payload
    udp[8..8 + payload.len()].copy_from_slice(payload);

    pkt
}

/// Compute IPv4 header checksum (RFC 1071).
fn ip_checksum(header: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < header.len() {
        sum += u16::from_be_bytes([header[i], header[i + 1]]) as u32;
        i += 2;
    }
    if i < header.len() {
        sum += (header[i] as u32) << 8;
    }
    while sum > 0xFFFF {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ip_checksum() {
        // Known good: IP header from RFC 1071 example
        // For a simple test, verify checksum of a hand-crafted header
        let mut header = [0u8; 20];
        header[0] = 0x45;
        header[8] = 64; // TTL
        header[9] = 17; // UDP
        header[12..16].copy_from_slice(&[10, 0, 0, 1]); // src
        header[16..20].copy_from_slice(&[10, 0, 0, 2]); // dst
        // Total length = 28 (20 IP + 8 UDP)
        header[2..4].copy_from_slice(&28u16.to_be_bytes());

        let cksum = ip_checksum(&header);
        // Verify: re-checksum with cksum set should be 0
        header[10..12].copy_from_slice(&cksum.to_be_bytes());
        assert_eq!(ip_checksum(&header), 0);
    }

    #[test]
    fn test_build_ipv4_udp_packet() {
        let pkt = build_ipv4_udp(
            Ipv4Addr::new(10, 0, 0, 1),
            12345,
            Ipv4Addr::new(10, 0, 0, 2),
            53,
            b"hello",
        );

        // 4 AF prefix + 20 IP + 8 UDP + 5 payload = 37
        assert_eq!(pkt.len(), 37);

        // Verify IP protocol is UDP (17)
        assert_eq!(pkt[4 + 9], 17);

        // Verify UDP payload
        assert_eq!(&pkt[4 + 20 + 8..], b"hello");
    }
}
