// UDP packet processor with NAT integration
//
// This module provides UDP packet processing functionality that integrates
// with the UDP NAT system for session management and traffic routing.

use std::{net::SocketAddr, sync::Arc, time::Duration};

use tokio::sync::Mutex;

use crate::{
    error::SbResult,
    net::udp_nat_core::{UdpFlowKey, UdpNat},
};

#[cfg(feature = "metrics")]
use crate::metrics::udp::{inc_packets_in, inc_packets_out, record_flow_bytes};

/// UDP packet information
#[derive(Debug, Clone)]
pub struct UdpPacket {
    /// Source address
    pub src: SocketAddr,
    /// Destination address  
    pub dst: SocketAddr,
    /// Packet payload
    pub data: Vec<u8>,
}

impl UdpPacket {
    /// Create a new UDP packet
    pub fn new(src: SocketAddr, dst: SocketAddr, data: Vec<u8>) -> Self {
        Self { src, dst, data }
    }

    /// Get packet size in bytes
    pub fn size(&self) -> usize {
        self.data.len()
    }
}

/// UDP packet processor with NAT integration
pub struct UdpProcessor {
    /// UDP NAT manager
    nat: Arc<Mutex<UdpNat>>,
}

impl UdpProcessor {
    /// Create a new UDP processor
    pub fn new(max_sessions: usize, session_ttl: Duration) -> Self {
        Self {
            nat: Arc::new(Mutex::new(UdpNat::new(max_sessions, session_ttl))),
        }
    }

    /// Create with env overrides: SB_UDP_TTL_MS, SB_UDP_GC_MS (ms), SB_UDP_NAT_MAX
    pub fn from_env() -> (Self, Duration) {
        let ttl_ms = std::env::var("SB_UDP_TTL_MS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(300_000);
        let max = std::env::var("SB_UDP_NAT_MAX")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(1000);
        let gc_ms = std::env::var("SB_UDP_GC_MS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(5_000);
        (
            Self::new(max, Duration::from_millis(ttl_ms)),
            Duration::from_millis(gc_ms),
        )
    }

    /// Process inbound UDP packet (from client to server)
    pub async fn process_inbound(&self, packet: UdpPacket) -> SbResult<SocketAddr> {
        #[cfg(feature = "metrics")]
        {
            inc_packets_in();
            record_flow_bytes("in", packet.size());
        }

        let mut nat = self.nat.lock().await;
        let mapped_addr = nat.create_mapping(packet.src, packet.dst)?;

        // Update session statistics
        if let Some(session) = nat.lookup_session(&mapped_addr) {
            let flow_key = session.flow_key.clone();
            drop(nat); // Release lock before calling add_session_bytes
            let mut nat = self.nat.lock().await;
            nat.add_session_bytes(&flow_key, packet.size() as u64, 0);
        }

        Ok(mapped_addr)
    }

    /// Process outbound UDP packet (from server to client)
    pub async fn process_outbound(
        &self,
        packet: UdpPacket,
        mapped_addr: SocketAddr,
    ) -> SbResult<Option<SocketAddr>> {
        #[cfg(feature = "metrics")]
        {
            inc_packets_out();
            record_flow_bytes("out", packet.size());
        }

        let mut nat = self.nat.lock().await;

        // Look up session by mapped address
        if let Some(session) = nat.lookup_session(&mapped_addr) {
            let flow_key = session.flow_key.clone();
            let client_addr = session.flow_key.src;

            // Update session statistics
            nat.add_session_bytes(&flow_key, 0, packet.size() as u64);

            Ok(Some(client_addr))
        } else {
            // No session found - packet should be dropped
            Ok(None)
        }
    }

    /// Look up session information by mapped address
    pub async fn lookup_session(&self, mapped_addr: &SocketAddr) -> Option<UdpFlowKey> {
        let nat = self.nat.lock().await;
        nat.lookup_session(mapped_addr)
            .map(|session| session.flow_key.clone())
    }

    /// Update activity for a session
    pub async fn update_activity(&self, mapped_addr: &SocketAddr) {
        let mut nat = self.nat.lock().await;
        nat.update_activity_by_addr(mapped_addr);
    }

    /// Get current session count
    pub async fn session_count(&self) -> usize {
        let nat = self.nat.lock().await;
        nat.session_count()
    }

    /// Perform cleanup of expired sessions
    pub async fn cleanup_expired(&self) -> usize {
        let mut nat = self.nat.lock().await;
        nat.evict_expired()
    }

    /// Clear all sessions (for testing/shutdown)
    pub async fn clear_sessions(&self) {
        let mut nat = self.nat.lock().await;
        nat.clear();
    }

    /// Get NAT configuration
    pub async fn get_config(&self) -> (usize, Duration) {
        let nat = self.nat.lock().await;
        (nat.max_sessions(), nat.session_ttl())
    }

    /// Start periodic cleanup task
    pub fn start_cleanup_task(self: Arc<Self>, cleanup_interval: Duration) {
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(cleanup_interval);
            loop {
                interval.tick().await;
                // Batch GC to reduce pause time
                let mut total = 0usize;
                loop {
                    let mut nat = self.nat.lock().await;
                    let removed = nat.evict_expired_batch(256);
                    drop(nat);
                    total += removed;
                    if removed < 256 {
                        break;
                    }
                }
                let expired_count = total;
                if expired_count > 0 {
                    tracing::debug!("Cleaned up {} expired UDP NAT sessions", expired_count);
                }
            }
        });
    }
}

impl Default for UdpProcessor {
    fn default() -> Self {
        Self::new(1000, Duration::from_secs(300)) // 5 minutes default TTL
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn test_addr(port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), port)
    }

    fn test_packet(src_port: u16, dst_port: u16, data: &[u8]) -> UdpPacket {
        UdpPacket::new(test_addr(src_port), test_addr(dst_port), data.to_vec())
    }

    #[tokio::test]
    async fn test_udp_processor_creation() {
        let processor = UdpProcessor::new(100, Duration::from_secs(300));
        let (max_sessions, ttl) = processor.get_config().await;

        assert_eq!(max_sessions, 100);
        assert_eq!(ttl, Duration::from_secs(300));
        assert_eq!(processor.session_count().await, 0);
    }

    #[tokio::test]
    async fn test_inbound_packet_processing() {
        let processor = UdpProcessor::new(100, Duration::from_secs(300));
        let packet = test_packet(1234, 5678, b"test data");

        let mapped_addr = processor.process_inbound(packet).await.unwrap();
        assert_eq!(processor.session_count().await, 1);

        // Verify session lookup
        let flow_key = processor.lookup_session(&mapped_addr).await.unwrap();
        assert_eq!(flow_key.src, test_addr(1234));
        assert_eq!(flow_key.dst, test_addr(5678));
    }

    #[tokio::test]
    async fn test_outbound_packet_processing() {
        let processor = UdpProcessor::new(100, Duration::from_secs(300));

        // First create an inbound session
        let inbound_packet = test_packet(1234, 5678, b"request");
        let mapped_addr = processor.process_inbound(inbound_packet).await.unwrap();

        // Then process outbound packet
        let outbound_packet = test_packet(5678, 1234, b"response");
        let client_addr = processor
            .process_outbound(outbound_packet, mapped_addr)
            .await
            .unwrap();

        assert_eq!(client_addr, Some(test_addr(1234)));
    }

    #[tokio::test]
    async fn test_outbound_packet_no_session() {
        let processor = UdpProcessor::new(100, Duration::from_secs(300));
        let fake_mapped_addr = test_addr(10000);

        let outbound_packet = test_packet(5678, 1234, b"response");
        let result = processor
            .process_outbound(outbound_packet, fake_mapped_addr)
            .await
            .unwrap();

        assert_eq!(result, None); // No session found
    }

    #[tokio::test]
    async fn test_session_activity_update() {
        let processor = UdpProcessor::new(100, Duration::from_secs(300));
        let packet = test_packet(1234, 5678, b"test data");

        let mapped_addr = processor.process_inbound(packet).await.unwrap();

        // Update activity
        processor.update_activity(&mapped_addr).await;

        // Session should still exist
        assert!(processor.lookup_session(&mapped_addr).await.is_some());
    }

    #[tokio::test]
    async fn test_session_cleanup() {
        let processor = UdpProcessor::new(100, Duration::from_millis(10));
        let packet = test_packet(1234, 5678, b"test data");

        let _mapped_addr = processor.process_inbound(packet).await.unwrap();
        assert_eq!(processor.session_count().await, 1);

        // Wait for expiration
        tokio::time::sleep(Duration::from_millis(20)).await;

        let expired_count = processor.cleanup_expired().await;
        assert_eq!(expired_count, 1);
        assert_eq!(processor.session_count().await, 0);
    }

    #[tokio::test]
    async fn test_inbound_zero_payload_no_crash() {
        let processor = UdpProcessor::new(100, Duration::from_secs(300));
        let packet = test_packet(1234, 5678, b"");
        // Should succeed and create mapping even with empty payload
        let mapped = processor.process_inbound(packet).await.expect("inbound ok");
        assert!(processor.lookup_session(&mapped).await.is_some());
    }

    #[tokio::test]
    async fn test_bidirectional_flow_mapping() {
        let processor = UdpProcessor::new(100, Duration::from_secs(300));

        // Client -> Server
        let request = test_packet(1234, 5678, b"request data");
        let mapped_addr = processor.process_inbound(request).await.unwrap();

        // Server -> Client
        let response = test_packet(5678, 1234, b"response data");
        let client_addr = processor
            .process_outbound(response, mapped_addr)
            .await
            .unwrap();

        assert_eq!(client_addr, Some(test_addr(1234)));

        // Verify session statistics
        let flow_key = processor.lookup_session(&mapped_addr).await.unwrap();
        let nat = processor.nat.lock().await;
        let session = nat.lookup_session_by_key(&flow_key).unwrap();

        assert_eq!(session.tx_bytes, b"request data".len() as u64);
        assert_eq!(session.rx_bytes, b"response data".len() as u64);
    }

    #[tokio::test]
    async fn test_clear_sessions() {
        let processor = UdpProcessor::new(100, Duration::from_secs(300));

        // Create some sessions
        let _addr1 = processor
            .process_inbound(test_packet(1000, 2000, b"data1"))
            .await
            .unwrap();
        let _addr2 = processor
            .process_inbound(test_packet(1001, 2001, b"data2"))
            .await
            .unwrap();
        assert_eq!(processor.session_count().await, 2);

        // Clear all sessions
        processor.clear_sessions().await;
        assert_eq!(processor.session_count().await, 0);
    }

    #[tokio::test]
    async fn gc_batch_removes_in_chunks() {
        let processor = UdpProcessor::new(100, Duration::from_millis(5));
        for i in 0..50u16 {
            let p = test_packet(1000 + i, 2000, b"x");
            let _ = processor.process_inbound(p).await.unwrap();
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
        let mut removed = 0usize;
        {
            let mut nat = processor.nat.lock().await;
            removed += nat.evict_expired_batch(10);
            assert_eq!(removed, 10);
            removed += nat.evict_expired_batch(10);
            assert_eq!(removed, 20);
        }
    }

    #[tokio::test]
    async fn burst_then_gc_falls_back() {
        let processor = UdpProcessor::new(200, Duration::from_millis(5));
        for i in 0..100u16 {
            let _ = processor
                .process_inbound(test_packet(2000 + i, 53, b"req"))
                .await
                .unwrap();
        }
        tokio::time::sleep(Duration::from_millis(8)).await;
        let start = processor.session_count().await;
        assert!(start >= 100);
        let removed = processor.cleanup_expired().await;
        assert!(removed > 0);
        let after = processor.session_count().await;
        assert!(after < start);
    }

    #[test]
    fn env_overrides_readable() {
        std::env::set_var("SB_UDP_TTL_MS", "1234");
        std::env::set_var("SB_UDP_GC_MS", "77");
        std::env::set_var("SB_UDP_NAT_MAX", "42");
        let (_p, gc) = UdpProcessor::from_env();
        assert_eq!(gc, Duration::from_millis(77));
        std::env::remove_var("SB_UDP_TTL_MS");
        std::env::remove_var("SB_UDP_GC_MS");
        std::env::remove_var("SB_UDP_NAT_MAX");
    }
}
