// Core UDP NAT System Implementation
//
// This module implements the UDP NAT system according to the design specifications
// with UdpFlowKey, UdpSession, and UdpNat structures as defined in the requirements.

use std::{
    collections::HashMap,
    net::SocketAddr,
    time::{Duration, Instant},
};

use crate::error::{SbError, SbResult};

#[cfg(feature = "metrics")]
use crate::metrics::udp::{record_nat_eviction, record_session_ttl, set_nat_size, EvictionReason};

/// UDP flow key for session identification
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct UdpFlowKey {
    /// Source address (client)
    pub src: SocketAddr,
    /// Destination address (target)
    pub dst: SocketAddr,
    /// Session identifier for disambiguation
    pub session_id: u64,
}

impl UdpFlowKey {
    /// Create a new UDP flow key
    pub const fn new(src: SocketAddr, dst: SocketAddr, session_id: u64) -> Self {
        Self {
            src,
            dst,
            session_id,
        }
    }
}

/// UDP session with TTL and activity tracking
#[derive(Debug)]
pub struct UdpSession {
    /// Flow key identifying this session
    pub flow_key: UdpFlowKey,
    /// When the session was created
    pub created_at: Instant,
    /// Last activity timestamp
    pub last_activity: Instant,
    /// Bytes transmitted (client to server)
    pub tx_bytes: u64,
    /// Bytes received (server to client)
    pub rx_bytes: u64,
    /// Mapped local address for this session
    pub mapped_addr: SocketAddr,
}

impl UdpSession {
    /// Create a new UDP session
    pub fn new(flow_key: UdpFlowKey, mapped_addr: SocketAddr) -> Self {
        let now = Instant::now();
        Self {
            flow_key,
            created_at: now,
            last_activity: now,
            tx_bytes: 0,
            rx_bytes: 0,
            mapped_addr,
        }
    }

    /// Update activity timestamp
    pub fn update_activity(&mut self) {
        self.last_activity = Instant::now();
    }

    /// Add transmitted bytes
    pub fn add_tx_bytes(&mut self, bytes: u64) {
        self.tx_bytes = self.tx_bytes.saturating_add(bytes);
        self.update_activity();
    }

    /// Add received bytes
    pub fn add_rx_bytes(&mut self, bytes: u64) {
        self.rx_bytes = self.rx_bytes.saturating_add(bytes);
        self.update_activity();
    }

    /// Check if session has expired
    pub fn is_expired(&self, ttl: Duration) -> bool {
        self.last_activity.elapsed() > ttl
    }

    /// Get total bytes transferred
    pub const fn total_bytes(&self) -> u64 {
        self.tx_bytes.saturating_add(self.rx_bytes)
    }
}

/// UDP NAT manager with HashMap-based session storage
pub struct UdpNat {
    /// Session storage indexed by flow key
    sessions: HashMap<UdpFlowKey, UdpSession>,
    /// Reverse mapping from mapped address to flow key
    reverse_map: HashMap<SocketAddr, UdpFlowKey>,
    /// Maximum number of sessions
    max_sessions: usize,
    /// Session TTL duration
    session_ttl: Duration,
    /// Next session ID counter
    next_session_id: u64,
    /// Base port for mapped addresses
    base_port: u16,
    /// Next available port
    next_port: u16,
}

impl UdpNat {
    /// Create a new UDP NAT manager
    pub fn new(max_sessions: usize, session_ttl: Duration) -> Self {
        Self {
            sessions: HashMap::new(),
            reverse_map: HashMap::new(),
            max_sessions,
            session_ttl,
            next_session_id: 1,
            base_port: 10000,
            next_port: 10000,
        }
    }

    /// Create a NAT mapping for a UDP flow
    pub fn create_mapping(&mut self, src: SocketAddr, dst: SocketAddr) -> SbResult<SocketAddr> {
        // Check if mapping already exists for this src/dst pair
        for (flow_key, session) in &mut self.sessions {
            if flow_key.src == src && flow_key.dst == dst {
                session.update_activity();
                return Ok(session.mapped_addr);
            }
        }

        // Check capacity and evict if necessary
        if self.sessions.len() >= self.max_sessions {
            self.evict_lru()?;
        }

        // Generate session ID and flow key
        let session_id = self.next_session_id;
        self.next_session_id = self.next_session_id.wrapping_add(1);
        let flow_key = UdpFlowKey::new(src, dst, session_id);

        // Allocate mapped address
        let mapped_addr = self.allocate_mapped_addr()?;

        // Create new session
        let session = UdpSession::new(flow_key.clone(), mapped_addr);

        // Store session and reverse mapping
        self.reverse_map.insert(mapped_addr, flow_key.clone());
        self.sessions.insert(flow_key, session);

        // Update metrics
        #[cfg(feature = "metrics")]
        set_nat_size(self.sessions.len());

        Ok(mapped_addr)
    }

    /// Lookup session by mapped address
    pub fn lookup_session(&self, addr: &SocketAddr) -> Option<&UdpSession> {
        let flow_key = self.reverse_map.get(addr)?;
        self.sessions.get(flow_key)
    }

    /// Lookup session by flow key
    pub fn lookup_session_by_key(&self, flow_key: &UdpFlowKey) -> Option<&UdpSession> {
        self.sessions.get(flow_key)
    }

    /// Update activity for a session
    pub fn update_activity(&mut self, flow_key: &UdpFlowKey) {
        if let Some(session) = self.sessions.get_mut(flow_key) {
            session.update_activity();
        }
    }

    /// Update activity by mapped address
    pub fn update_activity_by_addr(&mut self, addr: &SocketAddr) {
        if let Some(flow_key) = self.reverse_map.get(addr).cloned() {
            self.update_activity(&flow_key);
        }
    }

    /// Add bytes to session statistics
    pub fn add_session_bytes(&mut self, flow_key: &UdpFlowKey, tx_bytes: u64, rx_bytes: u64) {
        if let Some(session) = self.sessions.get_mut(flow_key) {
            if tx_bytes > 0 {
                session.add_tx_bytes(tx_bytes);
            }
            if rx_bytes > 0 {
                session.add_rx_bytes(rx_bytes);
            }
        }
    }

    /// Evict expired sessions (all)
    pub fn evict_expired(&mut self) -> usize {
        self.evict_expired_batch(usize::MAX)
    }

    /// Evict expired sessions up to `limit` entries (batch GC)
    pub fn evict_expired_batch(&mut self, limit: usize) -> usize {
        let mut expired_keys = Vec::new();

        // Find expired sessions
        for (flow_key, session) in &self.sessions {
            if session.is_expired(self.session_ttl) {
                expired_keys.push(flow_key.clone());
                if expired_keys.len() >= limit {
                    break;
                }
            }
        }

        // Remove expired sessions
        let count = expired_keys.len();
        for flow_key in expired_keys {
            // Record session lifetime before removal
            #[cfg(feature = "metrics")]
            if let Some(session) = self.sessions.get(&flow_key) {
                let lifetime_seconds = session.created_at.elapsed().as_secs_f64();
                record_session_ttl(lifetime_seconds);
            }

            self.remove_session(&flow_key);
            #[cfg(feature = "metrics")]
            record_nat_eviction(EvictionReason::Ttl);
        }

        // Update metrics
        #[cfg(feature = "metrics")]
        {
            set_nat_size(self.sessions.len());
            crate::metrics::udp::set_nat_entries(self.sessions.len(), count);
        }

        count
    }

    /// Evict least recently used session (LRU strategy)
    fn evict_lru(&mut self) -> SbResult<()> {
        if self.sessions.is_empty() {
            return Err(SbError::Capacity {
                what: "UDP NAT sessions".to_string(),
                limit: self.max_sessions,
            });
        }

        // Find LRU session
        let mut lru_key = None;
        let mut oldest_activity = Instant::now();

        for (flow_key, session) in &self.sessions {
            if session.last_activity < oldest_activity {
                oldest_activity = session.last_activity;
                lru_key = Some(flow_key.clone());
            }
        }

        // Remove LRU session
        if let Some(flow_key) = lru_key {
            // Record session lifetime before removal
            #[cfg(feature = "metrics")]
            if let Some(session) = self.sessions.get(&flow_key) {
                let lifetime_seconds = session.created_at.elapsed().as_secs_f64();
                record_session_ttl(lifetime_seconds);
            }

            self.remove_session(&flow_key);
            #[cfg(feature = "metrics")]
            record_nat_eviction(EvictionReason::Capacity);
        }

        Ok(())
    }

    /// Remove a session and its reverse mapping
    fn remove_session(&mut self, flow_key: &UdpFlowKey) {
        if let Some(session) = self.sessions.remove(flow_key) {
            self.reverse_map.remove(&session.mapped_addr);
        }
    }

    /// Allocate a mapped address for a new session
    fn allocate_mapped_addr(&mut self) -> SbResult<SocketAddr> {
        // Simple port allocation strategy
        let start_port = self.next_port;

        loop {
            // Use infallible constructor to avoid parse().unwrap()
            let addr = SocketAddr::new(
                std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                self.next_port,
            );

            // Check if port is already in use
            if !self.reverse_map.contains_key(&addr) {
                self.next_port = if self.next_port == 65535 {
                    self.base_port
                } else {
                    self.next_port + 1
                };
                return Ok(addr);
            }

            // Move to next port
            self.next_port = if self.next_port == 65535 {
                self.base_port
            } else {
                self.next_port + 1
            };

            // Check if we've wrapped around
            if self.next_port == start_port {
                return Err(SbError::Capacity {
                    what: "UDP NAT port allocation".to_string(),
                    limit: 65535 - self.base_port as usize,
                });
            }
        }
    }

    /// Get current session count
    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }

    /// Get maximum session count
    pub const fn max_sessions(&self) -> usize {
        self.max_sessions
    }

    /// Get session TTL
    pub const fn session_ttl(&self) -> Duration {
        self.session_ttl
    }

    /// Get all active sessions (for debugging/monitoring)
    pub fn active_sessions(&self) -> impl Iterator<Item = &UdpSession> {
        self.sessions.values()
    }

    /// Clear all sessions
    pub fn clear(&mut self) {
        self.sessions.clear();
        self.reverse_map.clear();

        #[cfg(feature = "metrics")]
        set_nat_size(0);
    }
}

impl Default for UdpNat {
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

    #[test]
    fn test_udp_flow_key_creation() {
        let src = test_addr(1234);
        let dst = test_addr(5678);
        let session_id = 42;

        let flow_key = UdpFlowKey::new(src, dst, session_id);

        assert_eq!(flow_key.src, src);
        assert_eq!(flow_key.dst, dst);
        assert_eq!(flow_key.session_id, session_id);
    }

    #[test]
    fn test_udp_session_creation() {
        let src = test_addr(1234);
        let dst = test_addr(5678);
        let mapped = test_addr(10000);
        let flow_key = UdpFlowKey::new(src, dst, 1);

        let session = UdpSession::new(flow_key.clone(), mapped);

        assert_eq!(session.flow_key, flow_key);
        assert_eq!(session.mapped_addr, mapped);
        assert_eq!(session.tx_bytes, 0);
        assert_eq!(session.rx_bytes, 0);
    }

    #[test]
    fn test_udp_session_activity() {
        let src = test_addr(1234);
        let dst = test_addr(5678);
        let mapped = test_addr(10000);
        let flow_key = UdpFlowKey::new(src, dst, 1);

        let mut session = UdpSession::new(flow_key, mapped);
        let initial_activity = session.last_activity;

        // Small delay to ensure timestamp difference
        std::thread::sleep(Duration::from_millis(1));

        session.add_tx_bytes(100);
        assert!(session.last_activity > initial_activity);
        assert_eq!(session.tx_bytes, 100);

        session.add_rx_bytes(200);
        assert_eq!(session.rx_bytes, 200);
        assert_eq!(session.total_bytes(), 300);
    }

    #[test]
    fn test_udp_session_expiration() {
        let src = test_addr(1234);
        let dst = test_addr(5678);
        let mapped = test_addr(10000);
        let flow_key = UdpFlowKey::new(src, dst, 1);

        let session = UdpSession::new(flow_key, mapped);
        let ttl = Duration::from_millis(10);

        assert!(!session.is_expired(ttl));

        std::thread::sleep(Duration::from_millis(20));
        assert!(session.is_expired(ttl));
    }

    #[test]
    fn test_udp_nat_creation() {
        let nat = UdpNat::new(100, Duration::from_secs(300));

        assert_eq!(nat.max_sessions(), 100);
        assert_eq!(nat.session_ttl(), Duration::from_secs(300));
        assert_eq!(nat.session_count(), 0);
    }

    #[test]
    fn test_udp_nat_mapping() {
        let mut nat = UdpNat::new(100, Duration::from_secs(300));
        let src = test_addr(1234);
        let dst = test_addr(5678);

        let mapped_addr = nat.create_mapping(src, dst).unwrap();
        assert_eq!(nat.session_count(), 1);

        // Lookup by mapped address
        let session = nat.lookup_session(&mapped_addr).unwrap();
        assert_eq!(session.flow_key.src, src);
        assert_eq!(session.flow_key.dst, dst);
        assert_eq!(session.mapped_addr, mapped_addr);
    }

    #[test]
    fn test_udp_nat_duplicate_mapping() {
        let mut nat = UdpNat::new(100, Duration::from_secs(300));
        let src = test_addr(1234);
        let dst = test_addr(5678);

        let mapped_addr1 = nat.create_mapping(src, dst).unwrap();
        let mapped_addr2 = nat.create_mapping(src, dst).unwrap();

        // Should return the same mapped address for the same flow
        assert_eq!(mapped_addr1, mapped_addr2);
        assert_eq!(nat.session_count(), 1);
    }

    #[test]
    fn test_udp_nat_capacity_limit() {
        let mut nat = UdpNat::new(2, Duration::from_secs(300));

        // Fill to capacity
        let _addr1 = nat
            .create_mapping(test_addr(1000), test_addr(2000))
            .unwrap();
        let _addr2 = nat
            .create_mapping(test_addr(1001), test_addr(2001))
            .unwrap();
        assert_eq!(nat.session_count(), 2);

        // Adding one more should evict LRU
        let _addr3 = nat
            .create_mapping(test_addr(1002), test_addr(2002))
            .unwrap();
        assert_eq!(nat.session_count(), 2); // Still at capacity
    }

    #[test]
    fn test_udp_nat_zero_capacity_returns_error() {
        let mut nat = UdpNat::new(0, Duration::from_secs(300));
        // When capacity is zero, creating a mapping should return a capacity error and not panic.
        let res = nat.create_mapping(test_addr(1000), test_addr(2000));
        assert!(res.is_err());
    }

    #[test]
    fn test_udp_nat_expiration() {
        let mut nat = UdpNat::new(100, Duration::from_millis(10));
        let src = test_addr(1234);
        let dst = test_addr(5678);

        let _mapped_addr = nat.create_mapping(src, dst).unwrap();
        assert_eq!(nat.session_count(), 1);

        // Wait for expiration
        std::thread::sleep(Duration::from_millis(20));

        let expired_count = nat.evict_expired();
        assert_eq!(expired_count, 1);
        assert_eq!(nat.session_count(), 0);
    }

    #[test]
    fn test_udp_nat_activity_update() {
        let mut nat = UdpNat::new(100, Duration::from_secs(300));
        let src = test_addr(1234);
        let dst = test_addr(5678);

        let mapped_addr = nat.create_mapping(src, dst).unwrap();
        let session = nat.lookup_session(&mapped_addr).unwrap();
        let flow_key = session.flow_key.clone();
        let initial_activity = session.last_activity;

        std::thread::sleep(Duration::from_millis(1));

        nat.update_activity(&flow_key);
        let session = nat.lookup_session(&mapped_addr).unwrap();
        assert!(session.last_activity > initial_activity);
    }

    #[test]
    fn test_udp_nat_clear() {
        let mut nat = UdpNat::new(100, Duration::from_secs(300));

        let _addr1 = nat
            .create_mapping(test_addr(1000), test_addr(2000))
            .unwrap();
        let _addr2 = nat
            .create_mapping(test_addr(1001), test_addr(2001))
            .unwrap();
        assert_eq!(nat.session_count(), 2);

        nat.clear();
        assert_eq!(nat.session_count(), 0);
    }
}
