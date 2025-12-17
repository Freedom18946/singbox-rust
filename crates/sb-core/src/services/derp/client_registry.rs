//! Client registry for managing DERP connections.

use super::protocol::{DerpFrame, PeerGoneReason, PublicKey};
use parking_lot::RwLock;
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tracing;

/// Handle for communicating with a connected DERP client.
#[derive(Debug, Clone)]
pub struct ClientHandle {
    pub public_key: PublicKey,
    pub addr: SocketAddr,
    pub tx: mpsc::UnboundedSender<DerpFrame>,
    pub last_seen: Instant,
    pub connected_at: Instant,
}

impl ClientHandle {
    /// Send a frame to this client.
    pub fn send(&self, frame: DerpFrame) -> Result<(), String> {
        self.tx
            .send(frame)
            .map_err(|e| format!("failed to send frame: {}", e))
    }

    /// Update the last seen timestamp.
    pub fn touch(&self) {
        // Note: This method doesn't actually update last_seen because we store ClientHandle
        // in a HashMap and can't mutate it without a lock. The registry should call
        // touch_client() instead.
    }
}

/// Registry for managing connected DERP clients.
pub struct ClientRegistry {
    clients: Arc<RwLock<HashMap<PublicKey, ClientHandle>>>,
    /// Map of client key -> mesh peer key (for clients connected to other mesh nodes)
    remote_clients: Arc<RwLock<HashMap<PublicKey, PublicKey>>>,
    /// Map of mesh peer key -> sender channel
    mesh_peers: Arc<RwLock<HashMap<PublicKey, mpsc::UnboundedSender<DerpFrame>>>>,
    /// Map of remote DERP server public key -> sender channel (outbound mesh forwarders).
    mesh_forwarders: Arc<RwLock<HashMap<PublicKey, mpsc::UnboundedSender<DerpFrame>>>>,
    /// Set of mesh peer keys subscribed via `WatchConns` (Go derp server watchers model).
    mesh_watchers: Arc<RwLock<HashSet<PublicKey>>>,
    metrics: Arc<DerpMetrics>,
}

/// Metrics for DERP server.
pub struct DerpMetrics {
    tag: Arc<str>,
    clients_connected: parking_lot::Mutex<usize>,
    packets_relayed: parking_lot::Mutex<u64>,
    bytes_transferred: parking_lot::Mutex<u64>,
}

impl DerpMetrics {
    pub fn new(tag: Arc<str>) -> Self {
        Self {
            tag,
            clients_connected: parking_lot::Mutex::new(0),
            packets_relayed: parking_lot::Mutex::new(0),
            bytes_transferred: parking_lot::Mutex::new(0),
        }
    }

    pub fn connect_failed(&self, reason: &str) {
        sb_metrics::inc_derp_connection(&self.tag, reason);
    }

    pub fn client_connected(&self, active: usize) {
        *self.clients_connected.lock() = active;
        sb_metrics::inc_derp_connection(&self.tag, "ok");
        sb_metrics::set_derp_clients(&self.tag, active as i64);
    }

    pub fn client_disconnected(&self, active: usize, lifetime: Duration) {
        *self.clients_connected.lock() = active;
        sb_metrics::set_derp_clients(&self.tag, active as i64);
        sb_metrics::observe_derp_client_lifetime(&self.tag, lifetime.as_secs_f64());
    }

    pub fn packet_relayed(&self, size_bytes: usize) {
        *self.packets_relayed.lock() += 1;
        *self.bytes_transferred.lock() += size_bytes as u64;
        sb_metrics::inc_derp_relay(&self.tag, "ok", Some(size_bytes as u64));
    }

    pub fn relay_failed(&self, reason: &str) {
        sb_metrics::inc_derp_relay(&self.tag, reason, None);
    }

    pub fn set_active_clients(&self, active: usize) {
        *self.clients_connected.lock() = active;
        sb_metrics::set_derp_clients(&self.tag, active as i64);
    }

    pub fn get_stats(&self) -> (usize, u64, u64) {
        let clients = *self.clients_connected.lock();
        let packets = *self.packets_relayed.lock();
        let bytes = *self.bytes_transferred.lock();
        (clients, packets, bytes)
    }
}

impl ClientRegistry {
    /// Create a new client registry.
    pub fn new(tag: impl Into<Arc<str>>) -> Self {
        let tag = tag.into();
        Self {
            clients: Arc::new(RwLock::new(HashMap::new())),
            remote_clients: Arc::new(RwLock::new(HashMap::new())),
            mesh_peers: Arc::new(RwLock::new(HashMap::new())),
            mesh_forwarders: Arc::new(RwLock::new(HashMap::new())),
            mesh_watchers: Arc::new(RwLock::new(HashSet::new())),
            metrics: Arc::new(DerpMetrics::new(tag)),
        }
    }

    /// Register a new client.
    pub fn register_client(
        &self,
        public_key: PublicKey,
        addr: SocketAddr,
        tx: mpsc::UnboundedSender<DerpFrame>,
    ) -> Result<(), String> {
        let mut clients = self.clients.write();

        if clients.contains_key(&public_key) {
            self.metrics.connect_failed("duplicate");
            return Err(format!(
                "client with public key {:?} already registered",
                public_key
            ));
        }

        let now = Instant::now();
        let handle = ClientHandle {
            public_key,
            addr,
            tx,
            last_seen: now,
            connected_at: now,
        };

        clients.insert(public_key, handle);
        let active = clients.len();
        self.metrics.client_connected(active);

        tracing::info!(
            service = "derp",
            client = ?public_key,
            addr = %addr,
            count = active,
            "Client registered"
        );

        Ok(())
    }

    /// Unregister a client.
    pub fn unregister_client(&self, public_key: &PublicKey) -> Option<SocketAddr> {
        let mut clients = self.clients.write();
        let handle = clients.remove(public_key)?;

        let active = clients.len();
        let lifetime = Instant::now().saturating_duration_since(handle.connected_at);
        self.metrics.client_disconnected(active, lifetime);

        tracing::info!(
            service = "derp",
            client = ?public_key,
            addr = %handle.addr,
            count = active,
            duration = ?Instant::now().duration_since(handle.connected_at),
            "Client unregistered"
        );

        Some(handle.addr)
    }

    /// Get a client handle by public key.
    pub fn get_client(&self, public_key: &PublicKey) -> Option<ClientHandle> {
        let clients = self.clients.read();
        clients.get(public_key).map(|h| ClientHandle {
            public_key: h.public_key,
            addr: h.addr,
            tx: h.tx.clone(),
            last_seen: h.last_seen,
            connected_at: h.connected_at,
        })
    }

    /// Check if a client is registered.
    pub fn is_registered(&self, public_key: &PublicKey) -> bool {
        self.clients.read().contains_key(public_key)
    }

    /// Get the number of connected clients.
    pub fn client_count(&self) -> usize {
        self.clients.read().len()
    }

    /// Get list of all connected client public keys.
    pub fn list_clients(&self) -> Vec<PublicKey> {
        self.clients.read().keys().copied().collect()
    }

    /// Send a frame to a specific client.
    pub fn send_to_client(&self, dst_key: &PublicKey, frame: DerpFrame) -> Result<(), String> {
        let clients = self.clients.read();
        let client = clients
            .get(dst_key)
            .ok_or_else(|| format!("client {:?} not found", dst_key))?;

        client.send(frame)?;
        Ok(())
    }

    /// Register a mesh peer.
    pub fn register_mesh_peer(
        &self,
        peer_key: PublicKey,
        tx: mpsc::UnboundedSender<DerpFrame>,
    ) -> Result<(), String> {
        let mut peers = self.mesh_peers.write();
        if peers.contains_key(&peer_key) {
            return Err(format!("mesh peer {:?} already registered", peer_key));
        }
        peers.insert(peer_key, tx);
        tracing::info!(service = "derp", peer = ?peer_key, "Mesh peer registered");
        Ok(())
    }

    /// Unregister a mesh peer.
    pub fn unregister_mesh_peer(&self, peer_key: &PublicKey) {
        let mut peers = self.mesh_peers.write();
        peers.remove(peer_key);

        self.mesh_watchers.write().remove(peer_key);

        tracing::info!(service = "derp", peer = ?peer_key, "Mesh peer unregistered");
    }

    /// Register an outbound mesh forwarder (client to another DERP server).
    pub fn register_mesh_forwarder(
        &self,
        peer_key: PublicKey,
        tx: mpsc::UnboundedSender<DerpFrame>,
    ) -> Result<(), String> {
        let mut peers = self.mesh_forwarders.write();
        if peers.contains_key(&peer_key) {
            return Err(format!("mesh forwarder {:?} already registered", peer_key));
        }
        peers.insert(peer_key, tx);
        tracing::info!(service = "derp", peer = ?peer_key, "Mesh forwarder registered");
        Ok(())
    }

    /// Unregister an outbound mesh forwarder and drop all remote client mappings routed via it.
    pub fn unregister_mesh_forwarder(&self, peer_key: &PublicKey) {
        self.mesh_forwarders.write().remove(peer_key);

        let mut remote = self.remote_clients.write();
        remote.retain(|_, p| p != peer_key);

        tracing::info!(service = "derp", peer = ?peer_key, "Mesh forwarder unregistered");
    }

    /// Register a remote client (connected via a mesh peer).
    pub fn register_remote_client(&self, client_key: PublicKey, peer_key: PublicKey) {
        let mut remote = self.remote_clients.write();
        remote.insert(client_key, peer_key);
        tracing::debug!(service = "derp", client = ?client_key, peer = ?peer_key, "Remote client registered");
    }

    /// Unregister a remote client.
    pub fn unregister_remote_client(&self, client_key: &PublicKey) {
        let mut remote = self.remote_clients.write();
        remote.remove(client_key);
        tracing::debug!(service = "derp", client = ?client_key, "Remote client unregistered");
    }

    /// Handle a forwarded packet from a mesh peer.
    pub fn handle_forward_packet(
        &self,
        src_key: &PublicKey,
        dst_key: &PublicKey,
        packet: Vec<u8>,
    ) -> Result<(), String> {
        // Destination must be a local client
        let clients = self.clients.read();
        let client = clients
            .get(dst_key)
            .ok_or_else(|| format!("destination client {:?} not found locally", dst_key))?;

        let packet_size = packet.len();
        let frame = DerpFrame::RecvPacket {
            src_key: *src_key,
            packet,
        };

        client.send(frame)?;
        self.metrics.packet_relayed(packet_size);
        Ok(())
    }

    /// Relay a packet from one client to another (local or remote).
    pub fn relay_packet(
        &self,
        src_key: &PublicKey,
        dst_key: &PublicKey,
        packet: Vec<u8>,
    ) -> Result<(), String> {
        if !self.is_registered(src_key) && !self.is_remote_registered(src_key) {
            self.metrics.relay_failed("src_missing");
            return Err(format!("source client {:?} not registered", src_key));
        }

        let packet_size = packet.len();

        // Check if destination is local
        if let Some(client) = self.clients.read().get(dst_key) {
            let frame = DerpFrame::RecvPacket {
                src_key: *src_key,
                packet,
            };
            client.send(frame)?;
            self.metrics.packet_relayed(packet_size);
            return Ok(());
        }

        // Check if destination is remote (via mesh)
        if let Some(peer_key) = self.remote_clients.read().get(dst_key) {
            let peers = self.mesh_forwarders.read();
            if let Some(tx) = peers.get(peer_key) {
                let frame = DerpFrame::ForwardPacket {
                    src_key: *src_key,
                    dst_key: *dst_key,
                    packet,
                };
                tx.send(frame)
                    .map_err(|e| format!("failed to forward to mesh peer: {}", e))?;
                self.metrics.packet_relayed(packet_size);
                return Ok(());
            }
        }

        self.metrics.relay_failed("dst_missing");
        Err(format!("destination client {:?} not found", dst_key))
    }

    fn is_remote_registered(&self, key: &PublicKey) -> bool {
        self.remote_clients.read().contains_key(key)
    }

    /// Broadcast a frame to all connected clients.
    pub fn broadcast(&self, frame: DerpFrame) {
        let clients = self.clients.read();
        let count = clients.len();

        for client in clients.values() {
            if let Err(e) = client.send(frame.clone()) {
                tracing::warn!(
                    service = "derp",
                    client = ?client.public_key,
                    error = %e,
                    "Failed to broadcast frame"
                );
            }
        }

        tracing::debug!(
            service = "derp",
            recipients = count,
            frame_type = ?frame.frame_type(),
            "Broadcast frame"
        );
    }

    /// Broadcast peer presence to all other clients.
    pub fn broadcast_peer_present(&self, public_key: &PublicKey) {
        let frame = DerpFrame::PeerPresent {
            key: *public_key,
            endpoint: None,
            flags: 0,
        };
        let clients = self.clients.read();

        for client in clients.values() {
            // Don't send to the peer itself
            if client.public_key != *public_key {
                if let Err(e) = client.send(frame.clone()) {
                    tracing::warn!(
                        service = "derp",
                        client = ?client.public_key,
                        error = %e,
                        "Failed to notify peer present"
                    );
                }
            }
        }

        tracing::debug!(
            service = "derp",
            peer = ?public_key,
            "Broadcast peer present"
        );
    }

    /// Broadcast peer presence to all connected mesh peers.
    pub fn broadcast_peer_present_to_mesh_peers(&self, public_key: &PublicKey) {
        let frame = DerpFrame::PeerPresent {
            key: *public_key,
            endpoint: None,
            flags: 0,
        };
        self.broadcast_to_mesh_peers(frame);
    }

    /// Register a mesh peer as a watcher (after it sends `WatchConns`).
    pub fn register_mesh_watcher(&self, peer_key: PublicKey) -> Result<(), String> {
        if !self.mesh_peers.read().contains_key(&peer_key) {
            return Err(format!("mesh peer {:?} not registered", peer_key));
        }
        self.mesh_watchers.write().insert(peer_key);
        Ok(())
    }

    /// Unregister a mesh watcher.
    pub fn unregister_mesh_watcher(&self, peer_key: &PublicKey) {
        self.mesh_watchers.write().remove(peer_key);
    }

    /// Broadcast peer presence to subscribed mesh watchers only (Go `WatchConns` model).
    pub fn broadcast_peer_present_to_mesh_watchers(
        &self,
        public_key: &PublicKey,
        endpoint: Option<SocketAddr>,
        flags: u8,
    ) {
        let frame = DerpFrame::PeerPresent {
            key: *public_key,
            endpoint,
            flags,
        };
        self.broadcast_to_mesh_watchers(frame);
    }

    /// Broadcast peer departure to subscribed mesh watchers only (Go `WatchConns` model).
    pub fn broadcast_peer_gone_to_mesh_watchers(
        &self,
        public_key: &PublicKey,
        reason: PeerGoneReason,
    ) {
        let frame = DerpFrame::PeerGone {
            key: *public_key,
            reason,
        };
        self.broadcast_to_mesh_watchers(frame);
    }

    /// Broadcast peer departure to all other clients.
    pub fn broadcast_peer_gone(&self, public_key: &PublicKey) {
        let frame = DerpFrame::PeerGone {
            key: *public_key,
            reason: PeerGoneReason::Disconnected,
        };
        let clients = self.clients.read();

        for client in clients.values() {
            // Don't send to the peer itself (it's already disconnected)
            if client.public_key != *public_key {
                if let Err(e) = client.send(frame.clone()) {
                    tracing::warn!(
                        service = "derp",
                        client = ?client.public_key,
                        error = %e,
                        "Failed to notify peer gone"
                    );
                }
            }
        }

        tracing::debug!(
            service = "derp",
            peer = ?public_key,
            "Broadcast peer gone"
        );
    }

    /// Broadcast peer departure to all connected mesh peers.
    pub fn broadcast_peer_gone_to_mesh_peers(&self, public_key: &PublicKey) {
        let frame = DerpFrame::PeerGone {
            key: *public_key,
            reason: PeerGoneReason::Disconnected,
        };
        self.broadcast_to_mesh_peers(frame);
    }

    /// Send all currently connected local clients as PeerPresent frames to a specific mesh watcher.
    pub fn send_existing_clients_to_mesh_watcher(
        &self,
        peer_key: &PublicKey,
    ) -> Result<(), String> {
        use super::protocol::peer_present_flags;

        if !self.mesh_watchers.read().contains(peer_key) {
            return Ok(());
        }

        let tx = self
            .mesh_peers
            .read()
            .get(peer_key)
            .cloned()
            .ok_or_else(|| format!("mesh peer {:?} not registered", peer_key))?;

        let clients: Vec<ClientHandle> = self.clients.read().values().cloned().collect();
        for client in clients {
            tx.send(DerpFrame::PeerPresent {
                key: client.public_key,
                endpoint: Some(client.addr),
                flags: peer_present_flags::IS_REGULAR,
            })
            .map_err(|e| format!("failed to send PeerPresent to mesh peer: {}", e))?;
        }
        Ok(())
    }

    fn broadcast_to_mesh_watchers(&self, frame: DerpFrame) {
        let watchers: Vec<PublicKey> = self.mesh_watchers.read().iter().copied().collect();
        let peers = self.mesh_peers.read();

        for peer_key in watchers {
            if let Some(tx) = peers.get(&peer_key) {
                if let Err(e) = tx.send(frame.clone()) {
                    tracing::warn!(
                        service = "derp",
                        peer = ?peer_key,
                        error = %e,
                        "Failed to broadcast frame to mesh watcher"
                    );
                }
            }
        }
    }

    fn broadcast_to_mesh_peers(&self, frame: DerpFrame) {
        let peers = self.mesh_peers.read();
        let count = peers.len();

        for (peer_key, tx) in peers.iter() {
            if let Err(e) = tx.send(frame.clone()) {
                tracing::warn!(
                    service = "derp",
                    peer = ?peer_key,
                    error = %e,
                    "Failed to broadcast frame to mesh peer"
                );
            }
        }

        tracing::debug!(
            service = "derp",
            recipients = count,
            frame_type = ?frame.frame_type(),
            "Broadcast frame to mesh peers"
        );
    }

    /// Update last seen timestamp for a client.
    pub fn touch_client(&self, public_key: &PublicKey) {
        let mut clients = self.clients.write();
        if let Some(client) = clients.get_mut(public_key) {
            // Update in place - this is safe because we have a write lock
            // We need to recreate the value to update last_seen
            let updated = ClientHandle {
                public_key: client.public_key,
                addr: client.addr,
                tx: client.tx.clone(),
                last_seen: Instant::now(),
                connected_at: client.connected_at,
            };
            clients.insert(*public_key, updated);
        }
    }

    /// Remove stale clients (not seen for more than timeout).
    pub fn cleanup_stale_clients(&self, timeout: std::time::Duration) -> Vec<PublicKey> {
        let mut removed = Vec::new();
        let now = Instant::now();
        let mut lifetimes = Vec::new();
        let mut clients = self.clients.write();

        clients.retain(|key, client| {
            if now.duration_since(client.last_seen) > timeout {
                removed.push(*key);
                lifetimes.push(now.saturating_duration_since(client.connected_at));
                tracing::warn!(
                    service = "derp",
                    client = ?key,
                    idle_duration = ?now.duration_since(client.last_seen),
                    "Removing stale client"
                );
                false
            } else {
                true
            }
        });

        let active = clients.len();
        for lifetime in lifetimes {
            self.metrics.client_disconnected(active, lifetime);
        }
        self.metrics.set_active_clients(active);

        removed
    }

    /// Get metrics.
    pub fn metrics(&self) -> &DerpMetrics {
        &self.metrics
    }
}

impl Default for ClientRegistry {
    fn default() -> Self {
        Self::new("derp")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_registration() {
        let registry = ClientRegistry::new("test");
        let key = [1u8; 32];
        let addr: SocketAddr = "127.0.0.1:1234".parse().unwrap();
        let (tx, _rx) = mpsc::unbounded_channel();

        assert_eq!(registry.client_count(), 0);

        registry.register_client(key, addr, tx.clone()).unwrap();
        assert_eq!(registry.client_count(), 1);
        assert!(registry.is_registered(&key));

        // Duplicate registration should fail
        let result = registry.register_client(key, addr, tx);
        assert!(result.is_err());
    }

    #[test]
    fn test_client_unregistration() {
        let registry = ClientRegistry::new("test");
        let key = [2u8; 32];
        let addr: SocketAddr = "127.0.0.1:5678".parse().unwrap();
        let (tx, _rx) = mpsc::unbounded_channel();

        registry.register_client(key, addr, tx).unwrap();
        assert_eq!(registry.client_count(), 1);

        let removed_addr = registry.unregister_client(&key);
        assert_eq!(removed_addr, Some(addr));
        assert_eq!(registry.client_count(), 0);
        assert!(!registry.is_registered(&key));

        // Second unregister should return None
        assert_eq!(registry.unregister_client(&key), None);
    }

    #[test]
    fn test_list_clients() {
        let registry = ClientRegistry::new("test");
        let key1 = [3u8; 32];
        let key2 = [4u8; 32];
        let addr: SocketAddr = "127.0.0.1:9999".parse().unwrap();
        let (tx1, _rx1) = mpsc::unbounded_channel();
        let (tx2, _rx2) = mpsc::unbounded_channel();

        registry.register_client(key1, addr, tx1).unwrap();
        registry.register_client(key2, addr, tx2).unwrap();

        let clients = registry.list_clients();
        assert_eq!(clients.len(), 2);
        assert!(clients.contains(&key1));
        assert!(clients.contains(&key2));
    }

    #[tokio::test]
    async fn test_send_to_client() {
        let registry = ClientRegistry::new("test");
        let key = [5u8; 32];
        let addr: SocketAddr = "127.0.0.1:1111".parse().unwrap();
        let (tx, mut rx) = mpsc::unbounded_channel();

        registry.register_client(key, addr, tx).unwrap();

        let frame = DerpFrame::KeepAlive;
        registry.send_to_client(&key, frame.clone()).unwrap();

        let received = rx.recv().await.unwrap();
        assert_eq!(received, frame);
    }

    #[tokio::test]
    async fn test_relay_packet() {
        let registry = ClientRegistry::new("test");
        let src_key = [6u8; 32];
        let dst_key = [7u8; 32];
        let addr: SocketAddr = "127.0.0.1:2222".parse().unwrap();
        let (tx_src, _rx_src) = mpsc::unbounded_channel();
        let (tx_dst, mut rx_dst) = mpsc::unbounded_channel();

        registry.register_client(src_key, addr, tx_src).unwrap();
        registry.register_client(dst_key, addr, tx_dst).unwrap();

        let packet = vec![0xAA, 0xBB, 0xCC];
        registry
            .relay_packet(&src_key, &dst_key, packet.clone())
            .unwrap();

        let received = rx_dst.recv().await.unwrap();
        match received {
            DerpFrame::RecvPacket {
                src_key: recv_src,
                packet: recv_packet,
            } => {
                assert_eq!(recv_src, src_key);
                assert_eq!(recv_packet, packet);
            }
            _ => panic!("Expected RecvPacket frame"),
        }

        let (_, packets, bytes) = registry.metrics().get_stats();
        assert_eq!(packets, 1);
        assert_eq!(bytes, 3);
    }

    #[tokio::test]
    async fn test_broadcast_peer_notifications() {
        let registry = ClientRegistry::new("test");
        let new_peer = [8u8; 32];
        let existing1 = [9u8; 32];
        let existing2 = [10u8; 32];
        let addr: SocketAddr = "127.0.0.1:3333".parse().unwrap();

        let (tx_new, _rx_new) = mpsc::unbounded_channel();
        let (tx_ex1, mut rx_ex1) = mpsc::unbounded_channel();
        let (tx_ex2, mut rx_ex2) = mpsc::unbounded_channel();

        registry.register_client(existing1, addr, tx_ex1).unwrap();
        registry.register_client(existing2, addr, tx_ex2).unwrap();

        // Register new peer and broadcast presence
        registry.register_client(new_peer, addr, tx_new).unwrap();
        registry.broadcast_peer_present(&new_peer);

        // Both existing clients should receive PeerPresent
        let frame1 = rx_ex1.recv().await.unwrap();
        assert!(matches!(frame1, DerpFrame::PeerPresent { key, .. } if key == new_peer));

        let frame2 = rx_ex2.recv().await.unwrap();
        assert!(matches!(frame2, DerpFrame::PeerPresent { key, .. } if key == new_peer));

        // Unregister and broadcast gone
        registry.unregister_client(&new_peer);
        registry.broadcast_peer_gone(&new_peer);

        let gone1 = rx_ex1.recv().await.unwrap();
        assert!(matches!(gone1, DerpFrame::PeerGone { key, .. } if key == new_peer));

        let gone2 = rx_ex2.recv().await.unwrap();
        assert!(matches!(gone2, DerpFrame::PeerGone { key, .. } if key == new_peer));
    }

    #[test]
    fn test_stale_client_cleanup() {
        let registry = ClientRegistry::new("test");
        let key = [11u8; 32];
        let addr: SocketAddr = "127.0.0.1:4444".parse().unwrap();
        let (tx, _rx) = mpsc::unbounded_channel();

        registry.register_client(key, addr, tx).unwrap();
        assert_eq!(registry.client_count(), 1);

        // Cleanup with short timeout shouldn't remove fresh client
        let removed = registry.cleanup_stale_clients(std::time::Duration::from_secs(10));
        assert_eq!(removed.len(), 0);
        assert_eq!(registry.client_count(), 1);

        // Cleanup with zero timeout should remove all clients
        let removed = registry.cleanup_stale_clients(std::time::Duration::ZERO);
        assert_eq!(removed.len(), 1);
        assert_eq!(removed[0], key);
        assert_eq!(registry.client_count(), 0);
    }
}
