//! Connection tracking module for monitoring active connections.
//! 连接跟踪模块，用于监控活动连接。
//!
//! Provides functionality to track TCP/UDP connections, their metadata,
//! and statistics like bytes transferred and connection duration.

use dashmap::DashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio_util::sync::CancellationToken;

/// Unique identifier for a tracked connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ConnId(u64);

impl ConnId {
    /// Create a new connection ID.
    pub fn new(id: u64) -> Self {
        Self(id)
    }

    /// Get the raw ID value.
    pub fn as_u64(&self) -> u64 {
        self.0
    }
}

/// Network protocol type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Network {
    /// TCP protocol.
    Tcp,
    /// UDP protocol.
    Udp,
}

impl Network {
    /// Get the protocol name as a static string.
    pub fn as_str(&self) -> &'static str {
        match self {
            Network::Tcp => "tcp",
            Network::Udp => "udp",
        }
    }
}

/// Metadata about a tracked connection.
#[derive(Debug, Clone)]
pub struct ConnMetadata {
    /// Unique connection ID.
    pub id: ConnId,
    /// Network protocol (TCP/UDP).
    pub network: Network,
    /// Source address (client).
    pub source: SocketAddr,
    /// Destination address (target).
    pub destination: String,
    /// Destination port.
    pub destination_port: u16,
    /// Inbound adapter tag.
    pub inbound_tag: Option<String>,
    /// Outbound adapter tag.
    pub outbound_tag: Option<String>,
    /// Connection start time.
    pub start_time: Instant,
    /// Process name (if detected).
    pub process_name: Option<String>,
    /// Process path (if detected).
    pub process_path: Option<String>,
    /// Bytes uploaded (client -> server).
    pub upload_bytes: Arc<AtomicU64>,
    /// Bytes downloaded (server -> client).
    pub download_bytes: Arc<AtomicU64>,
    /// Host/domain name (SNI or CONNECT host).
    pub host: Option<String>,
    /// Matched routing rule description.
    pub rule: Option<String>,
    /// Proxy chain (reversed: leaf → ... → matched outbound).
    pub chains: Vec<String>,
    /// Inbound type string (e.g., "mixed", "http", "socks5").
    pub inbound_type: Option<String>,
    /// Cancellation token for closing the connection.
    pub cancel: CancellationToken,
}

impl ConnMetadata {
    /// Create new connection metadata.
    pub fn new(
        id: ConnId,
        network: Network,
        source: SocketAddr,
        destination: String,
        destination_port: u16,
    ) -> Self {
        Self {
            id,
            network,
            source,
            destination,
            destination_port,
            inbound_tag: None,
            outbound_tag: None,
            start_time: Instant::now(),
            process_name: None,
            process_path: None,
            upload_bytes: Arc::new(AtomicU64::new(0)),
            download_bytes: Arc::new(AtomicU64::new(0)),
            host: None,
            rule: None,
            chains: vec![],
            inbound_type: None,
            cancel: CancellationToken::new(),
        }
    }

    /// Set host/domain name.
    pub fn with_host(mut self, host: String) -> Self {
        self.host = Some(host);
        self
    }

    /// Set matched routing rule.
    pub fn with_rule(mut self, rule: String) -> Self {
        self.rule = Some(rule);
        self
    }

    /// Set proxy chain.
    pub fn with_chains(mut self, chains: Vec<String>) -> Self {
        self.chains = chains;
        self
    }

    /// Set inbound type string.
    pub fn with_inbound_type(mut self, t: String) -> Self {
        self.inbound_type = Some(t);
        self
    }

    /// Set inbound adapter tag.
    pub fn with_inbound_tag(mut self, tag: String) -> Self {
        self.inbound_tag = Some(tag);
        self
    }

    /// Set outbound adapter tag.
    pub fn with_outbound_tag(mut self, tag: String) -> Self {
        self.outbound_tag = Some(tag);
        self
    }

    /// Add uploaded bytes.
    pub fn add_upload(&self, bytes: u64) {
        self.upload_bytes.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Add downloaded bytes.
    pub fn add_download(&self, bytes: u64) {
        self.download_bytes.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Get total uploaded bytes.
    pub fn get_upload(&self) -> u64 {
        self.upload_bytes.load(Ordering::Relaxed)
    }

    /// Get total downloaded bytes.
    pub fn get_download(&self) -> u64 {
        self.download_bytes.load(Ordering::Relaxed)
    }

    /// Get connection duration.
    pub fn duration(&self) -> Duration {
        self.start_time.elapsed()
    }
}

/// Connection tracker for monitoring active connections.
#[derive(Debug)]
pub struct ConnTracker {
    /// Active connections indexed by ID.
    connections: DashMap<ConnId, Arc<ConnMetadata>>,
    /// Next connection ID.
    next_id: AtomicU64,
    /// Total connections ever created.
    total_connections: AtomicU64,
    /// Total bytes uploaded.
    total_upload: AtomicU64,
    /// Total bytes downloaded.
    total_download: AtomicU64,
}

impl Default for ConnTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl ConnTracker {
    /// Create a new connection tracker.
    pub fn new() -> Self {
        Self {
            connections: DashMap::new(),
            next_id: AtomicU64::new(1),
            total_connections: AtomicU64::new(0),
            total_upload: AtomicU64::new(0),
            total_download: AtomicU64::new(0),
        }
    }

    /// Generate a new unique connection ID.
    pub fn next_id(&self) -> ConnId {
        ConnId(self.next_id.fetch_add(1, Ordering::Relaxed))
    }

    /// Register a new connection.
    pub fn register(&self, metadata: ConnMetadata) -> Arc<ConnMetadata> {
        let id = metadata.id;
        let arc = Arc::new(metadata);
        self.connections.insert(id, arc.clone());
        self.total_connections.fetch_add(1, Ordering::Relaxed);
        tracing::debug!(id = %id.as_u64(), "Connection registered");
        arc
    }

    /// Unregister a connection and update totals.
    pub fn unregister(&self, id: ConnId) -> Option<Arc<ConnMetadata>> {
        if let Some((_, meta)) = self.connections.remove(&id) {
            let upload = meta.get_upload();
            let download = meta.get_download();
            self.total_upload.fetch_add(upload, Ordering::Relaxed);
            self.total_download.fetch_add(download, Ordering::Relaxed);
            tracing::debug!(
                id = %id.as_u64(),
                upload = upload,
                download = download,
                duration_ms = meta.duration().as_millis(),
                "Connection unregistered"
            );
            Some(meta)
        } else {
            None
        }
    }

    /// Get a connection by ID.
    pub fn get(&self, id: ConnId) -> Option<Arc<ConnMetadata>> {
        self.connections.get(&id).map(|r| r.value().clone())
    }

    /// Get the number of active connections.
    pub fn active_count(&self) -> usize {
        self.connections.len()
    }

    /// Get total connections ever created.
    pub fn total_count(&self) -> u64 {
        self.total_connections.load(Ordering::Relaxed)
    }

    /// Get total bytes uploaded across all connections.
    pub fn total_upload(&self) -> u64 {
        // Sum active + completed
        let active: u64 = self
            .connections
            .iter()
            .map(|r| r.value().get_upload())
            .sum();
        self.total_upload.load(Ordering::Relaxed) + active
    }

    /// Get total bytes downloaded across all connections.
    pub fn total_download(&self) -> u64 {
        let active: u64 = self
            .connections
            .iter()
            .map(|r| r.value().get_download())
            .sum();
        self.total_download.load(Ordering::Relaxed) + active
    }

    /// List all active connections.
    pub fn list(&self) -> Vec<Arc<ConnMetadata>> {
        self.connections.iter().map(|r| r.value().clone()).collect()
    }

    /// Close a connection by ID (cancels token and removes from tracker).
    pub fn close(&self, id: ConnId) -> bool {
        if let Some(meta) = self.get(id) {
            meta.cancel.cancel();
        }
        self.unregister(id).is_some()
    }

    /// Close all connections.
    pub fn close_all(&self) -> usize {
        let ids: Vec<ConnId> = self.connections.iter().map(|r| *r.key()).collect();
        let count = ids.len();
        for id in ids {
            if let Some(meta) = self.get(id) {
                meta.cancel.cancel();
            }
            self.unregister(id);
        }
        count
    }
}

/// Global connection tracker instance.
static GLOBAL_TRACKER: std::sync::OnceLock<ConnTracker> = std::sync::OnceLock::new();

/// Get the global connection tracker.
pub fn global_tracker() -> &'static ConnTracker {
    GLOBAL_TRACKER.get_or_init(ConnTracker::new)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn test_connection_tracking() {
        let tracker = ConnTracker::new();

        let id = tracker.next_id();
        let source = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 12345);
        let mut meta = ConnMetadata::new(id, Network::Tcp, source, "example.com".to_string(), 443);
        meta.inbound_tag = Some("http".to_string());
        meta.outbound_tag = Some("proxy".to_string());

        let conn = tracker.register(meta);
        assert_eq!(tracker.active_count(), 1);

        conn.add_upload(100);
        conn.add_download(200);

        assert_eq!(conn.get_upload(), 100);
        assert_eq!(conn.get_download(), 200);

        tracker.unregister(id);
        assert_eq!(tracker.active_count(), 0);
        assert_eq!(tracker.total_upload(), 100);
        assert_eq!(tracker.total_download(), 200);
    }

    #[test]
    fn test_global_tracker() {
        let tracker = global_tracker();
        let initial = tracker.total_count();

        let id = tracker.next_id();
        let source = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 54321);
        let meta = ConnMetadata::new(id, Network::Udp, source, "dns.google".to_string(), 53);

        tracker.register(meta);
        assert_eq!(tracker.total_count(), initial + 1);
        tracker.close(id);
    }
}
