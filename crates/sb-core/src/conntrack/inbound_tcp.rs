use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use tokio_util::sync::CancellationToken;

use crate::net::metered::TrafficRecorder;

/// Guard that unregisters a connection from the global tracker on drop.
///
/// This is intentionally best-effort and idempotent: if the connection has
/// already been removed (e.g. via API close), drop does nothing.
#[derive(Debug)]
pub struct ConntrackGuard {
    id: sb_common::conntrack::ConnId,
}

impl ConntrackGuard {
    pub fn id(&self) -> sb_common::conntrack::ConnId {
        self.id
    }
}

impl Drop for ConntrackGuard {
    fn drop(&mut self) {
        // Best-effort cleanup: totals are accounted on unregister().
        let tracker = sb_common::conntrack::global_tracker();
        let _ = tracker.unregister(self.id);
    }
}

/// Wiring result for integrating conntrack into an inbound TCP copy loop.
pub struct ConntrackWiring {
    pub guard: ConntrackGuard,
    pub cancel: CancellationToken,
    pub traffic: Arc<dyn TrafficRecorder>,
}

struct CompositeTrafficRecorder {
    upload: Arc<std::sync::atomic::AtomicU64>,
    download: Arc<std::sync::atomic::AtomicU64>,
    inner: Option<Arc<dyn TrafficRecorder>>,
}

impl TrafficRecorder for CompositeTrafficRecorder {
    fn record_up(&self, bytes: u64) {
        self.upload.fetch_add(bytes, Ordering::Relaxed);
        if let Some(inner) = &self.inner {
            inner.record_up(bytes);
        }
    }

    fn record_down(&self, bytes: u64) {
        self.download.fetch_add(bytes, Ordering::Relaxed);
        if let Some(inner) = &self.inner {
            inner.record_down(bytes);
        }
    }

    fn record_up_packet(&self, packets: u64) {
        if let Some(inner) = &self.inner {
            inner.record_up_packet(packets);
        }
    }

    fn record_down_packet(&self, packets: u64) {
        if let Some(inner) = &self.inner {
            inner.record_down_packet(packets);
        }
    }
}

/// Shared implementation for inbound conntrack wiring (TCP/UDP).
#[allow(clippy::too_many_arguments)]
pub(crate) fn register_inbound(
    network: sb_common::conntrack::Network,
    source: SocketAddr,
    destination_host: String,
    destination_port: u16,
    host_for_display: String,
    inbound_type: &'static str,
    inbound_tag: Option<String>,
    outbound_tag: Option<String>,
    chains: Vec<String>,
    rule: Option<String>,
    process_name: Option<String>,
    process_path: Option<String>,
    inner_traffic: Option<Arc<dyn TrafficRecorder>>,
) -> ConntrackWiring {
    let tracker = sb_common::conntrack::global_tracker();
    let tracker_id = tracker.next_id();

    let mut meta = sb_common::conntrack::ConnMetadata::new(
        tracker_id,
        network,
        source,
        destination_host,
        destination_port,
    )
    .with_host(host_for_display)
    .with_inbound_type(inbound_type.to_string())
    .with_inbound_tag(inbound_tag.unwrap_or_else(|| inbound_type.to_string()))
    .with_outbound_tag(outbound_tag.unwrap_or_else(|| "unresolved".to_string()))
    .with_chains(chains);

    if let Some(rule) = rule {
        meta = meta.with_rule(rule);
    }
    if let Some(name) = process_name {
        meta.process_name = Some(name);
    }
    if let Some(path) = process_path {
        meta.process_path = Some(path);
    }

    let handle = tracker.register(meta);

    let traffic = Arc::new(CompositeTrafficRecorder {
        upload: handle.upload_bytes.clone(),
        download: handle.download_bytes.clone(),
        inner: inner_traffic,
    });

    ConntrackWiring {
        guard: ConntrackGuard { id: tracker_id },
        cancel: handle.cancel.clone(),
        traffic,
    }
}

/// Register a TCP connection into the global conntrack and return cancel + traffic wiring.
///
/// - `inner_traffic`: optional existing recorder (e.g. V2Ray stats); we will forward
///   record_up/down into it while also incrementing conntrack counters.
#[allow(clippy::too_many_arguments)]
pub fn register_inbound_tcp(
    source: SocketAddr,
    destination_host: String,
    destination_port: u16,
    host_for_display: String,
    inbound_type: &'static str,
    inbound_tag: Option<String>,
    outbound_tag: Option<String>,
    chains: Vec<String>,
    rule: Option<String>,
    process_name: Option<String>,
    process_path: Option<String>,
    inner_traffic: Option<Arc<dyn TrafficRecorder>>,
) -> ConntrackWiring {
    register_inbound(
        sb_common::conntrack::Network::Tcp,
        source,
        destination_host,
        destination_port,
        host_for_display,
        inbound_type,
        inbound_tag,
        outbound_tag,
        chains,
        rule,
        process_name,
        process_path,
        inner_traffic,
    )
}
