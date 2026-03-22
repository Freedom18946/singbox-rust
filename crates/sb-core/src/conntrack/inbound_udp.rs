use std::net::SocketAddr;
use std::sync::Arc;

use crate::net::metered::TrafficRecorder;

/// Register a UDP connection into a local default conntrack and return cancel + traffic wiring.
///
/// - `inner_traffic`: optional existing recorder (e.g. V2Ray stats); we will forward
///   record_up/down into it while also incrementing conntrack counters.
#[allow(clippy::too_many_arguments)]
pub fn register_inbound_udp(
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
) -> super::inbound_tcp::ConntrackWiring {
    register_inbound_udp_with_tracker(
        Arc::new(sb_common::conntrack::ConnTracker::new()),
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

/// Register a UDP connection into the provided conntrack and return cancel + traffic wiring.
#[allow(clippy::too_many_arguments)]
pub fn register_inbound_udp_with_tracker(
    tracker: Arc<sb_common::conntrack::ConnTracker>,
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
) -> super::inbound_tcp::ConntrackWiring {
    super::inbound_tcp::register_inbound(
        tracker,
        sb_common::conntrack::Network::Udp,
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
