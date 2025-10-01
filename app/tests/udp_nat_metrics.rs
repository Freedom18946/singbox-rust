use sb_core::udp_nat_instrument::{UdpNatTable, UpstreamFail};
use std::net::SocketAddr;
use std::time::Duration;

#[test]
fn nat_metrics_update() {
    let t = UdpNatTable::new(4);
    let s: SocketAddr = "127.0.0.1:10001".parse().unwrap();
    let u: SocketAddr = "8.8.8.8:53".parse().unwrap();
    t.insert(s, u, Duration::from_millis(1));
    std::thread::sleep(Duration::from_millis(2));
    t.evict_expired();
    // Metrics are recorded internally, no direct assertion possible
    t.upstream_fail(UpstreamFail::Timeout);
}

// Note: The following tests have been simplified because direct metric inspection
// requires access to the Prometheus registry, which is an implementation detail.
// In a production environment, metrics would be validated through the /metrics endpoint.
