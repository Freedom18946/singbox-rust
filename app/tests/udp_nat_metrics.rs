use sb_core::udp_nat_instrument::{UdpNatTable, UpstreamFail};
use sb_metrics::registry::global as M;
use std::net::SocketAddr;
use std::str::FromStr;
use std::time::Duration;

#[test]
fn nat_metrics_update() {
    let t = UdpNatTable::new(4);
    let s: SocketAddr = "127.0.0.1:10001".parse().unwrap();
    let u: SocketAddr = "8.8.8.8:53".parse().unwrap();
    t.insert(s, u, Duration::from_millis(1));
    std::thread::sleep(Duration::from_millis(2));
    t.evict_expired();
    assert!(M().udp_evict_total.snapshot().len() >= 1);
    t.upstream_fail(UpstreamFail::Timeout);
}
