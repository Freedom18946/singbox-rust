use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

#[tokio::test]
async fn conntrack_wiring_udp_counts_and_cancel_work() {
    let tracker = sb_common::conntrack::global_tracker();
    let _ = tracker.close_all();

    let source = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 12345);
    let wiring = sb_core::conntrack::register_inbound_udp(
        source,
        "example.com".to_string(),
        53,
        "example.com".to_string(),
        "test-udp",
        Some("test-in".to_string()),
        Some("direct".to_string()),
        vec!["DIRECT".to_string()],
        Some("final".to_string()),
        None,
        None,
        None,
    );
    let id = wiring.guard.id();

    let cancel = wiring.cancel.clone();
    let traffic = wiring.traffic.clone();
    let _guard = wiring.guard;

    // Simulate traffic accounting
    traffic.record_up(10);
    traffic.record_up_packet(1);
    traffic.record_down(20);
    traffic.record_down_packet(1);

    tokio::time::sleep(Duration::from_millis(20)).await;

    let meta = tracker.get(id).expect("meta exists");
    assert!(meta.get_upload() >= 10);
    assert!(meta.get_download() >= 20);

    let waiter = tokio::spawn(async move {
        cancel.cancelled().await;
    });

    assert!(tracker.close(id));
    waiter.await.unwrap();
    assert!(tracker.get(id).is_none());
}
