use sb_common::conntrack::{global_tracker, ConnMetadata, Network};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

#[test]
fn build_connections_snapshot_includes_rule_and_chains() {
    let tracker = global_tracker();
    let _ = tracker.close_all();

    let tcp_id = tracker.next_id();
    let tcp_meta = ConnMetadata::new(
        tcp_id,
        Network::Tcp,
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 12345),
        "example.com".to_string(),
        443,
    )
    .with_host("example.com".to_string())
    .with_inbound_type("http".to_string())
    .with_inbound_tag("test-in".to_string())
    .with_outbound_tag("direct".to_string())
    .with_rule("final".to_string())
    .with_chains(vec!["DIRECT".to_string()]);

    let handle = tracker.register(tcp_meta);
    handle.add_upload(100);
    handle.add_download(200);

    let udp_id = tracker.next_id();
    let udp_meta = ConnMetadata::new(
        udp_id,
        Network::Udp,
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 23456),
        "example.net".to_string(),
        53,
    )
    .with_host("example.net".to_string())
    .with_inbound_type("dns".to_string())
    .with_inbound_tag("test-in".to_string())
    .with_outbound_tag("direct".to_string())
    .with_rule("final".to_string())
    .with_chains(vec!["DIRECT".to_string()]);
    tracker.register(udp_meta);

    let snapshot = sb_api::clash::websocket::build_connections_snapshot();
    let conns = snapshot
        .get("connections")
        .and_then(|v| v.as_array())
        .expect("connections array");

    let tcp_id_str = tcp_id.as_u64().to_string();
    let c = conns
        .iter()
        .find(|v| v.get("id").and_then(|x| x.as_str()) == Some(tcp_id_str.as_str()))
        .expect("tcp connection present");

    let chains = c.get("chains").and_then(|v| v.as_array()).expect("chains");
    assert!(!chains.is_empty());
    assert_eq!(
        c.get("rule").and_then(|v| v.as_str()).unwrap_or(""),
        "final"
    );

    let udp_id_str = udp_id.as_u64().to_string();
    let c_udp = conns
        .iter()
        .find(|v| v.get("id").and_then(|x| x.as_str()) == Some(udp_id_str.as_str()))
        .expect("udp connection present");
    let chains_udp = c_udp
        .get("chains")
        .and_then(|v| v.as_array())
        .expect("udp chains");
    assert!(!chains_udp.is_empty());
    assert_eq!(
        c_udp.get("rule").and_then(|v| v.as_str()).unwrap_or(""),
        "final"
    );

    tracker.close(tcp_id);
    tracker.close(udp_id);
}
