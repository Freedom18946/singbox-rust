#![cfg(all(feature = "handshake_alpha", feature = "io_local_alpha"))]
use sb_runtime::prelude::*;
use sb_runtime::tcp_local;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use tempfile::tempdir;
#[tokio::test]
async fn chaos_injection_basic() {
    let hs = trojan::Trojan::new("example.com".into(), 443);
    let dir = tempdir().unwrap();
    let p = dir.path().join("hs.session.chaos.jsonl");
    let bind = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
    let echo = tcp_local::spawn_echo_once(bind, Some(0xAA)).await.unwrap();
    let chaos = tcp_local::ChaosSpec {
        delay_tx_ms: 5,
        delay_rx_ms: 5,
        rx_drop: 2,
        rx_trim: Some(16),
        rx_xor: Some(0x55),
    };
    let (tx, rx) = tcp_local::io_local_once(&hs, echo, 42, &p, 64, 200, Some(chaos))
        .await
        .unwrap();
    assert!(tx > 0 && rx <= 16);
}
