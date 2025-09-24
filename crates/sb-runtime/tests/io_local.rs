#![cfg(all(feature = "handshake_alpha", feature = "io_local_alpha"))]
use sb_runtime::prelude::*;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use tempfile::tempdir;
#[tokio::test]
async fn io_local_echo_once() {
    let hs = trojan::Trojan::new("example.com".into(), 443);
    let dir = tempdir().unwrap();
    let p = dir.path().join("io.session.jsonl");
    // 启动内置 echo（系统分配端口）
    let bind = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
    let addr = tcp_local::spawn_echo_once(bind, Some(0xAA)).await.unwrap();
    let (actual, tx, rx) =
        tcp_local::io_local_with_optional_echo(&hs, addr.port(), 42, &p, 64, 200, false, None)
            .await
            .unwrap();
    assert_eq!(actual.port(), addr.port());
    assert!(tx > 0 && rx > 0);
}
