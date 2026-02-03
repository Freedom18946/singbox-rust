use sb_core::net::datagram::{UdpNatKey, UdpNatMap, UdpTargetAddr};
use std::sync::Arc;

async fn bind_or_skip(addr: &str) -> Option<Arc<tokio::net::UdpSocket>> {
    match tokio::net::UdpSocket::bind(addr).await {
        Ok(sock) => Some(Arc::new(sock)),
        Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => {
            eprintln!("skip: permission denied binding udp socket {addr}: {err}");
            None
        }
        Err(err) => {
            panic!("failed to bind udp socket {addr}: {err}");
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn nat_capacity_and_ttl() {
    // capacity = 2
    std::env::set_var("SB_UDP_NAT_MAX", "2");
    let map = Arc::new(UdpNatMap::new(None));
    // dummy sockets
    let s1 = match bind_or_skip("127.0.0.1:0").await {
        Some(sock) => sock,
        None => return,
    };
    let s2 = match bind_or_skip("127.0.0.1:0").await {
        Some(sock) => sock,
        None => return,
    };
    let s3 = match bind_or_skip("127.0.0.1:0").await {
        Some(sock) => sock,
        None => return,
    };
    let k1 = UdpNatKey {
        client: "127.0.0.1:10001".parse().unwrap(),
        dst: UdpTargetAddr::Ip("127.0.0.1:7".parse().unwrap()),
    };
    let k2 = UdpNatKey {
        client: "127.0.0.1:10002".parse().unwrap(),
        dst: UdpTargetAddr::Ip("127.0.0.1:7".parse().unwrap()),
    };
    let k3 = UdpNatKey {
        client: "127.0.0.1:10003".parse().unwrap(),
        dst: UdpTargetAddr::Ip("127.0.0.1:7".parse().unwrap()),
    };
    assert!(map.upsert_guarded(k1.clone(), s1).await);
    assert!(map.upsert_guarded(k2.clone(), s2).await);
    assert!(!map.upsert_guarded(k3.clone(), s3.clone()).await);
    // ttl expire then can insert again
    let ttl = std::time::Duration::from_millis(100);
    tokio::time::sleep(ttl + std::time::Duration::from_millis(20)).await;
    let _ = map.purge_expired(ttl).await;
    assert!(map.upsert_guarded(k3, s3).await);
}
