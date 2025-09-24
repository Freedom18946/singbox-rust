use sb_core::net::datagram::{UdpNatKey, UdpNatMap, UdpTargetAddr};
use std::sync::Arc;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn nat_capacity_and_ttl() {
    // capacity = 2
    std::env::set_var("SB_UDP_NAT_MAX", "2");
    let map = Arc::new(UdpNatMap::new(None));
    // dummy sockets
    let s1 = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let s2 = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let s3 = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
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
