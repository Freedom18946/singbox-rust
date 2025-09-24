use sb_core::net::datagram::{UdpNatKey, UdpNatMap, UdpTargetAddr};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;

#[tokio::test]
async fn evict_by_ttl() {
    let ttl = Duration::from_millis(30);
    let nat = UdpNatMap::new(Some(ttl));
    let k = UdpNatKey {
        client: "127.0.0.1:55555".parse::<SocketAddr>().unwrap(),
        dst: UdpTargetAddr::Ip("1.1.1.1:53".parse().unwrap()),
    };
    let socket = Arc::new(UdpSocket::bind(("0.0.0.0", 0)).await.unwrap());
    nat.upsert(k.clone(), socket).await;

    // Verify it was inserted
    assert!(nat.get(&k).await.is_some());

    tokio::time::sleep(Duration::from_millis(50)).await;
    let removed = nat.purge_expired(ttl).await;
    assert!(removed >= 1);
}

#[tokio::test]
async fn capacity_limit() {
    // Set a very small capacity for testing
    std::env::set_var("SB_UDP_NAT_MAX", "2");

    let nat = UdpNatMap::new(Duration::from_secs(60));

    // Insert first entry
    let k1 = UdpNatKey {
        client: "127.0.0.1:55555".parse::<SocketAddr>().unwrap(),
        dst: UdpTargetAddr::Ip("1.1.1.1:53".parse().unwrap()),
    };
    let v1 = Arc::new(UdpSocket::bind(("0.0.0.0", 0)).await.unwrap());
    assert!(nat.upsert_guarded(k1, v1).await);

    // Insert second entry
    let k2 = UdpNatKey {
        client: "127.0.0.1:55556".parse::<SocketAddr>().unwrap(),
        dst: UdpTargetAddr::Ip("1.1.1.1:53".parse().unwrap()),
    };
    let v2 = Arc::new(UdpSocket::bind(("0.0.0.0", 0)).await.unwrap());
    assert!(nat.upsert_guarded(k2, v2).await);

    // Third entry should be rejected due to capacity limit
    let k3 = UdpNatKey {
        client: "127.0.0.1:55557".parse::<SocketAddr>().unwrap(),
        dst: UdpTargetAddr::Ip("1.1.1.1:53".parse().unwrap()),
    };
    let v3 = Arc::new(UdpSocket::bind(("0.0.0.0", 0)).await.unwrap());
    assert!(!nat.upsert_guarded(k3, v3).await);

    // Clean up
    std::env::remove_var("SB_UDP_NAT_MAX");
}
