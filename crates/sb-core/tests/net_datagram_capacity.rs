use sb_core::net::datagram::{UdpNatKey, UdpNatMap, UdpTargetAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::sleep;

fn is_permission_denied(err: &std::io::Error) -> bool {
    err.kind() == std::io::ErrorKind::PermissionDenied
        || err
            .to_string()
            .to_lowercase()
            .contains("operation not permitted")
}

async fn bind_socket_or_skip() -> Option<Arc<UdpSocket>> {
    match UdpSocket::bind("127.0.0.1:0").await {
        Ok(socket) => Some(Arc::new(socket)),
        Err(err) if is_permission_denied(&err) => {
            eprintln!("skipping nat_capacity_evicts_and_counts: {err}");
            None
        }
        Err(err) => panic!("failed to bind udp socket: {err}"),
    }
}

/// 验证 NAT 表容量触顶后的拒绝计数与回落清理
#[tokio::test]
async fn nat_capacity_evicts_and_counts() {
    // 小容量与短 TTL
    std::env::set_var("SB_UDP_NAT_MAX", "4");

    let capacity = 4usize;
    let ttl_ms = 50u64;
    let map = UdpNatMap::new(None);

    // 塞满
    for i in 0..capacity {
        let client: std::net::SocketAddr = format!("127.0.0.1:{}", 12345 + i).parse().unwrap();
        let dst = UdpTargetAddr::Ip(format!("10.0.0.{}:12345", i).parse().unwrap());
        let key = UdpNatKey { client, dst };
        let Some(socket) = bind_socket_or_skip().await else {
            return;
        };
        let result = map.upsert_guarded(key, socket).await;
        assert!(result, "should accept within capacity");
    }

    // 再放入触发拒绝
    let client: std::net::SocketAddr = "127.0.0.1:12346".parse().unwrap();
    let dst = UdpTargetAddr::Ip("10.0.0.99:12345".parse().unwrap());
    let key = UdpNatKey { client, dst };
    let Some(socket) = bind_socket_or_skip().await else {
        return;
    };
    let rejected = map.upsert_guarded(key, socket).await;
    assert!(!rejected, "expect capacity rejection");

    // 等 TTL 过期并清理
    sleep(Duration::from_millis(ttl_ms + 20)).await;
    let removed = map.purge_expired(Duration::from_millis(ttl_ms)).await;
    assert!(removed > 0, "expired entries should be purged");
}
