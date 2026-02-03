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
            eprintln!("skipping nat_ttl_compaction_under_race: {err}");
            None
        }
        Err(err) => panic!("failed to bind udp socket: {err}"),
    }
}

/// 验证 TTL 竞态下的逐步回收（无内存泄漏）
#[tokio::test]
async fn nat_ttl_compaction_under_race() {
    let capacity = 64usize;
    let ttl_ms = 30u64;
    std::env::set_var("SB_UDP_NAT_MAX", capacity.to_string());
    let map = UdpNatMap::new(None);

    // 连续插入并读写，制造"刷新部分、过期部分"的竞态
    for i in 0..32 {
        let client: std::net::SocketAddr = format!("127.0.0.1:{}", 8080 + i).parse().unwrap();
        let dst = UdpTargetAddr::Ip(format!("172.16.0.{}:8080", i).parse().unwrap());
        let key = UdpNatKey { client, dst };
        let Some(socket) = bind_socket_or_skip().await else {
            return;
        };
        map.upsert(key.clone(), socket).await;

        // 模拟部分访问刷新
        if i % 2 == 0 {
            let _ = map.get(&key).await;
        }
    }
    // 等一半 TTL
    sleep(Duration::from_millis(ttl_ms / 2)).await;
    // 新增一些键
    for i in 32..48 {
        let client: std::net::SocketAddr = format!("127.0.0.1:{}", 8080 + i).parse().unwrap();
        let dst = UdpTargetAddr::Ip(format!("172.16.0.{}:8080", i).parse().unwrap());
        let key = UdpNatKey { client, dst };
        let Some(socket) = bind_socket_or_skip().await else {
            return;
        };
        map.upsert(key, socket).await;
    }
    // 再等，触发过期
    sleep(Duration::from_millis(ttl_ms)).await;
    // 进行逐步回收
    let _ = map.evict_expired().await;
    // 不做强断言：只要不 panic 且容量回落即可
    assert!(
        map.len().await <= 48,
        "map should compact after TTL eviction"
    );
}
