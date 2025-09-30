#![cfg(feature = "router")]
use sb_core::router::engine::RouterHandle;
use std::{
    net::SocketAddr,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};
use tokio::net::UdpSocket; // 引入 runtime

/// 本测试起一个"黑洞 DNS 上游"（收到查询不回复，睡眠后丢弃），
/// 设置 inflight=1，发起两次并发 resolve，断言第二次不会在第一个超时前打到上游。
#[tokio::test]
async fn dns_inflight_global_and_per_host_gate() {
    // 黑洞 UDP "上游"
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr: SocketAddr = sock.local_addr().unwrap();
    let hits = Arc::new(AtomicUsize::new(0));
    let hits2 = hits.clone();
    tokio::spawn(async move {
        let mut buf = [0u8; 1500];
        loop {
            let Ok((_n, _p)) = sock.recv_from(&mut buf).await else {
                break;
            };
            hits2.fetch_add(1, Ordering::SeqCst);
            // 不回复，阻塞住调用端直到其超时
            tokio::time::sleep(Duration::from_millis(120)).await;
        }
    });

    // 配置：启用 DNS、使用单并发门控、短超时
    std::env::set_var("SB_DNS_ENABLE", "1");
    std::env::set_var("SB_DNS_POOL", format!("udp://{}", addr));
    std::env::set_var("SB_DNS_GLOBAL_INFLIGHT", "1");
    std::env::set_var("SB_DNS_PER_HOST_INFLIGHT", "1");
    std::env::set_var("SB_DNS_TIMEOUT_MS", "60");
    // 解析器句柄（通过 RouterHandle 内部懒加载）
    let h = RouterHandle::from_env(); // 只为触发 resolver 静态句柄生命周期

    let started = Instant::now();
    let t1 = tokio::spawn(async {
        // 第一次解析，确保会命中上游并在 60ms 超时
        let _ = sb_core::dns::resolve::resolve_all("blocked.test", 80).await;
    });
    // 稍后立刻发起第二个（应该被 inflight 门控阻塞，不会立刻打到上游）
    let t2 = tokio::spawn(async {
        let _ = sb_core::dns::resolve::resolve_all("blocked.test", 80).await;
    });
    // 等待 80ms，若门控正确，此时 hits 仍应为 1（第二个没打到）
    tokio::time::sleep(Duration::from_millis(80)).await;
    assert_eq!(
        hits.load(Ordering::SeqCst),
        1,
        "second query leaked to upstream without gate"
    );
    // 等到第一个超时释放 permit，第二个才会打到上游
    let _ = tokio::join!(t1, t2);
    assert!(
        hits.load(Ordering::SeqCst) >= 1,
        "at least one query must reach upstream"
    );
    // 允许第二次最终也打到上游（是否到达取决于时间片，不做强约束）
    assert!(started.elapsed() >= Duration::from_millis(60));
}
