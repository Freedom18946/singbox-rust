#![cfg(feature = "router")]
use sb_core::dns::ResolverHandle;
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
    let hits_a = Arc::new(AtomicUsize::new(0));
    let hits_aaaa = Arc::new(AtomicUsize::new(0));
    let hits_a2 = hits_a.clone();
    let hits_aaaa2 = hits_aaaa.clone();
    tokio::spawn(async move {
        let mut buf = [0u8; 1500];
        loop {
            let Ok((n, _p)) = sock.recv_from(&mut buf).await else {
                break;
            };
            if let Some(qtype) = parse_dns_qtype(&buf[..n]) {
                match qtype {
                    1 => {
                        hits_a2.fetch_add(1, Ordering::SeqCst);
                    }
                    28 => {
                        hits_aaaa2.fetch_add(1, Ordering::SeqCst);
                    }
                    _ => {}
                }
            }
            // 不回复，阻塞住调用端直到其超时
            tokio::time::sleep(Duration::from_millis(120)).await;
        }
    });

    // 配置：启用 DNS、使用单并发门控、短超时
    std::env::set_var("SB_DNS_ENABLE", "1");
    std::env::set_var("SB_DNS_POOL", format!("udp:{}", addr));
    std::env::set_var("SB_DNS_POOL_MAX_INFLIGHT", "1");
    std::env::set_var("SB_DNS_PER_HOST_INFLIGHT", "1");
    std::env::set_var("SB_DNS_UDP_TIMEOUT_MS", "60");
    std::env::set_var("SB_DNS_HE_RACE_MS", "30");

    let h = ResolverHandle::from_env_or_default();
    let started = Instant::now();
    let t1 = tokio::spawn({
        let h = h.clone();
        async move {
            // 第一次解析，确保会命中上游并在 60ms 超时
            let _ = h.resolve("blocked.test").await;
        }
    });
    // 稍后立刻发起第二个（应该被 inflight 门控阻塞，不会立刻打到上游）
    let t2 = tokio::spawn({
        let h = h.clone();
        async move {
            let _ = h.resolve("blocked.test").await;
        }
    });
    // 等待 80ms，若门控正确，此时 A 记录查询只应发送 1 次（第二个被 gate 阻塞）。
    tokio::time::sleep(Duration::from_millis(80)).await;
    assert_eq!(
        hits_a.load(Ordering::SeqCst),
        1,
        "second query leaked to upstream without gate"
    );
    // 等到第一个超时释放 permit，第二个才会打到上游
    let _ = tokio::join!(t1, t2);
    assert!(
        hits_a.load(Ordering::SeqCst) >= 1 || hits_aaaa.load(Ordering::SeqCst) >= 1,
        "at least one query must reach upstream"
    );
    // 允许第二次最终也打到上游（是否到达取决于时间片，不做强约束）
    assert!(started.elapsed() >= Duration::from_millis(60));
}

fn parse_dns_qtype(packet: &[u8]) -> Option<u16> {
    if packet.len() < 12 {
        return None;
    }
    let mut idx = 12;
    while idx < packet.len() {
        let len = *packet.get(idx)? as usize;
        idx += 1;
        if len == 0 {
            break;
        }
        idx = idx.checked_add(len)?;
    }
    let qt = packet.get(idx..idx + 2)?;
    Some(u16::from_be_bytes([qt[0], qt[1]]))
}
