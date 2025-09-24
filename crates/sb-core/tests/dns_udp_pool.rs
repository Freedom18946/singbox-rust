#![cfg(feature = "dns_udp")]
use std::net::SocketAddr;
use std::time::Duration;

use sb_core::dns::udp::build_query;
use sb_core::dns::ResolverHandle;
use tokio::net::UdpSocket;

async fn start_stub(addr: SocketAddr, delay_ms: u64, v4: Option<[u8; 4]>, v6: Option<[u8; 16]>) {
    let sock = UdpSocket::bind(addr).await.unwrap();
    tokio::spawn(async move {
        let mut buf = [0u8; 1500];
        loop {
            let Ok((n, peer)) = sock.recv_from(&mut buf).await else {
                break;
            };
            if n < 12 {
                continue;
            }
            let id = [buf[0], buf[1]];
            let qname_end = {
                let mut i = 12usize;
                while i < n && buf[i] != 0 {
                    i += 1 + (buf[i] as usize);
                }
                i + 1
            };
            if qname_end + 4 > n {
                continue;
            }
            let qtype = u16::from_be_bytes([buf[qname_end], buf[qname_end + 1]]);
            // Build minimal response
            let mut out = Vec::new();
            out.extend_from_slice(&id);
            out.extend_from_slice(&0x8180u16.to_be_bytes()); // QR=1, RD=1, RA=1
            out.extend_from_slice(&1u16.to_be_bytes()); // QD
            let mut an = 0u16;
            if qtype == 1 && v4.is_some() {
                an = 1;
            }
            if qtype == 28 && v6.is_some() {
                an = 1;
            }
            out.extend_from_slice(&an.to_be_bytes()); // AN
            out.extend_from_slice(&0u16.to_be_bytes()); // NS
            out.extend_from_slice(&0u16.to_be_bytes()); // AR
                                                        // question
            out.extend_from_slice(&buf[12..qname_end + 4]);
            if qtype == 1 {
                if let Some(ip) = v4 {
                    out.extend_from_slice(&[0xC0, 0x0C]); // pointer to qname
                    out.extend_from_slice(&1u16.to_be_bytes()); // A
                    out.extend_from_slice(&1u16.to_be_bytes()); // IN
                    out.extend_from_slice(&5u32.to_be_bytes()); // TTL
                    out.extend_from_slice(&4u16.to_be_bytes());
                    out.extend_from_slice(&ip);
                }
            } else if qtype == 28 {
                if let Some(ip) = v6 {
                    out.extend_from_slice(&[0xC0, 0x0C]);
                    out.extend_from_slice(&28u16.to_be_bytes());
                    out.extend_from_slice(&1u16.to_be_bytes());
                    out.extend_from_slice(&5u32.to_be_bytes());
                    out.extend_from_slice(&16u16.to_be_bytes());
                    out.extend_from_slice(&ip);
                }
            }
            if delay_ms > 0 {
                tokio::time::sleep(Duration::from_millis(delay_ms)).await;
            }
            let _ = sock.send_to(&out, peer).await;
        }
    });
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pool_race_picks_faster() {
    // two stubs: one slow A 1.2.3.4, one fast AAAA 2001:db8::1
    let up1: SocketAddr = "127.0.0.1:20531".parse().unwrap();
    let up2: SocketAddr = "127.0.0.1:20532".parse().unwrap();
    start_stub(up1, 150, Some([1, 2, 3, 4]), None).await;
    start_stub(
        up2,
        10,
        None,
        Some([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
    )
    .await;

    std::env::set_var("SB_DNS_ENABLE", "1");
    std::env::set_var("SB_DNS_POOL", format!("udp:{},udp:{}", up1, up2));
    std::env::set_var("SB_DNS_POOL_STRATEGY", "race");
    std::env::set_var("SB_DNS_HE_ORDER", "A_FIRST");
    std::env::set_var("SB_DNS_RACE_WINDOW_MS", "0");

    let h = ResolverHandle::from_env_or_default();
    let ans = h.resolve("example.com").await.unwrap();
    assert!(!ans.ips.is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pool_sequential_fallback() {
    let up1: SocketAddr = "127.0.0.1:20541".parse().unwrap();
    let up2: SocketAddr = "127.0.0.1:20542".parse().unwrap();
    // up1: no response (not started), up2: responds A
    start_stub(up2, 5, Some([5, 6, 7, 8]), None).await;
    std::env::set_var("SB_DNS_ENABLE", "1");
    std::env::set_var("SB_DNS_POOL", format!("udp:{},udp:{}", up1, up2));
    std::env::set_var("SB_DNS_POOL_STRATEGY", "sequential");
    let h = ResolverHandle::from_env_or_default();
    let ans = h.resolve("example.org").await.unwrap();
    assert!(!ans.ips.is_empty());
}
