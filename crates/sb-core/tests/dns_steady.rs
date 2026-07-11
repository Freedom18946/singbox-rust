#![allow(clippy::await_holding_lock)]

use sb_core::dns::cache::{DnsCache, Key, QType};
use sb_core::dns::ResolverHandle;
use sb_core::runtime_options::DnsRuntimeOptions;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;

async fn start_nxdomain_dns_stub() -> std::io::Result<SocketAddr> {
    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    let addr = socket.local_addr()?;
    tokio::spawn(async move {
        let mut buf = [0u8; 1500];
        while let Ok((len, peer)) = socket.recv_from(&mut buf).await {
            if let Some(response) =
                sb_core::dns::message::build_dns_response(&buf[..len], &[], 0, 3)
            {
                let _ = socket.send_to(&response, peer).await;
            }
        }
    });
    Ok(addr)
}

async fn start_blackhole_dns_stub() -> std::io::Result<SocketAddr> {
    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    let addr = socket.local_addr()?;
    tokio::spawn(async move {
        let mut buf = [0u8; 1500];
        while socket.recv_from(&mut buf).await.is_ok() {}
    });
    Ok(addr)
}

#[tokio::test]
async fn bad_domain_returns_err() {
    let upstream = start_nxdomain_dns_stub()
        .await
        .expect("start local NXDOMAIN DNS stub");
    let h = ResolverHandle::from_options(Arc::new(DnsRuntimeOptions {
        enabled: true,
        pool: format!("udp:{upstream}"),
        pool_strategy: "sequential".into(),
        udp_timeout_ms: 100,
        happy_eyeballs_race_ms: 0,
        ..Default::default()
    }));
    let res = h.resolve("nonexistent.invalid").await;
    assert!(res.is_err());
}

#[tokio::test]
async fn udp_pool_timeout_is_handled() {
    let upstream = start_blackhole_dns_stub()
        .await
        .expect("start local blackhole DNS stub");
    let h = ResolverHandle::from_options(Arc::new(DnsRuntimeOptions {
        enabled: true,
        pool: format!("udp:{upstream}"),
        pool_strategy: "sequential".into(),
        udp_timeout_ms: 20,
        happy_eyeballs_race_ms: 0,
        ..Default::default()
    }));
    let res = h.resolve("example.com").await;
    assert!(res.is_err());
}

#[test]
fn cache_hit_and_expire() {
    let options = DnsRuntimeOptions {
        answer_cache_min_ttl_s: 0,
        ..Default::default()
    };
    let cache = DnsCache::with_options(8, &options);
    let key = Key {
        name: "test.example".to_string(),
        qtype: QType::A,
        transport_tag: None,
    };
    let ans = sb_core::dns::DnsAnswer::new(
        vec!["127.0.0.1".parse::<IpAddr>().unwrap()],
        Duration::from_millis(50),
        sb_core::dns::cache::Source::System,
        sb_core::dns::cache::Rcode::NoError,
    );
    cache.put(key.clone(), ans.clone());
    // immediate hit
    let got = cache.get(&key).expect("hit");
    assert_eq!(got.ips, ans.ips);
    // wait to expire
    std::thread::sleep(Duration::from_millis(70));
    assert!(cache.get(&key).is_none());
}
