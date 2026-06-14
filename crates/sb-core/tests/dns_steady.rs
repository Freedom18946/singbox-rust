#![allow(clippy::await_holding_lock)]

use sb_core::dns::cache::{DnsCache, Key, QType};
use sb_core::dns::ResolverHandle;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Mutex, OnceLock};
use std::time::Duration;
use tokio::net::UdpSocket;

fn serial_guard() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|err| err.into_inner())
}

struct EnvVarGuard {
    key: &'static str,
    prev: Option<std::ffi::OsString>,
}

impl EnvVarGuard {
    fn set(key: &'static str, value: &str) -> Self {
        let prev = std::env::var_os(key);
        std::env::set_var(key, value);
        Self { key, prev }
    }
}

impl Drop for EnvVarGuard {
    fn drop(&mut self) {
        match self.prev.as_ref() {
            Some(v) => std::env::set_var(self.key, v),
            None => std::env::remove_var(self.key),
        }
    }
}

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
    let _serial = serial_guard();
    let upstream = start_nxdomain_dns_stub()
        .await
        .expect("start local NXDOMAIN DNS stub");
    let _enabled = EnvVarGuard::set("SB_DNS_ENABLE", "1");
    let _pool = EnvVarGuard::set("SB_DNS_POOL", &format!("udp:{upstream}"));
    let _strategy = EnvVarGuard::set("SB_DNS_POOL_STRATEGY", "sequential");
    let _timeout = EnvVarGuard::set("SB_DNS_UDP_TIMEOUT_MS", "100");
    let _he = EnvVarGuard::set("SB_DNS_HE_RACE_MS", "0");
    let h = ResolverHandle::from_env_or_default();
    let res = h.resolve("nonexistent.invalid").await;
    assert!(res.is_err());
}

#[tokio::test]
async fn udp_pool_timeout_is_handled() {
    let _serial = serial_guard();
    let upstream = start_blackhole_dns_stub()
        .await
        .expect("start local blackhole DNS stub");
    let _enabled = EnvVarGuard::set("SB_DNS_ENABLE", "1");
    let _pool = EnvVarGuard::set("SB_DNS_POOL", &format!("udp:{upstream}"));
    let _strategy = EnvVarGuard::set("SB_DNS_POOL_STRATEGY", "sequential");
    let _timeout = EnvVarGuard::set("SB_DNS_UDP_TIMEOUT_MS", "20");
    let _he = EnvVarGuard::set("SB_DNS_HE_RACE_MS", "0");
    let h = ResolverHandle::from_env_or_default();
    let res = h.resolve("example.com").await;
    assert!(res.is_err());
}

#[test]
fn cache_hit_and_expire() {
    let _serial = serial_guard();
    // Allow sub-second TTLs for this test.
    let _min_ttl = EnvVarGuard::set("SB_DNS_MIN_TTL_S", "0");
    let cache = DnsCache::new(8);
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
