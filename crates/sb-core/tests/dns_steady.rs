use sb_core::dns::cache::{DnsCache, Key, QType};
use sb_core::dns::ResolverHandle;
use std::net::IpAddr;
use std::time::Duration;

#[tokio::test]
async fn bad_domain_returns_err() {
    // Ensure system resolver path
    std::env::remove_var("SB_DNS_POOL");
    let h = ResolverHandle::from_env_or_default();
    let res = h.resolve("nonexistent.invalid").await;
    assert!(res.is_err());
}

#[tokio::test]
async fn udp_pool_timeout_is_handled() {
    // Force UDP upstream to an unroutable/closed port and a tiny timeout
    std::env::set_var("SB_DNS_POOL", "udp:127.0.0.1:9");
    std::env::set_var("SB_DNS_UDP_TIMEOUT_MS", "20");
    let h = ResolverHandle::from_env_or_default();
    let res = h.resolve("example.com").await;
    assert!(res.is_err());
    // cleanup
    std::env::remove_var("SB_DNS_POOL");
    std::env::remove_var("SB_DNS_UDP_TIMEOUT_MS");
}

#[test]
fn cache_hit_and_expire() {
    let cache = DnsCache::new(8);
    let key = Key {
        name: "test.example".to_string(),
        qtype: QType::A,
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
