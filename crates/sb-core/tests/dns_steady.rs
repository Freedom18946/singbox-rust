use sb_core::dns::cache::{DnsCache, Key, QType};
use sb_core::dns::ResolverHandle;
use std::net::IpAddr;
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

fn serial_guard() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(())).lock().unwrap()
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

    fn remove(key: &'static str) -> Self {
        let prev = std::env::var_os(key);
        std::env::remove_var(key);
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

#[tokio::test]
async fn bad_domain_returns_err() {
    let _serial = serial_guard();
    // Ensure system resolver path
    let _pool = EnvVarGuard::remove("SB_DNS_POOL");
    let h = ResolverHandle::from_env_or_default();
    let res = h.resolve("nonexistent.invalid").await;
    assert!(res.is_err());
}

#[tokio::test]
async fn udp_pool_timeout_is_handled() {
    let _serial = serial_guard();
    // Force UDP upstream to an unroutable/closed port and a tiny timeout
    let _pool = EnvVarGuard::set("SB_DNS_POOL", "udp:127.0.0.1:9");
    let _timeout = EnvVarGuard::set("SB_DNS_UDP_TIMEOUT_MS", "20");
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
