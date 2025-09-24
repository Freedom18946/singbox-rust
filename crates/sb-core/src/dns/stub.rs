//! Very small DNS stub + cache (default OFF; enable via env DNS_STUB=1).
//! - 使用系统解析（getaddrinfo）作为唯一上游；失败时不阻塞主链，按需返回 None。
//! - 提供 TTL 缓存；TTL 由 init_global(ttl_secs) 指定。
//! - 后续可挂 DoT/DoH 实现，保持接口不变。
use std::collections::HashMap;
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

#[derive(Clone, Debug)]
struct Entry {
    addrs: Vec<SocketAddr>,
    expire_at: Instant,
}

#[derive(Debug)]
pub struct DnsCache {
    ttl: Duration,
    inner: Mutex<HashMap<String, Entry>>,
}

impl DnsCache {
    pub fn new(ttl_secs: u64) -> Self {
        Self {
            ttl: Duration::from_secs(ttl_secs),
            inner: Mutex::new(HashMap::new()),
        }
    }
    fn now() -> Instant {
        Instant::now()
    }

    pub fn resolve(&self, host: &str, port: u16) -> Option<Vec<SocketAddr>> {
        // 1) 命中缓存
        if let Some(v) = self.inner.lock().unwrap().get(host) {
            if Self::now() < v.expire_at {
                return Some(v.addrs.clone());
            }
        }
        // 2) 系统解析
        let q = format!("{}:{}", host, port);
        match q.to_socket_addrs() {
            Ok(mut it) => {
                let mut acc = vec![];
                while let Some(a) = it.next() {
                    acc.push(a);
                }
                if !acc.is_empty() {
                    // 3) 写缓存
                    let e = Entry {
                        addrs: acc.clone(),
                        expire_at: Self::now() + self.ttl,
                    };
                    self.inner.lock().unwrap().insert(host.to_string(), e);
                    return Some(acc);
                }
                None
            }
            Err(_) => None,
        }
    }
    pub fn purge_expired(&self) {
        let now = Self::now();
        self.inner.lock().unwrap().retain(|_, e| e.expire_at > now);
    }
    pub fn size(&self) -> usize {
        self.inner.lock().unwrap().len()
    }
}

static GLOBAL: OnceLock<DnsCache> = OnceLock::new();
pub fn init_global(ttl_secs: u64) {
    let _ = GLOBAL.set(DnsCache::new(ttl_secs));
}
pub fn global() -> Option<&'static DnsCache> {
    GLOBAL.get()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cache_basic() {
        let c = DnsCache::new(1);
        let r = c.resolve("localhost", 80);
        assert!(r.is_some());
        assert!(c.size() >= 1);
    }
}
