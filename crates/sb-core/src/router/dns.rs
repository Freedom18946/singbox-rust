//! Simple DNS cache with TTL-based entries.
//!
//! Example
//! ```
//! use sb_core::router::dns::DnsCache;
//! use std::time::Duration;
//!
//! let cache = DnsCache::new(Duration::from_secs(1));
//! // "localhost" should resolve on all platforms without network I/O.
//! let ips = cache.resolve_cached_or_lookup("localhost");
//! assert!(ips.is_some());
//! // Subsequent lookup should be served from cache.
//! let ips2 = cache.resolve_cached_or_lookup("localhost");
//! assert_eq!(ips, ips2);
//! ```
use std::collections::HashMap;
use std::net::{IpAddr, ToSocketAddrs};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};
use tracing::trace;

#[derive(Clone, Debug)]
pub struct DnsCache {
    ttl: Duration,
    // host -> (ips, expire_at)
    inner: Arc<RwLock<CacheMap>>,
}

type CacheMap = HashMap<String, (Vec<IpAddr>, Instant)>;

impl DnsCache {
    pub fn new(ttl: Duration) -> Self {
        Self {
            ttl,
            inner: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// 先查缓存；过期就用系统解析器阻塞解析（最简单、最稳）。
    /// 解析失败返回 None，不污染缓存。
    pub fn resolve_cached_or_lookup(&self, host: &str) -> Option<Vec<IpAddr>> {
        let now = Instant::now();

        // 读缓存命中
        if let Some((ips, exp)) = self.inner.read().ok().and_then(|g| g.get(host).cloned()) {
            if now < exp {
                return Some(ips);
            }
        }

        // 阻塞解析（系统解析器 /etc/hosts, resolv.conf 等）
        let mut uniq = Vec::<IpAddr>::new();
        if let Ok(iter) = (host, 0u16).to_socket_addrs() {
            for sa in iter {
                let ip = sa.ip();
                if !uniq.contains(&ip) {
                    uniq.push(ip);
                }
            }
        }
        if uniq.is_empty() {
            trace!(host = host, "dns resolve failed (no addrs)");
            return None;
        }

        // 写回缓存
        if let Ok(mut g) = self.inner.write() {
            g.insert(host.to_string(), (uniq.clone(), now + self.ttl));
        }

        trace!(host = host, count = uniq.len(), "dns cache updated");
        Some(uniq)
    }
}
