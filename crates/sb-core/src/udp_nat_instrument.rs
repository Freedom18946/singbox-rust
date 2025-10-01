//! UDP NAT metrics instrumentation.
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use sb_metrics::constants::*;
use sb_metrics::registry::global as M;

#[derive(Clone, Copy, Debug)]
pub enum EvictReason {
    Lru,
    Ttl,
    Pressure,
}
impl EvictReason {
    fn as_str(&self) -> &'static str {
        match self {
            EvictReason::Lru => "lru",
            EvictReason::Ttl => "ttl",
            EvictReason::Pressure => "pressure",
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub enum UpstreamFail {
    Timeout,
    Icmp,
    Refused,
    Other,
}
impl UpstreamFail {
    fn as_str(&self) -> &'static str {
        match self {
            UpstreamFail::Timeout => "timeout",
            UpstreamFail::Icmp => "icmp",
            UpstreamFail::Refused => "refused",
            UpstreamFail::Other => "other",
        }
    }
}

#[derive(Clone, Debug)]
struct Entry {
    last: Instant,
    ttl: Duration,
}

/// 简化 NAT 表（仅用于指标演示；真实 NAT 逻辑应在现有模块）
#[derive(Clone, Default)]
pub struct UdpNatTable {
    inner: Arc<Mutex<HashMap<(SocketAddr, SocketAddr), Entry>>>,
    max_entries: usize,
}

impl UdpNatTable {
    pub fn new(max_entries: usize) -> Self {
        Self {
            inner: Arc::new(Mutex::new(HashMap::new())),
            max_entries,
        }
    }
    pub fn insert(&self, src: SocketAddr, upstream: SocketAddr, ttl: Duration) {
        let Ok(mut g) = self.inner.lock() else {
            // On lock poison, skip UDP NAT tracking (graceful degradation)
            return;
        };
        if g.len() >= self.max_entries {
            // 逐出一个最旧的（简化）
            if let Some((k, _)) = g
                .iter()
                .min_by_key(|(_, v)| v.last)
                .map(|(k, v)| (*k, v.clone()))
            {
                g.remove(&k);
                M().udp_evict_total
                    .inc(&[(LABEL_REASON, EvictReason::Pressure.as_str())]);
            }
        }
        g.insert(
            (src, upstream),
            Entry {
                last: Instant::now(),
                ttl,
            },
        );
        M().udp_map_size.set(g.len() as u64);
    }
    pub fn hit(&self, src: SocketAddr, upstream: SocketAddr) {
        let Ok(mut g) = self.inner.lock() else {
            // On lock poison, skip UDP NAT tracking (graceful degradation)
            return;
        };
        if let Some(e) = g.get_mut(&(src, upstream)) {
            e.last = Instant::now();
        }
    }
    pub fn evict_expired(&self) {
        let now = Instant::now();
        let Ok(mut g) = self.inner.lock() else {
            // On lock poison, skip UDP NAT tracking (graceful degradation)
            return;
        };
        let mut removed = 0;
        g.retain(|_, e| {
            if now.duration_since(e.last) > e.ttl {
                M().udp_evict_total
                    .inc(&[(LABEL_REASON, EvictReason::Ttl.as_str())]);
                M().udp_ttl_seconds.observe(e.ttl.as_secs_f64());
                removed += 1;
                false
            } else {
                true
            }
        });
        if removed > 0 {
            M().udp_map_size.set(g.len() as u64);
        }
    }
    pub fn upstream_fail(&self, class: UpstreamFail) {
        M().udp_fail_total.inc(&[(LABEL_CLASS, class.as_str())]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;
    #[test]
    fn eviction_and_counters() {
        let t = UdpNatTable::new(8);
        let s = SocketAddr::from_str("127.0.0.1:10000").unwrap();
        let u = SocketAddr::from_str("1.1.1.1:53").unwrap();
        t.insert(s, u, Duration::from_millis(1));
        std::thread::sleep(Duration::from_millis(2));
        t.evict_expired();
        assert!(M().udp_map_size.get() <= 1);
    }
}
