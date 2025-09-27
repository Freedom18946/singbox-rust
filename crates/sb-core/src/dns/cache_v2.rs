use std::{
    collections::HashMap,
    time::{Duration, Instant},
};
use tokio::sync::Mutex;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum QType {
    A,
    AAAA,
}

#[derive(Clone, Debug)]
pub struct PosEntry {
    pub addrs: smallvec::SmallVec<[std::net::IpAddr; 4]>,
    pub expires_at: Instant,
}

#[derive(Clone, Debug)]
pub struct NegEntry {
    pub expires_at: Instant,
}

pub enum CacheCell {
    Pos(PosEntry),
    Neg(NegEntry),
}

pub struct DnsCache {
    inner: Mutex<HashMap<(String, QType), CacheCell>>,
    min_ttl: Duration,
    max_ttl: Duration,
    #[cfg(feature = "metrics")]
    metrics: crate::metrics::dns_v2::DnsCacheMetrics,
}

impl DnsCache {
    pub fn new(min_ttl: Duration, max_ttl: Duration) -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
            min_ttl,
            max_ttl,
            #[cfg(feature = "metrics")]
            metrics: crate::metrics::dns_v2::register_dns_cache_metrics(),
        }
    }

    #[inline]
    fn clamp(&self, ttl: Duration) -> (Duration, &'static str) {
        if ttl < self.min_ttl {
            (self.min_ttl, "up")
        } else if ttl > self.max_ttl {
            (self.max_ttl, "down")
        } else {
            (ttl, "ok")
        }
    }

    pub async fn get(&self, name: &str, q: QType, now: Instant) -> Option<CacheCell> {
        let key = (name.to_ascii_lowercase(), q);
        let mut g = self.inner.lock().await;
        if let Some(cell) = g.get(&key) {
            match cell {
                CacheCell::Pos(e) if e.expires_at > now => {
                    #[cfg(feature = "metrics")]
                    self.metrics.hit_total.with_label_values(&["pos"]).inc();
                    return Some(CacheCell::Pos(e.clone()));
                }
                CacheCell::Neg(e) if e.expires_at > now => {
                    #[cfg(feature = "metrics")]
                    self.metrics.hit_total.with_label_values(&["neg"]).inc();
                    return Some(CacheCell::Neg(e.clone()));
                }
                _ => {
                    g.remove(&key);
                }
            }
        }
        None
    }

    pub async fn put_pos(
        &self,
        name: &str,
        q: QType,
        addrs: smallvec::SmallVec<[std::net::IpAddr; 4]>,
        ttl: Duration,
        now: Instant,
    ) {
        let (ttl, clamp_dir) = self.clamp(ttl);
        #[cfg(not(feature = "metrics"))]
        let _ = clamp_dir;
        let key = (name.to_ascii_lowercase(), q);
        let e = PosEntry {
            addrs,
            expires_at: now + ttl,
        };
        let mut g = self.inner.lock().await;
        g.insert(key, CacheCell::Pos(e));
        #[cfg(feature = "metrics")]
        {
            self.metrics.store_total.with_label_values(&["pos"]).inc();
            if clamp_dir != "ok" {
                self.metrics
                    .ttl_clamped_total
                    .with_label_values(&[clamp_dir])
                    .inc();
            }
        }
    }

    pub async fn put_neg(&self, name: &str, q: QType, ttl: Duration, now: Instant) {
        let (ttl, clamp_dir) = self.clamp(ttl);
        #[cfg(not(feature = "metrics"))]
        let _ = clamp_dir;
        let key = (name.to_ascii_lowercase(), q);
        let e = NegEntry {
            expires_at: now + ttl,
        };
        let mut g = self.inner.lock().await;
        g.insert(key, CacheCell::Neg(e));
        #[cfg(feature = "metrics")]
        {
            self.metrics.store_total.with_label_values(&["neg"]).inc();
            if clamp_dir != "ok" {
                self.metrics
                    .ttl_clamped_total
                    .with_label_values(&[clamp_dir])
                    .inc();
            }
        }
    }
}
