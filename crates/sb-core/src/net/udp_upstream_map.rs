use crate::outbound::socks5_udp::UpSocksSession;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::time::{Duration, Instant};

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Key {
    pub src: SocketAddr,
    pub dst: (IpAddr, u16),
}

struct Entry {
    sess: Arc<UpSocksSession>,
    last: Instant,
}

pub struct UdpUpstreamMap {
    inner: Mutex<HashMap<Key, Entry>>,
    ttl: Duration,
    max: Option<usize>,
}

impl UdpUpstreamMap {
    pub fn new(ttl: Duration) -> Self {
        let max = std::env::var("SB_UDP_UPSTREAM_MAX")
            .ok()
            .and_then(|v| v.parse::<usize>().ok());
        Self {
            inner: Mutex::new(HashMap::new()),
            ttl,
            max,
        }
    }

    pub async fn get(&self, key: &Key) -> Option<Arc<UpSocksSession>> {
        let mut guard = self.inner.lock().await;
        if let Some(entry) = guard.get_mut(key) {
            entry.last = Instant::now();
            Some(Arc::clone(&entry.sess))
        } else {
            None
        }
    }

    pub async fn insert(&self, key: Key, sess: Arc<UpSocksSession>) -> bool {
        let mut guard = self.inner.lock().await;
        if let Some(max) = self.max {
            if !guard.contains_key(&key) && guard.len() >= max {
                #[cfg(feature = "metrics")]
                metrics::counter!("udp_upstream_error_total", "class" => "capacity").increment(1);
                return false;
            }
        }
        let is_new = !guard.contains_key(&key);
        guard.insert(
            key,
            Entry {
                sess,
                last: Instant::now(),
            },
        );
        #[cfg(feature = "metrics")]
        {
            if is_new {
                metrics::counter!("udp_upstream_map_create_total").increment(1);
            }
            metrics::gauge!("udp_upstream_map_size").set(guard.len() as f64);
        }
        true
    }

    pub async fn remove(&self, key: &Key) -> Option<Arc<UpSocksSession>> {
        let mut guard = self.inner.lock().await;
        let removed = guard.remove(key).map(|entry| entry.sess);
        #[cfg(feature = "metrics")]
        {
            if removed.is_some() {
                metrics::counter!("udp_upstream_map_close_total").increment(1);
            }
            metrics::gauge!("udp_upstream_map_size").set(guard.len() as f64);
        }
        removed
    }

    pub async fn evict_expired(&self) -> usize {
        let ttl = self.ttl;
        let mut guard = self.inner.lock().await;
        let before = guard.len();
        guard.retain(|_, entry| entry.last.elapsed() < ttl);
        let removed = before.saturating_sub(guard.len());
        if removed > 0 {
            #[cfg(feature = "metrics")]
            {
                metrics::counter!("udp_upstream_map_evict_total").increment(removed as u64);
                metrics::gauge!("udp_upstream_map_size").set(guard.len() as f64);
            }
        }
        removed
    }
}
