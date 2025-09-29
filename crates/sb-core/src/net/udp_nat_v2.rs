use dashmap::DashMap;
use std::{
    cmp::Ordering,
    collections::BinaryHeap,
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::net::UdpSocket;
use tokio::sync::Mutex;

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub enum TargetAddr {
    Ip(std::net::SocketAddr),
    // 未来可加 Domain(String, u16)
}

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct NatKey {
    pub client: SocketAddr,
    pub dst: TargetAddr,
}

#[derive(Debug)]
pub struct NatEntry {
    pub upstream: Arc<UdpSocket>,
    pub last_seen: Instant,
    pub expiry: Instant,
    pub gen: u64,
    pub bytes_in: u64,
    pub bytes_out: u64,
}

#[derive(Clone, Debug)]
struct HeapItem {
    expiry: Instant,
    gen: u64,
    key: NatKey,
}

impl PartialEq for HeapItem {
    fn eq(&self, other: &Self) -> bool {
        self.expiry.eq(&other.expiry) && self.gen == other.gen
    }
}
impl Eq for HeapItem {}
impl PartialOrd for HeapItem {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for HeapItem {
    fn cmp(&self, other: &Self) -> Ordering {
        // BinaryHeap 是最大堆，我们要最早过期在堆顶 => 反转
        other
            .expiry
            .cmp(&self.expiry)
            .then_with(|| self.gen.cmp(&other.gen))
    }
}

pub struct NatMap {
    map: DashMap<NatKey, NatEntry>,
    heap: Mutex<BinaryHeap<HeapItem>>,
    ttl: Duration,
    cap: usize,
    #[cfg(feature = "metrics")]
    metrics: crate::metrics::udp_v2::UdpNatMetrics,
}

impl NatMap {
    pub fn new(ttl: Duration, cap: usize) -> Arc<Self> {
        Arc::new(Self {
            map: DashMap::new(),
            heap: Mutex::new(BinaryHeap::new()),
            ttl,
            cap,
            #[cfg(feature = "metrics")]
            metrics: crate::metrics::udp_v2::register_udp_nat_metrics(),
        })
    }

    #[inline]
    fn now(&self) -> Instant {
        Instant::now()
    }

    /// 获取或插入一个 NAT 映射；当达到容量时先做"前置驱逐"
    pub async fn get_or_insert_with<F>(&self, key: NatKey, make: F) -> Arc<UdpSocket>
    where
        F: FnOnce() -> Arc<UdpSocket>,
    {
        self.pre_evict().await;

        if let Some(mut e) = self.map.get_mut(&key) {
            e.gen = e.gen.wrapping_add(1);
            e.last_seen = self.now();
            e.expiry = e.last_seen + self.ttl;
            let item = HeapItem {
                expiry: e.expiry,
                gen: e.gen,
                key: key.clone(),
            };
            {
                let mut h = self.heap.lock().await;
                h.push(item);
                #[cfg(feature = "metrics")]
                self.metrics.heap_len.set(h.len() as i64);
            }
            return e.upstream.clone();
        }

        let now = self.now();
        let entry = NatEntry {
            upstream: make(),
            last_seen: now,
            expiry: now + self.ttl,
            gen: 1,
            bytes_in: 0,
            bytes_out: 0,
        };
        let upstream = entry.upstream.clone();
        self.map.insert(key.clone(), entry);
        {
            let mut h = self.heap.lock().await;
            h.push(HeapItem {
                expiry: now + self.ttl,
                gen: 1,
                key,
            });
            #[cfg(feature = "metrics")]
            self.metrics.heap_len.set(h.len() as i64);
        }
        #[cfg(feature = "metrics")]
        self.metrics.size_gauge.set(self.map.len() as i64);
        upstream
    }

    /// 记录流量（可在收发路径调用）
    pub fn add_in_bytes(&self, key: &NatKey, n: usize) {
        if let Some(mut e) = self.map.get_mut(key) {
            e.bytes_in = e.bytes_in.saturating_add(n as u64);
        }
        #[cfg(feature = "metrics")]
        self.metrics.bytes_in.inc_by(n as u64);
    }
    pub fn add_out_bytes(&self, key: &NatKey, n: usize) {
        if let Some(mut e) = self.map.get_mut(key) {
            e.bytes_out = e.bytes_out.saturating_add(n as u64);
        }
        #[cfg(feature = "metrics")]
        self.metrics.bytes_out.inc_by(n as u64);
    }

    /// 周期淘汰：过期优先；必要时退一步做容量驱逐
    pub async fn run_evictor(self: Arc<Self>, period: Duration) {
        loop {
            tokio::time::sleep(period).await;
            let now = self.now();
            let mut removed = 0usize;
            {
                let mut h = self.heap.lock().await;
                while let Some(top) = h.peek() {
                    if top.expiry > now && self.map.len() <= self.cap {
                        break;
                    }
                    let Some(item) = h.pop() else {
                        break;
                    };
                    match self.try_evict(item, now).await {
                        EvictResult::Removed(_reason) => {
                            removed += 1;
                            #[cfg(feature = "metrics")]
                            self.metrics
                                .evicted_total
                                .with_label_values(&[_reason])
                                .inc();
                        }
                        EvictResult::GenMismatch => {
                            #[cfg(feature = "metrics")]
                            self.metrics.gen_mismatch.inc();
                        }
                        EvictResult::Keep => {}
                    }
                }
                #[cfg(feature = "metrics")]
                self.metrics.heap_len.set(h.len() as i64);
            }
            if removed > 0 {
                #[cfg(feature = "metrics")]
                self.metrics.size_gauge.set(self.map.len() as i64);
            }
        }
    }

    async fn pre_evict(&self) {
        if self.map.len() < self.cap {
            return;
        }
        let now = self.now();
        let mut _cnt = 0usize;
        let mut h = self.heap.lock().await;
        while self.map.len() > self.cap {
            if let Some(item) = h.pop() {
                let _ = self.try_evict_inner(item, now, Some("capacity")).await;
                _cnt += 1;
            } else {
                break;
            }
        }
        #[cfg(feature = "metrics")]
        {
            if _cnt > 0 {
                self.metrics.heap_len.set(h.len() as i64);
            }
            self.metrics.size_gauge.set(self.map.len() as i64);
        }
    }

    async fn try_evict(&self, item: HeapItem, now: Instant) -> EvictResult {
        self.try_evict_inner(item, now, None).await
    }

    async fn try_evict_inner(
        &self,
        item: HeapItem,
        now: Instant,
        reason_override: Option<&'static str>,
    ) -> EvictResult {
        use EvictResult::*;
        if let Some(e) = self.map.get(&item.key) {
            if e.gen != item.gen {
                return GenMismatch;
            }
            if e.expiry > now && reason_override.is_none() {
                return Keep;
            }
        } else {
            // 已被移除，无需记录
            return Removed("closed");
        }
        // 到这里说明：gen 匹配，且已到期或容量驱逐
        self.map.remove(&item.key);
        let reason = reason_override.unwrap_or("expiry");
        Removed(reason)
    }
}

enum EvictResult {
    Removed(&'static str),
    GenMismatch,
    Keep,
}
