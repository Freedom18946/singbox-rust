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
use tokio_util::sync::CancellationToken;

use crate::net::datagram::UdpConntrackMeta;
use crate::net::metered::TrafficRecorder;

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub enum TargetAddr {
    Ip(std::net::SocketAddr),
    Domain(String, u16),
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
    pub conntrack: Option<UdpConntrackMeta>,
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
    metrics: crate::metrics::udp::UdpNatMetrics,
}

impl NatMap {
    pub fn new(ttl: Duration, cap: usize) -> Arc<Self> {
        Arc::new(Self {
            map: DashMap::new(),
            heap: Mutex::new(BinaryHeap::new()),
            ttl,
            cap,
            #[cfg(feature = "metrics")]
            metrics: crate::metrics::udp::register_udp_nat_metrics(),
        })
    }

    /// 当前 NAT 表项数量
    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Get a NAT entry if present and refresh its expiry.
    pub async fn get(&self, key: &NatKey) -> Option<Arc<UdpSocket>> {
        if let Some(mut e) = self.map.get_mut(key) {
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
            return Some(e.upstream.clone());
        }
        None
    }

    /// Fetch conntrack metadata (traffic + cancel) for an existing NAT entry.
    pub async fn get_conntrack_meta(
        &self,
        key: &NatKey,
    ) -> Option<(Arc<dyn TrafficRecorder>, CancellationToken)> {
        if let Some(mut e) = self.map.get_mut(key) {
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
            if let Some(meta) = &e.conntrack {
                return Some((meta.traffic.clone(), meta.cancel.clone()));
            }
        }
        None
    }

    /// Insert or update a NAT entry with optional conntrack metadata.
    pub async fn insert_with_meta(
        &self,
        key: NatKey,
        upstream: Arc<UdpSocket>,
        conntrack: Option<UdpConntrackMeta>,
    ) -> bool {
        self.pre_evict().await;

        let now = self.now();
        if let Some(mut e) = self.map.get_mut(&key) {
            e.gen = e.gen.wrapping_add(1);
            e.last_seen = now;
            e.expiry = now + self.ttl;
            e.upstream = upstream;
            if conntrack.is_some() {
                e.conntrack = conntrack;
            }
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
            return true;
        }

        if self.map.len() >= self.cap {
            return false;
        }

        let entry = NatEntry {
            upstream,
            last_seen: now,
            expiry: now + self.ttl,
            gen: 1,
            bytes_in: 0,
            bytes_out: 0,
            conntrack,
        };
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
        true
    }

    /// Update conntrack metadata for an existing NAT entry.
    pub async fn set_conntrack_meta(&self, key: &NatKey, conntrack: Option<UdpConntrackMeta>) {
        if let Some(mut e) = self.map.get_mut(key) {
            e.conntrack = conntrack;
        }
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
            conntrack: None,
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

    /// 异步版本：允许通过异步工厂创建上游 socket，并返回 (socket, 是否新建)
    pub async fn get_or_insert_with_async<Fut, F>(
        &self,
        key: NatKey,
        make: F,
    ) -> (Arc<UdpSocket>, bool)
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Arc<UdpSocket>> + Send,
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
            return (e.upstream.clone(), false);
        }

        let now = self.now();
        let upstream = make().await;
        let entry = NatEntry {
            upstream: upstream.clone(),
            last_seen: now,
            expiry: now + self.ttl,
            gen: 1,
            bytes_in: 0,
            bytes_out: 0,
            conntrack: None,
        };
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
        (upstream, true)
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
        use EvictResult::{GenMismatch, Keep, Removed};
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
        if let Some((_k, entry)) = self.map.remove(&item.key) {
            if let Some(meta) = entry.conntrack {
                meta.cancel.cancel();
            }
        }
        let reason = reason_override.unwrap_or("expiry");
        Removed(reason)
    }
}

enum EvictResult {
    Removed(&'static str),
    GenMismatch,
    Keep,
}
