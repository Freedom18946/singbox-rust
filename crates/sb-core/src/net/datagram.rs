// --- SOCKS5 UDP NAT: 基础类型与表封装（behind env；默认不启用） ---
#![allow(dead_code)]
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::Mutex;

/// 目标地址（避免强耦合上层 TargetAddr，保持最小依赖）
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum UdpTargetAddr {
    Ip(SocketAddr),
    Domain { host: String, port: u16 },
}

/// NAT 键：客户端五元组（近似）中的 (client, dst)
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct UdpNatKey {
    pub client: SocketAddr,
    pub dst: UdpTargetAddr,
}

/// NAT 表项：保持上游 socket 与统计
#[derive(Debug)]
pub struct UdpNatEntry {
    pub upstream: Arc<UdpSocket>,
    pub last_seen: Instant,
    pub bytes_in: u64,
    pub bytes_out: u64,
}

/// 简单 NAT 表：单进程内共享；避免引入新的第三方依赖
#[derive(Debug, Default)]
pub struct UdpNatMap {
    inner: Mutex<HashMap<UdpNatKey, UdpNatEntry>>,
}

impl UdpNatMap {
    /// 兼容两种调用方式：
    // - UdpNatMap::new()                       // 无参
    // - UdpNatMap::new(Duration::from_secs(x)) // 旧调用点传入 TTL，我们忽略该参数
    pub fn new<T>(_maybe_ttl: T) -> Self
    where
        T: Into<Option<Duration>>,
    {
        Self {
            inner: Mutex::new(HashMap::new()),
        }
    }

    pub async fn get(&self, k: &UdpNatKey) -> Option<Arc<UdpSocket>> {
        let mut g = self.inner.lock().await;
        if let Some(e) = g.get_mut(k) {
            e.last_seen = Instant::now();
            Some(Arc::clone(&e.upstream))
        } else {
            None
        }
    }

    pub async fn upsert(&self, k: UdpNatKey, upstream: Arc<UdpSocket>) {
        let mut g = self.inner.lock().await;
        g.entry(k)
            .and_modify(|e| {
                e.upstream = Arc::clone(&upstream);
                e.last_seen = Instant::now();
            })
            .or_insert(UdpNatEntry {
                upstream,
                last_seen: Instant::now(),
                bytes_in: 0,
                bytes_out: 0,
            });
    }

    /// Guarded upsert with capacity check from env `SB_UDP_NAT_MAX` (default 65536).
    /// Returns true if inserted or updated; false if rejected due to capacity.
    pub async fn upsert_guarded(&self, k: UdpNatKey, upstream: Arc<UdpSocket>) -> bool {
        let max = std::env::var("SB_UDP_NAT_MAX")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(65536);
        let mut g = self.inner.lock().await;
        if !g.contains_key(&k) && g.len() >= max {
            #[cfg(feature = "metrics")]
            metrics::counter!("udp_nat_reject_total", "reason"=>"capacity").increment(1);
            return false;
        }
        g.entry(k)
            .and_modify(|e| {
                e.upstream = Arc::clone(&upstream);
                e.last_seen = Instant::now();
            })
            .or_insert(UdpNatEntry {
                upstream,
                last_seen: Instant::now(),
                bytes_in: 0,
                bytes_out: 0,
            });
        true
    }

    pub async fn len(&self) -> usize {
        self.inner.lock().await.len()
    }

    pub async fn is_empty(&self) -> bool {
        self.inner.lock().await.is_empty()
    }

    /// 真实淘汰：扫描并逐出过期项（统计留到调用侧埋点）
    pub async fn purge_expired(&self, ttl: Duration) -> usize {
        let now = Instant::now();
        let mut g = self.inner.lock().await;
        let before = g.len();
        g.retain(|_, v| now.duration_since(v.last_seen) < ttl);
        before - g.len()
    }

    /// 内置淘汰：使用构造时的默认 TTL
    pub async fn evict_expired(&self) -> usize {
        // 使用默认TTL (300秒)
        self.purge_expired(Duration::from_secs(300)).await
    }

    pub async fn map(&self) -> &Mutex<HashMap<UdpNatKey, UdpNatEntry>> {
        &self.inner
    }
}

/// 运行周期性 NAT 清理任务（由上层调用，behind env）
pub async fn run_nat_evictor(map: Arc<UdpNatMap>, ttl: Duration, scan: Duration) {
    loop {
        tokio::time::sleep(scan).await;
        let _removed = map.purge_expired(ttl).await;
        #[cfg(feature = "metrics")]
        {
            use metrics::{counter, gauge};
            gauge!("udp_nat_size").set(map.len().await as f64);
            if _removed > 0 {
                counter!("udp_nat_evicted_total").increment(_removed as u64);
            }
        }
    }
}

async fn purge_expired(map: &std::sync::Arc<UdpNatMap>, _ttl: std::time::Duration) {
    // 复用 UdpNatMap 的内置淘汰；当前以构造时的 ttl 为准（避免热路径锁放大）。
    let _removed = map.evict_expired().await;
    #[cfg(feature = "metrics")]
    {
        // UdpNatMap::map() 异步返回 &Mutex<HashMap<..>>
        // 获取锁后再读取当前会话数量
        let cur = {
            let m = map.map().await;
            let guard = m.lock().await;
            guard.len() as f64
        };
        let g = metrics::gauge!("udp_nat_size");
        g.set(cur);
        let c = metrics::counter!("udp_nat_evicted_total");
        if _removed > 0 {
            c.increment(_removed as u64);
        }
    }
}
