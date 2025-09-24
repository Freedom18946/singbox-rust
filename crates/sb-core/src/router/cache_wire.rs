//! R121: 将真实路由决策缓存接到 cache_stats / cache_hot 提供者（适配层）
//! - 提供 trait：`DecisionCacheSource` 暴露 size/capacity/hits/misses 与热点迭代
//! - 提供注册函数：`register_router_decision_cache_adapter(src)` / `register_router_hot_adapter(src)`
//! - 若启用 `router_cache_lru_demo`，实现一个内置 LRU 以便测试演示；否则仅适配外部缓存实现
use super::{cache_hot, cache_stats};
use std::sync::OnceLock;

pub fn clear_cache_metrics() {
    if let Some(src) = SRC.get() {
        // For demo LRU implementation, we don't expose a clear method
        // This is just a placeholder for when real cache implementations are wired
        let _ = src;
    }
}

pub trait DecisionCacheSource: Send + Sync + 'static {
    fn size(&self) -> usize;
    fn capacity(&self) -> usize;
    fn hits(&self) -> u64;
    fn misses(&self) -> u64;
    /// 返回前 N 个热点项的（hash_prefix, hits）
    fn topn(&self, n: usize) -> Vec<(String, u64)>;
}

static SRC: OnceLock<&'static dyn DecisionCacheSource> = OnceLock::new();

pub fn register_router_decision_cache_adapter(src: &'static dyn DecisionCacheSource) {
    let _ = SRC.set(src);
    cache_stats::register_provider(cache_stats_provider);
}

fn cache_stats_provider() -> cache_stats::CacheStats {
    if let Some(src) = SRC.get() {
        cache_stats::CacheStats {
            enabled: true,
            size: src.size() as u64,
            capacity: src.capacity() as u64,
            hits: src.hits(),
            misses: src.misses(),
        }
    } else {
        cache_stats::CacheStats::default()
    }
}

pub fn register_router_hot_adapter(src: &'static dyn DecisionCacheSource) {
    cache_hot::register_hot_provider(cache_hot_provider);
}

fn cache_hot_provider(limit: usize) -> Vec<cache_hot::HotItem> {
    if let Some(src) = SRC.get() {
        src.topn(limit)
            .into_iter()
            .map(|(hp, h)| cache_hot::HotItem {
                hash_prefix: hp,
                hits: h,
            })
            .collect()
    } else {
        Vec::new()
    }
}

// 可选：内置 LRU 演示（测试/示例用）
#[cfg(feature = "router_cache_lru_demo")]
pub mod demo_lru {
    use super::*;
    use blake3::Hasher;
    use lru::LruCache;
    use std::num::NonZeroUsize;
    use std::sync::{Arc, Mutex};

    pub struct LruDecision {
        inner: Arc<Mutex<LruCache<u64, u64>>>,
        cap: usize,
        hits: std::sync::atomic::AtomicU64,
        misses: std::sync::atomic::AtomicU64,
    }
    impl LruDecision {
        pub fn new(cap: usize) -> Self {
            Self {
                inner: Arc::new(Mutex::new(LruCache::new(
                    NonZeroUsize::new(cap.max(1)).unwrap(),
                ))),
                cap,
                hits: 0.into(),
                misses: 0.into(),
            }
        }
        fn h(s: &str) -> u64 {
            let mut hasher = Hasher::new();
            hasher.update(s.as_bytes());
            u64::from_le_bytes(hasher.finalize().as_bytes()[..8].try_into().unwrap())
        }
        pub fn get(&self, k: &str) -> Option<u64> {
            let mut g = self.inner.lock().unwrap();
            let ok = g.get(&Self::h(k)).cloned();
            if ok.is_some() {
                self.hits.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            } else {
                self.misses
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            };
            ok
        }
        pub fn put(&self, k: &str, v: u64) {
            let mut g = self.inner.lock().unwrap();
            let _ = g.put(Self::h(k), v);
        }
    }
    impl DecisionCacheSource for LruDecision {
        fn size(&self) -> usize {
            self.inner.lock().unwrap().len()
        }
        fn capacity(&self) -> usize {
            self.cap
        }
        fn hits(&self) -> u64 {
            self.hits.load(std::sync::atomic::Ordering::Relaxed)
        }
        fn misses(&self) -> u64 {
            self.misses.load(std::sync::atomic::Ordering::Relaxed)
        }
        fn topn(&self, n: usize) -> Vec<(String, u64)> {
            let g = self.inner.lock().unwrap();
            g.iter()
                .take(n)
                .map(|(k, _)| (format!("{:016x}", k), 1))
                .collect()
        }
    }
}
