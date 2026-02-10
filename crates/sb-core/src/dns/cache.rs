//! DNS 缓存实现
//!
//! 提供高效的 DNS 缓存机制，支持：
//! - TTL 过期管理
//! - LRU 淘汰策略
//! - 负缓存支持
//! - 缓存指标暴露

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use super::DnsAnswer;

/// DNS 解析来源
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Source {
    /// 静态配置
    Static,
    /// 系统解析器
    System,
    /// 上游 DNS 服务器
    Upstream,
}

/// DNS 响应码
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Rcode {
    NoError,
    FormErr,
    ServFail,
    NxDomain,
    NotImp,
    Refused,
    Other(u8),
}

impl Rcode {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::NoError => "NOERROR",
            Self::FormErr => "FORMERR",
            Self::ServFail => "SERVFAIL",
            Self::NxDomain => "NXDOMAIN",
            Self::NotImp => "NOTIMP",
            Self::Refused => "REFUSED",
            Self::Other(_) => "OTHER",
        }
    }
}

/// DNS cache query key for lookups.
///
/// When `independent_cache` is enabled, `transport_tag` is populated so that
/// different upstreams maintain separate cache entries for the same domain+qtype.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Key {
    pub name: String,
    pub qtype: QType,
    /// When independent_cache is enabled, this field contains the upstream/transport
    /// tag so that different transports don't share cached results.
    pub transport_tag: Option<String>,
}

/// DNS query type
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum QType {
    A,     // IPv4 address
    AAAA,  // IPv6 address
    CNAME, // Canonical name
    Other(u16),
}

impl QType {
    pub const fn from_u16(value: u16) -> Self {
        match value {
            1 => Self::A,
            28 => Self::AAAA,
            5 => Self::CNAME,
            other => Self::Other(other),
        }
    }

    pub const fn to_u16(&self) -> u16 {
        match self {
            Self::A => 1,
            Self::AAAA => 28,
            Self::CNAME => 5,
            Self::Other(value) => *value,
        }
    }
}

/// Cache hit information
#[derive(Clone, Debug)]
pub enum HitKind {
    Miss,
    Hit,
    Expired,
}

/// DNS cache entry with metadata
#[derive(Clone, Debug)]
pub struct Entry {
    pub answer: DnsAnswer,
    pub created_at: std::time::Instant,
    pub hit_kind: HitKind,
}

/// Internal DNS 缓存条目
#[derive(Clone, Debug)]
struct CacheEntry {
    /// 缓存的 DNS 答案
    answer: DnsAnswer,
    /// 条目创建时间
    created_at: Instant,
    /// 访问次数（用于 LRU）
    access_count: u64,
    /// 最后访问时间
    last_accessed: Instant,
    /// 是否为负缓存（查询失败的结果）
    is_negative: bool,
}

impl CacheEntry {
    fn new(answer: DnsAnswer, is_negative: bool) -> Self {
        let now = Instant::now();
        Self {
            answer,
            created_at: now,
            access_count: 1,
            last_accessed: now,
            is_negative,
        }
    }

    /// 检查条目是否已过期
    fn is_expired(&self) -> bool {
        self.created_at.elapsed() > self.answer.ttl
    }

    /// 更新访问统计
    fn touch(&mut self) {
        self.access_count += 1;
        self.last_accessed = Instant::now();
    }

    /// 获取剩余 TTL
    fn remaining_ttl(&self) -> Duration {
        let elapsed = self.created_at.elapsed();
        if elapsed >= self.answer.ttl {
            Duration::ZERO
        } else {
            self.answer.ttl - elapsed
        }
    }
}

/// DNS 缓存实现
pub struct DnsCache {
    /// 缓存存储 - 使用完整的Key（包含域名和查询类型）
    cache: Arc<Mutex<HashMap<Key, CacheEntry>>>,
    /// 最大缓存条目数
    max_entries: usize,
    /// 负缓存 TTL
    negative_ttl: Duration,
    /// 最小 TTL（防止过短的 TTL）
    min_ttl: Duration,
    /// 最大 TTL（防止过长的 TTL）
    max_ttl: Duration,
    /// When true, cached entries never expire based on TTL; only LRU eviction removes them.
    /// Corresponds to `disable_expire` in sing-box Go configuration.
    disable_expire: bool,
}

impl DnsCache {
    /// 创建新的 DNS 缓存
    pub fn new(max_entries: usize) -> Self {
        let negative_ttl = Duration::from_secs(
            std::env::var("SB_DNS_NEGATIVE_TTL_S")
                .ok()
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(300),
        );

        let min_ttl = Duration::from_secs(
            std::env::var("SB_DNS_MIN_TTL_S")
                .ok()
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(5),
        );

        let max_ttl = Duration::from_secs(
            std::env::var("SB_DNS_MAX_TTL_S")
                .ok()
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(3600),
        );

        Self {
            cache: Arc::new(Mutex::new(HashMap::new())),
            max_entries,
            negative_ttl,
            min_ttl,
            max_ttl,
            disable_expire: false,
        }
    }

    /// Set whether TTL-based expiry is disabled.
    ///
    /// When `disable_expire` is `true`, entries are never considered expired by
    /// TTL; only LRU eviction removes them. This is useful for environments
    /// where stale answers are preferred over re-querying.
    pub fn with_disable_expire(mut self, disable: bool) -> Self {
        self.disable_expire = disable;
        self
    }

    /// Returns whether TTL-based expiry is disabled.
    pub fn disable_expire(&self) -> bool {
        self.disable_expire
    }

    /// 从缓存获取 DNS 答案
    pub fn get(&self, key: &Key) -> Option<DnsAnswer> {
        let mut cache = match self.cache.lock() {
            Ok(g) => g,
            Err(_e) => {
                tracing::error!(target: "sb_core::dns::cache", "cache lock poisoned on get");
                return None;
            }
        };

        if let Some(entry) = cache.get_mut(key) {
            // When disable_expire is true, skip the TTL expiry check entirely;
            // entries are only removed via LRU eviction.
            if !self.disable_expire && entry.is_expired() {
                // 条目已过期，移除
                cache.remove(key);

                #[cfg(feature = "metrics")]
                metrics::counter!("dns_cache_total", "result" => "expired").increment(1);

                return None;
            }

            // 更新访问统计
            entry.touch();

            #[cfg(feature = "metrics")]
            metrics::counter!("dns_cache_total", "result" => "hit").increment(1);

            // 返回带有剩余 TTL 的答案
            let mut answer = entry.answer.clone();
            // When disable_expire is true, return the original TTL so callers
            // don't see a zero/negative value.
            if !self.disable_expire {
                answer.ttl = entry.remaining_ttl();
            }

            Some(answer)
        } else {
            #[cfg(feature = "metrics")]
            metrics::counter!("dns_cache_total", "result" => "miss").increment(1);

            None
        }
    }

    /// 将 DNS 答案存入缓存
    pub fn put(&self, key: Key, mut answer: DnsAnswer) {
        // 调整 TTL 到合理范围
        answer.ttl = answer.ttl.clamp(self.min_ttl, self.max_ttl);

        let mut cache = match self.cache.lock() {
            Ok(g) => g,
            Err(_e) => {
                tracing::error!(target: "sb_core::dns::cache", "cache lock poisoned on put");
                return;
            }
        };

        // 如果缓存已满，执行 LRU 淘汰
        if cache.len() >= self.max_entries && !cache.contains_key(&key) {
            self.evict_lru(&mut cache);
        }

        // 插入新条目
        let entry = CacheEntry::new(answer, false);
        cache.insert(key, entry);

        #[cfg(feature = "metrics")]
        {
            metrics::counter!("dns_cache_total", "result" => "put").increment(1);
            metrics::gauge!("dns_cache_size").set(cache.len() as f64);
        }
    }

    /// 将查询失败结果存入负缓存
    pub fn put_negative(&self, key: Key) {
        let answer = DnsAnswer::new(
            Vec::new(),
            self.negative_ttl,
            Source::System,
            Rcode::NxDomain,
        );

        let mut cache = match self.cache.lock() {
            Ok(g) => g,
            Err(_e) => {
                tracing::error!(target: "sb_core::dns::cache", "cache lock poisoned on put_negative");
                return;
            }
        };

        // 如果缓存已满，执行 LRU 淘汰
        if cache.len() >= self.max_entries && !cache.contains_key(&key) {
            self.evict_lru(&mut cache);
        }

        // 插入负缓存条目
        let entry = CacheEntry::new(answer, true);
        cache.insert(key, entry);

        #[cfg(feature = "metrics")]
        {
            metrics::counter!("dns_cache_total", "result" => "put_negative").increment(1);
            metrics::gauge!("dns_cache_size").set(cache.len() as f64);
        }
    }

    /// 清除过期条目
    ///
    /// When `disable_expire` is `true`, this is a no-op since entries are never
    /// considered expired by TTL.
    pub fn cleanup_expired(&self) {
        if self.disable_expire {
            return;
        }

        let mut cache = match self.cache.lock() {
            Ok(g) => g,
            Err(_e) => {
                tracing::error!(target: "sb_core::dns::cache", "cache lock poisoned on cleanup_expired");
                return;
            }
        };
        let initial_size = cache.len();

        cache.retain(|_, entry| !entry.is_expired());

        let removed = initial_size - cache.len();
        if removed > 0 {
            #[cfg(feature = "metrics")]
            {
                metrics::counter!("dns_cache_cleanup_total").increment(removed as u64);
                metrics::gauge!("dns_cache_size").set(cache.len() as f64);
            }

            tracing::debug!("Cleaned up {} expired DNS cache entries", removed);
        }
    }

    /// 清空缓存
    pub fn clear(&self) {
        let mut cache = match self.cache.lock() {
            Ok(g) => g,
            Err(_e) => {
                tracing::error!(target: "sb_core::dns::cache", "cache lock poisoned on clear");
                return;
            }
        };
        let size = cache.len();
        cache.clear();

        #[cfg(feature = "metrics")]
        {
            metrics::counter!("dns_cache_clear_total").increment(1);
            metrics::gauge!("dns_cache_size").set(0.0);
        }

        tracing::debug!("Cleared {} DNS cache entries", size);
    }

    /// 获取缓存统计信息
    pub fn stats(&self) -> CacheStats {
        let cache = match self.cache.lock() {
            Ok(g) => g,
            Err(_e) => {
                tracing::error!(target: "sb_core::dns::cache", "cache lock poisoned on stats");
                return CacheStats {
                    total_entries: 0,
                    expired_entries: 0,
                    negative_entries: 0,
                    max_entries: self.max_entries,
                };
            }
        };
        let mut expired_count = 0;
        let mut negative_count = 0;

        for entry in cache.values() {
            if !self.disable_expire && entry.is_expired() {
                expired_count += 1;
            }
            if entry.is_negative {
                negative_count += 1;
            }
        }

        CacheStats {
            total_entries: cache.len(),
            expired_entries: expired_count,
            negative_entries: negative_count,
            max_entries: self.max_entries,
        }
    }

    /// 查看指定域名的剩余TTL，不更新访问统计
    pub fn peek_remaining(&self, key: &Key) -> Option<Duration> {
        let cache = match self.cache.lock() {
            Ok(g) => g,
            Err(_e) => {
                tracing::error!(target: "sb_core::dns::cache", "cache lock poisoned on peek_remaining");
                return None;
            }
        };

        if let Some(entry) = cache.get(key) {
            if !self.disable_expire && entry.is_expired() {
                None
            } else if self.disable_expire {
                // Return original TTL when expiry is disabled
                Some(entry.answer.ttl)
            } else {
                Some(entry.remaining_ttl())
            }
        } else {
            None
        }
    }

    /// LRU 淘汰策略
    fn evict_lru(&self, cache: &mut HashMap<Key, CacheEntry>) {
        if cache.is_empty() {
            return;
        }

        // 找到最少使用的条目
        let lru_key = cache
            .iter()
            .min_by_key(|(_, entry)| (entry.access_count, entry.last_accessed))
            .map(|(key, _)| key.clone());

        if let Some(key) = lru_key {
            cache.remove(&key);

            #[cfg(feature = "metrics")]
            metrics::counter!("dns_cache_evict_total", "reason" => "lru").increment(1);

            tracing::debug!(
                "Evicted DNS cache entry: {}:{:?} (transport: {:?})",
                key.name,
                key.qtype,
                key.transport_tag,
            );
        }
    }
}

/// 缓存统计信息
#[derive(Debug, Clone)]
pub struct CacheStats {
    /// 总条目数
    pub total_entries: usize,
    /// 过期条目数
    pub expired_entries: usize,
    /// 负缓存条目数
    pub negative_entries: usize,
    /// 最大条目数
    pub max_entries: usize,
}

/// 缓存管理器，提供后台清理任务
pub struct CacheManager {
    cache: Arc<DnsCache>,
    cleanup_interval: Duration,
}

impl CacheManager {
    /// 创建新的缓存管理器
    pub fn new(cache: Arc<DnsCache>) -> Self {
        let cleanup_interval = Duration::from_secs(
            std::env::var("SB_DNS_CACHE_CLEANUP_INTERVAL_S")
                .ok()
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(300),
        );

        Self {
            cache,
            cleanup_interval,
        }
    }

    /// 启动后台清理任务
    pub fn start_cleanup_task(&self) -> tokio::task::JoinHandle<()> {
        let cache = self.cache.clone();
        let interval = self.cleanup_interval;

        tokio::spawn(async move {
            let mut cleanup_timer = tokio::time::interval(interval);

            loop {
                cleanup_timer.tick().await;
                cache.cleanup_expired();
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    /// Helper to create a basic Key without transport_tag.
    fn make_key(name: &str) -> Key {
        Key {
            name: name.to_string(),
            qtype: QType::A,
            transport_tag: None,
        }
    }

    /// Helper to create a Key with a transport_tag (for independent_cache tests).
    fn make_key_with_transport(name: &str, tag: &str) -> Key {
        Key {
            name: name.to_string(),
            qtype: QType::A,
            transport_tag: Some(tag.to_string()),
        }
    }

    /// Helper to create a simple DnsAnswer.
    fn make_answer(ip_last: u8, ttl: Duration) -> DnsAnswer {
        DnsAnswer {
            ips: vec![IpAddr::V4(Ipv4Addr::new(1, 2, 3, ip_last))],
            ttl,
            source: Source::System,
            rcode: Rcode::NoError,
            created_at: Instant::now(),
        }
    }

    #[test]
    fn test_cache_basic_operations() {
        let cache = DnsCache::new(10);
        let key = make_key("example.com");

        // 缓存未命中
        assert!(cache.get(&key).is_none());

        // 存入缓存
        let answer = make_answer(4, Duration::from_secs(300));
        cache.put(key.clone(), answer.clone());

        // 缓存命中
        let cached = cache.get(&key).unwrap();
        assert_eq!(cached.ips, answer.ips);
        assert!(cached.ttl <= answer.ttl); // TTL 应该减少
    }

    #[test]
    fn test_negative_cache() {
        let cache = DnsCache::new(10);
        let key = make_key("nonexistent.com");

        // 存入负缓存
        cache.put_negative(key.clone());

        // 负缓存命中
        let cached = cache.get(&key).unwrap();
        assert!(cached.ips.is_empty());
    }

    #[test]
    fn test_cache_expiration() {
        // 设置较小的 min_ttl 用于测试
        std::env::set_var("SB_DNS_MIN_TTL_S", "0");

        let cache = DnsCache::new(10);
        let key = make_key("example.com");

        // 存入短 TTL 的条目
        let answer = make_answer(4, Duration::from_millis(10));
        cache.put(key.clone(), answer);

        // 等待过期
        std::thread::sleep(Duration::from_millis(50));

        // 应该返回 None（已过期）
        assert!(cache.get(&key).is_none());

        // 清理环境变量
        std::env::remove_var("SB_DNS_MIN_TTL_S");
    }

    #[test]
    fn test_cache_stats() {
        let cache = DnsCache::new(10);

        // 添加一些条目
        for i in 0..5 {
            let domain = format!("example{}.com", i);
            let key = Key {
                name: domain,
                qtype: QType::A,
                transport_tag: None,
            };
            let answer = make_answer(i as u8, Duration::from_secs(300));
            cache.put(key, answer);
        }

        // 添加负缓存
        let neg_key = make_key("nonexistent.com");
        cache.put_negative(neg_key);

        let stats = cache.stats();
        assert_eq!(stats.total_entries, 6);
        assert_eq!(stats.negative_entries, 1);
        assert_eq!(stats.max_entries, 10);
    }

    #[tokio::test]
    async fn test_cache_manager() {
        // 设置较小的 min_ttl 用于测试
        std::env::set_var("SB_DNS_MIN_TTL_S", "0");

        let cache = Arc::new(DnsCache::new(10));
        let _manager = CacheManager::new(cache.clone());

        // 添加一个短 TTL 的条目
        let answer = make_answer(4, Duration::from_millis(50));
        let key = make_key("example.com");
        cache.put(key.clone(), answer);

        // 启动清理任务（短间隔用于测试）
        let cache_clone = cache.clone();
        let _cleanup_task = tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_millis(100));
            loop {
                interval.tick().await;
                cache_clone.cleanup_expired();
            }
        });

        // 等待清理
        tokio::time::sleep(Duration::from_millis(200)).await;

        // 条目应该被清理
        assert!(cache.get(&key).is_none());

        // 清理环境变量
        std::env::remove_var("SB_DNS_MIN_TTL_S");
    }

    // =========================================================================
    // L2.10.18: Independent cache per-transport
    // =========================================================================

    #[test]
    fn test_independent_cache_different_transport_tags_are_separate() {
        let cache = DnsCache::new(100);

        // Same domain, same qtype, but different transport tags.
        let key_upstream_a = make_key_with_transport("example.com", "google-dns");
        let key_upstream_b = make_key_with_transport("example.com", "cloudflare-dns");

        let answer_a = make_answer(1, Duration::from_secs(300));
        let answer_b = make_answer(2, Duration::from_secs(300));

        cache.put(key_upstream_a.clone(), answer_a.clone());
        cache.put(key_upstream_b.clone(), answer_b.clone());

        // Each transport tag should return its own answer.
        let cached_a = cache.get(&key_upstream_a).unwrap();
        assert_eq!(cached_a.ips[0], IpAddr::V4(Ipv4Addr::new(1, 2, 3, 1)));

        let cached_b = cache.get(&key_upstream_b).unwrap();
        assert_eq!(cached_b.ips[0], IpAddr::V4(Ipv4Addr::new(1, 2, 3, 2)));
    }

    #[test]
    fn test_independent_cache_none_tag_separate_from_tagged() {
        let cache = DnsCache::new(100);

        // Key without transport_tag (shared cache mode)
        let key_shared = make_key("example.com");
        // Key with transport_tag (independent cache mode)
        let key_tagged = make_key_with_transport("example.com", "upstream-1");

        let answer_shared = make_answer(10, Duration::from_secs(300));
        let answer_tagged = make_answer(20, Duration::from_secs(300));

        cache.put(key_shared.clone(), answer_shared);
        cache.put(key_tagged.clone(), answer_tagged);

        let cached_shared = cache.get(&key_shared).unwrap();
        assert_eq!(cached_shared.ips[0], IpAddr::V4(Ipv4Addr::new(1, 2, 3, 10)));

        let cached_tagged = cache.get(&key_tagged).unwrap();
        assert_eq!(cached_tagged.ips[0], IpAddr::V4(Ipv4Addr::new(1, 2, 3, 20)));
    }

    #[test]
    fn test_independent_cache_same_tag_shares() {
        let cache = DnsCache::new(100);

        let key1 = make_key_with_transport("example.com", "upstream-1");
        let key2 = make_key_with_transport("example.com", "upstream-1");

        let answer = make_answer(42, Duration::from_secs(300));
        cache.put(key1.clone(), answer);

        // Same transport_tag should share the entry.
        let cached = cache.get(&key2).unwrap();
        assert_eq!(cached.ips[0], IpAddr::V4(Ipv4Addr::new(1, 2, 3, 42)));
    }

    #[test]
    fn test_independent_cache_stats_counts_all_entries() {
        let cache = DnsCache::new(100);

        // Insert same domain with two different transport tags.
        let key_a = make_key_with_transport("example.com", "dns-a");
        let key_b = make_key_with_transport("example.com", "dns-b");

        cache.put(key_a, make_answer(1, Duration::from_secs(300)));
        cache.put(key_b, make_answer(2, Duration::from_secs(300)));

        let stats = cache.stats();
        // Two separate entries for the same domain but different transport tags.
        assert_eq!(stats.total_entries, 2);
    }

    // =========================================================================
    // L2.10.19: disable_expire support
    // =========================================================================

    #[test]
    fn test_disable_expire_entries_never_expire() {
        // Use min_ttl=0 so the short TTL isn't clamped up.
        std::env::set_var("SB_DNS_MIN_TTL_S", "0");

        let cache = DnsCache::new(10).with_disable_expire(true);
        assert!(cache.disable_expire());

        let key = make_key("example.com");
        let answer = make_answer(4, Duration::from_millis(10));
        cache.put(key.clone(), answer.clone());

        // Wait well past the TTL.
        std::thread::sleep(Duration::from_millis(50));

        // Entry should still be returned because disable_expire is true.
        let cached = cache.get(&key);
        assert!(
            cached.is_some(),
            "entry should not expire when disable_expire is true"
        );
        let cached = cached.unwrap();
        assert_eq!(cached.ips, answer.ips);
        // TTL should be the original value, not a decremented one.
        assert_eq!(cached.ttl, Duration::from_millis(10));

        std::env::remove_var("SB_DNS_MIN_TTL_S");
    }

    #[test]
    fn test_disable_expire_false_entries_still_expire() {
        std::env::set_var("SB_DNS_MIN_TTL_S", "0");

        let cache = DnsCache::new(10).with_disable_expire(false);
        assert!(!cache.disable_expire());

        let key = make_key("expire-test.com");
        let answer = make_answer(5, Duration::from_millis(10));
        cache.put(key.clone(), answer);

        std::thread::sleep(Duration::from_millis(50));

        // Should expire normally.
        assert!(cache.get(&key).is_none());

        std::env::remove_var("SB_DNS_MIN_TTL_S");
    }

    #[test]
    fn test_disable_expire_cleanup_is_noop() {
        std::env::set_var("SB_DNS_MIN_TTL_S", "0");

        let cache = DnsCache::new(10).with_disable_expire(true);

        let key = make_key("cleanup-test.com");
        let answer = make_answer(6, Duration::from_millis(10));
        cache.put(key.clone(), answer);

        std::thread::sleep(Duration::from_millis(50));

        // cleanup_expired should be a no-op when disable_expire is true.
        cache.cleanup_expired();

        let stats = cache.stats();
        assert_eq!(
            stats.total_entries, 1,
            "cleanup_expired should not remove entries when disable_expire is true"
        );
        assert_eq!(
            stats.expired_entries, 0,
            "no entries should be counted as expired when disable_expire is true"
        );

        // Entry should still be accessible.
        assert!(cache.get(&key).is_some());

        std::env::remove_var("SB_DNS_MIN_TTL_S");
    }

    #[test]
    fn test_disable_expire_lru_eviction_still_works() {
        std::env::set_var("SB_DNS_MIN_TTL_S", "0");

        // Cache with capacity of 2.
        let cache = DnsCache::new(2).with_disable_expire(true);

        let key1 = make_key("first.com");
        let key2 = make_key("second.com");
        let key3 = make_key("third.com");

        cache.put(key1.clone(), make_answer(1, Duration::from_millis(10)));
        cache.put(key2.clone(), make_answer(2, Duration::from_millis(10)));

        // Access key2 to make key1 the LRU candidate.
        let _ = cache.get(&key2);

        // Inserting key3 should evict the LRU entry (key1).
        cache.put(key3.clone(), make_answer(3, Duration::from_millis(10)));

        assert!(
            cache.get(&key1).is_none(),
            "LRU entry should be evicted even with disable_expire"
        );
        assert!(
            cache.get(&key2).is_some(),
            "recently accessed entry should survive"
        );
        assert!(
            cache.get(&key3).is_some(),
            "newly inserted entry should exist"
        );

        std::env::remove_var("SB_DNS_MIN_TTL_S");
    }

    #[test]
    fn test_disable_expire_peek_remaining_returns_original_ttl() {
        std::env::set_var("SB_DNS_MIN_TTL_S", "0");

        let cache = DnsCache::new(10).with_disable_expire(true);

        let key = make_key("peek-test.com");
        let ttl = Duration::from_millis(10);
        cache.put(key.clone(), make_answer(7, ttl));

        std::thread::sleep(Duration::from_millis(50));

        // peek_remaining should return the original TTL when disable_expire is true.
        let remaining = cache.peek_remaining(&key);
        assert!(
            remaining.is_some(),
            "peek_remaining should return Some when disable_expire is true"
        );
        assert_eq!(remaining.unwrap(), ttl);

        std::env::remove_var("SB_DNS_MIN_TTL_S");
    }

    // =========================================================================
    // Combined: independent_cache + disable_expire
    // =========================================================================

    #[test]
    fn test_independent_cache_with_disable_expire() {
        std::env::set_var("SB_DNS_MIN_TTL_S", "0");

        let cache = DnsCache::new(100).with_disable_expire(true);

        let key_a = make_key_with_transport("example.com", "dns-a");
        let key_b = make_key_with_transport("example.com", "dns-b");

        cache.put(key_a.clone(), make_answer(1, Duration::from_millis(10)));
        cache.put(key_b.clone(), make_answer(2, Duration::from_millis(10)));

        // Wait past TTL.
        std::thread::sleep(Duration::from_millis(50));

        // Both entries should still be present (disable_expire) and independent.
        let cached_a = cache.get(&key_a).unwrap();
        assert_eq!(cached_a.ips[0], IpAddr::V4(Ipv4Addr::new(1, 2, 3, 1)));

        let cached_b = cache.get(&key_b).unwrap();
        assert_eq!(cached_b.ips[0], IpAddr::V4(Ipv4Addr::new(1, 2, 3, 2)));

        std::env::remove_var("SB_DNS_MIN_TTL_S");
    }
}
