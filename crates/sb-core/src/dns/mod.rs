//! DNS facilities
//! - 默认仅提供轻量 stub（不依赖 reqwest）
//! - 当启用 `dns_http` 特性时，编译 HTTP DNS 客户端（使用 reqwest blocking + rustls）

use std::collections::HashMap;
#[cfg(any(test, feature = "dns_cache", feature = "dev-cli"))]
use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use async_trait::async_trait;

#[cfg(feature = "dns_cache")]
use cache::{Key as CacheKey, QType as CacheQType};

pub mod cache;
pub mod cache_v2;
pub mod client;
#[cfg(feature = "dns_doh")]
pub mod doh;
#[cfg(all(feature = "dns_dot", feature = "tls_rustls"))]
pub mod dot;
pub mod enhanced_client;
#[cfg(feature = "dns_http")]
pub mod http_client;
pub mod message;
pub mod metrics;
pub mod resolve;
pub mod resolver;
pub mod strategy;
pub mod stub;
pub mod system;
pub mod transport;
pub mod upstream;
pub mod fakeip;
#[cfg(feature = "router")]
pub mod rule_engine;

#[cfg(test)]
mod integration_tests;
#[cfg(feature = "dns_udp")]
pub mod udp;

/// DNS 解析结果：包含 IP 列表和 TTL 信息
#[derive(Clone, Debug)]
pub struct DnsAnswer {
    /// 解析得到的 IP 地址列表
    pub ips: Vec<IpAddr>,
    /// 缓存 TTL（生存时间）
    pub ttl: Duration,
    /// DNS 解析来源
    pub source: cache::Source,
    /// DNS 响应码
    pub rcode: cache::Rcode,
    /// 创建时间
    pub created_at: Instant,
}

impl DnsAnswer {
    /// 创建新的 DNS 答案
    pub fn new(ips: Vec<IpAddr>, ttl: Duration, source: cache::Source, rcode: cache::Rcode) -> Self {
        Self {
            ips,
            ttl,
            source,
            rcode,
            created_at: Instant::now(),
        }
    }

    /// 检查 DNS 答案是否已过期
    pub fn is_expired(&self) -> bool {
        self.created_at.elapsed() > self.ttl
    }

    /// 获取剩余 TTL
    pub fn remaining_ttl(&self) -> Duration {
        let elapsed = self.created_at.elapsed();
        if elapsed >= self.ttl {
            Duration::ZERO
        } else {
            self.ttl - elapsed
        }
    }

    /// 检查 DNS 答案是否仍然有效
    pub fn is_valid(&self) -> bool {
        !self.is_expired()
    }
}

/// 标准 DNS 解析器接口
#[async_trait]
pub trait Resolver: Send + Sync {
    /// 解析域名到 IP 地址列表
    async fn resolve(&self, domain: &str) -> Result<DnsAnswer>;

    /// 获取解析器名称（用于日志和指标）
    fn name(&self) -> &str;
}

/// DNS 上游服务器抽象
#[async_trait]
pub trait DnsUpstream: Send + Sync {
    /// 执行 DNS 查询
    async fn query(&self, domain: &str, record_type: RecordType) -> Result<DnsAnswer>;

    /// 获取上游名称
    fn name(&self) -> &str;

    /// 检查上游是否可用
    async fn health_check(&self) -> bool;
}

/// DNS 记录类型
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RecordType {
    A = 1,
    AAAA = 28,
    CNAME = 5,
    MX = 15,
    TXT = 16,
}

impl RecordType {
    pub fn as_u16(self) -> u16 {
        self as u16
    }

    pub fn from_u16(value: u16) -> Option<Self> {
        match value {
            1 => Some(RecordType::A),
            28 => Some(RecordType::AAAA),
            5 => Some(RecordType::CNAME),
            15 => Some(RecordType::MX),
            16 => Some(RecordType::TXT),
            _ => None,
        }
    }
}

// 保持向后兼容的旧接口
#[async_trait]
pub trait DnsResolver: Send + Sync {
    async fn resolve(&self, host: &str) -> Result<DnsAnswer>;
}

/// 轻量句柄：持有解析器实现与 enabled 标记（ENV 控制）
#[derive(Clone)]
pub struct ResolverHandle {
    inner: Arc<dyn DnsResolver>,
    enabled: bool,
    #[cfg(feature = "dns_cache")]
    cache: Arc<std::sync::Mutex<crate::dns::cache::DnsCache>>, // 共享 LRU
    static_map: std::collections::HashMap<String, Vec<IpAddr>>, // 静态表优先
    static_ttl: Duration,
    ipv6_enabled: bool,
    // Prefetch
    #[cfg(any(test, feature = "dev-cli"))]
    prefetch_enabled: bool,
    #[cfg(any(test, feature = "dev-cli"))]
    prefetch_before: Duration,
    #[cfg(any(test, feature = "dev-cli"))]
    prefetch_sem: Arc<tokio::sync::Semaphore>,
    #[cfg(any(test, feature = "dev-cli"))]
    prefetch_inflight: Arc<std::sync::Mutex<HashSet<String>>>,
    // Upstream health
    up_health: Arc<std::sync::Mutex<HashMap<String, UpHealth>>>,
    // Inflight gating
    inflight_global: Arc<tokio::sync::Semaphore>,
    inflight_per_host: Arc<std::sync::Mutex<HashMap<String, Arc<tokio::sync::Semaphore>>>>,
}

impl std::fmt::Debug for ResolverHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResolverHandle")
            .field("enabled", &self.enabled)
            .finish()
    }
}

/// RAII 守卫：封装 DNS 并发门控（全局 + 每 host）
// - 构造时获取 permit 并打点 `dns_inflight{scope}`
// - Drop 自动释放 permit 并做对称打点
struct InflightGuards {
    g: Option<tokio::sync::OwnedSemaphorePermit>,
    h: Option<tokio::sync::OwnedSemaphorePermit>,
}

impl InflightGuards {
    async fn acquire(
        global: &Arc<tokio::sync::Semaphore>,
        host_sem: &Arc<tokio::sync::Semaphore>,
    ) -> Self {
        let g = global.clone().acquire_owned().await.ok();
        let h = host_sem.clone().acquire_owned().await.ok();
        #[cfg(feature = "metrics")]
        {
            if g.is_some() {
                ::metrics::gauge!("dns_inflight", "scope" => "global").increment(1.0);
            }
            if h.is_some() {
                ::metrics::gauge!("dns_inflight", "scope" => "per_host").increment(1.0);
            }
        }
        Self { g, h }
    }
}

impl Drop for InflightGuards {
    fn drop(&mut self) {
        // 先释放 permit（通过 drop Option 内部 OwnedSemaphorePermit）
        self.h.take();
        self.g.take();
        // 再做 gauge 对称扣减
        #[cfg(feature = "metrics")]
        {
            ::metrics::gauge!("dns_inflight", "scope" => "per_host").decrement(1.0);
            ::metrics::gauge!("dns_inflight", "scope" => "global").decrement(1.0);
        }
    }
}

impl ResolverHandle {
    /// 从 env 初始化：
    // - SB_DNS_ENABLE=1 时启用；否则标记为 disabled（但仍提供 SystemResolver）
    // - 静态表通过 SB_DNS_STATIC 提供
    pub fn from_env_or_default() -> Self {
        let enabled = std::env::var("SB_DNS_ENABLE")
            .ok()
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
        let default_ttl = Duration::from_secs(
            std::env::var("SB_DNS_DEFAULT_TTL_S")
                .ok()
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(60),
        );
        let _min_ttl = Duration::from_secs(
            std::env::var("SB_DNS_MIN_TTL_S")
                .ok()
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(1),
        );
        let _max_ttl = Duration::from_secs(
            std::env::var("SB_DNS_MAX_TTL_S")
                .ok()
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(600),
        );
        let _neg_ttl = Duration::from_secs(
            std::env::var("SB_DNS_NEG_TTL_S")
                .ok()
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(30),
        );
        let _cap = std::env::var("SB_DNS_CACHE_SIZE")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(1024);
        let ipv6_enabled = std::env::var("SB_DNS_IPV6")
            .ok()
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(true);
        let static_ttl = Duration::from_secs(
            std::env::var("SB_DNS_STATIC_TTL_S")
                .ok()
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(300),
        );
        let static_raw = std::env::var("SB_DNS_STATIC").unwrap_or_default();
        let mut static_map = std::collections::HashMap::new();
        for kv in static_raw
            .split(',')
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
        {
            if let Some((k, v)) = kv.split_once('=') {
                let host = k.trim().to_ascii_lowercase();
                let mut ips = Vec::new();
                for ip_s in v.split(';').map(|s| s.trim()).filter(|s| !s.is_empty()) {
                    if let Ok(ip) = ip_s.parse::<IpAddr>() {
                        ips.push(ip);
                    }
                }
                if !ips.is_empty() {
                    static_map.insert(host, ips);
                }
            }
        }
        #[cfg(feature = "dns_cache")]
        let cache = crate::dns::cache::DnsCache::new(_cap);
        let sys = system::SystemResolver::new(default_ttl);
        #[cfg(any(test, feature = "dev-cli"))]
        let prefetch_enabled = std::env::var("SB_DNS_PREFETCH")
            .ok()
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
        #[cfg(any(test, feature = "dev-cli"))]
        let prefetch_before = Duration::from_millis(
            std::env::var("SB_DNS_PREFETCH_BEFORE_MS")
                .ok()
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(200),
        );
        #[cfg(any(test, feature = "dev-cli"))]
        let prefetch_conc = std::env::var("SB_DNS_PREFETCH_CONCURRENCY")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(4);
        let max_inflight = std::env::var("SB_DNS_POOL_MAX_INFLIGHT")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(64);
        let per_host = std::env::var("SB_DNS_PER_HOST_INFLIGHT")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(2);
        Self {
            inner: Arc::new(sys),
            enabled,
            #[cfg(feature = "dns_cache")]
            cache: Arc::new(std::sync::Mutex::new(cache)),
            static_map,
            static_ttl,
            ipv6_enabled,
            #[cfg(any(test, feature = "dev-cli"))]
            prefetch_enabled,
            #[cfg(any(test, feature = "dev-cli"))]
            prefetch_before,
            #[cfg(any(test, feature = "dev-cli"))]
            prefetch_sem: Arc::new(tokio::sync::Semaphore::new(prefetch_conc)),
            #[cfg(any(test, feature = "dev-cli"))]
            prefetch_inflight: Arc::new(std::sync::Mutex::new(HashSet::new())),
            up_health: Arc::new(std::sync::Mutex::new(HashMap::new())),
            inflight_global: Arc::new(tokio::sync::Semaphore::new(std::cmp::max(1, max_inflight))),
            inflight_per_host: Arc::new(std::sync::Mutex::new(HashMap::from([(
                String::from("__init__"),
                Arc::new(tokio::sync::Semaphore::new(std::cmp::max(1, per_host))),
            )]))),
        }
    }

    /// 显式禁用：用于调用方测试/占位
    pub fn disabled() -> Self {
        let sys = system::SystemResolver::new(Duration::from_secs(60));
        #[cfg(feature = "dns_cache")]
        let cache = crate::dns::cache::DnsCache::new(1024);
        Self {
            inner: Arc::new(sys),
            enabled: false,
            #[cfg(feature = "dns_cache")]
            cache: Arc::new(std::sync::Mutex::new(cache)),
            static_map: Default::default(),
            static_ttl: Duration::from_secs(300),
            ipv6_enabled: true,
            #[cfg(any(test, feature = "dev-cli"))]
            prefetch_enabled: false,
            #[cfg(any(test, feature = "dev-cli"))]
            prefetch_before: Duration::from_millis(200),
            #[cfg(any(test, feature = "dev-cli"))]
            prefetch_sem: Arc::new(tokio::sync::Semaphore::new(0)),
            #[cfg(any(test, feature = "dev-cli"))]
            prefetch_inflight: Arc::new(std::sync::Mutex::new(HashSet::new())),
            up_health: Arc::new(std::sync::Mutex::new(HashMap::new())),
            inflight_global: Arc::new(tokio::sync::Semaphore::new(64)),
            inflight_per_host: Arc::new(std::sync::Mutex::new(HashMap::new())),
        }
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    pub async fn resolve(&self, host: &str) -> Result<DnsAnswer> {
        #[cfg(feature = "dns_cache")]
        let cache_key = CacheKey {
            name: host.to_ascii_lowercase(),
            qtype: CacheQType::A, // Default to A record query
        };
        let key = host.to_ascii_lowercase();
        #[cfg(feature = "dns_cache")]
        let mut need_fallback = false;
        #[cfg(not(feature = "dns_cache"))]
        let need_fallback = false;
        // 1) cache hit (scoped; drop lock before awaits)
        #[cfg(feature = "dns_cache")]
        {
            let cache_opt = self.cache.lock();
            if cache_opt.is_err() {
                tracing::error!(target: "sb_core::dns", "cache lock poisoned on resolve/get");
                need_fallback = true;
            }
            if let Ok(cache) = cache_opt {
                if let Some(ent) = cache.get(&cache_key) {
                    #[cfg(feature = "metrics")]
                ::metrics::counter!("dns_query_total", "hit"=>"hit", "family"=>"ANY", "source"=> match ent.source { crate::dns::cache::Source::Static => "static", _ => "system" }, "rcode"=> ent.rcode.as_str()).increment(1);
                    let ips = if self.ipv6_enabled {
                        ent.ips.clone()
                    } else {
                        ent.ips.iter().cloned().filter(|ip| ip.is_ipv4()).collect()
                    };
                    let mut to_spawn: Option<(tokio::sync::OwnedSemaphorePermit, String)> = None;
                    // Optional prefetch on near-expiry
                    if let Some(rem) = cache.peek_remaining(&cache_key) {
                        if rem <= self.prefetch_before {
                            if self.prefetch_enabled {
                                let key_clone = key.clone();
                                let permit = self.prefetch_sem.clone().try_acquire_owned();
                                if let Ok(mut inflight) = self.prefetch_inflight.lock() {
                                    if let Ok(p) = permit {
                                        if inflight.insert(key_clone.clone()) {
                                            #[cfg(feature = "metrics")]
                                        ::metrics::counter!("dns_prefetch_total", "reason"=>"spawn")
                                            .increment(1);
                                            to_spawn = Some((p, key_clone));
                                        } else {
                                            #[cfg(feature = "metrics")]
                                        ::metrics::counter!("dns_prefetch_total", "reason"=>"skip")
                                            .increment(1);
                                        }
                                    } else {
                                        #[cfg(feature = "metrics")]
                                        ::metrics::counter!("dns_prefetch_total", "reason"=>"skip")
                                            .increment(1);
                                    }
                                } else {
                                    tracing::warn!(target: "sb_core::dns", "prefetch inflight lock poisoned; skip prefetch");
                                    // 预取锁被毒化，但我们仍然可以返回缓存结果，只是无法进行预取
                                }
                            } else {
                                #[cfg(feature = "metrics")]
                                ::metrics::counter!("dns_prefetch_total", "reason"=>"hit_stale")
                                    .increment(1);
                            }
                        }
                    }
                    // drop lock before spawning
                    drop(cache);
                    if let Some((permit, key_spawn)) = to_spawn {
                        let handle = self.clone();
                        tokio::spawn(async move {
                            let _p = permit;
                            let _ = handle.resolve_via_pool_or_system(&key_spawn).await;
                            if let Ok(mut s) = handle.prefetch_inflight.lock() {
                                let _ = s.remove(&key_spawn);
                            }
                        });
                    }
                    return Ok(DnsAnswer::new(
                        ips,
                        std::time::Duration::from_secs(0),
                        cache::Source::Static,
                        cache::Rcode::NoError,
                    ));
                }
            }
        }
        if need_fallback {
            return self.resolve_via_pool_or_system(host).await;
        }
        // 2) static table
        if let Some(ips) = self.static_map.get(&key) {
            let mut ips = ips.clone();
            if !self.ipv6_enabled {
                ips.retain(|ip| ip.is_ipv4());
            }
            #[cfg(feature = "dns_cache")]
            {
                let answer = DnsAnswer::new(
                    ips.clone(),
                    self.static_ttl,
                    cache::Source::Static,
                    cache::Rcode::NoError,
                );
                if let Ok(c) = self.cache.lock() {
                    c.put(cache_key.clone(), answer);
                } else {
                    tracing::error!(target: "sb_core::dns", "cache lock poisoned on static put");
                }
            }
            #[cfg(feature = "metrics")]
            ::metrics::counter!("dns_query_total", "hit"=>"miss", "family"=>"ANY", "source"=>"static", "rcode"=>"ok").increment(1);
            return Ok(DnsAnswer::new(
                ips,
                self.static_ttl,
                cache::Source::Static,
                cache::Rcode::NoError,
            ));
        }
        // 3) pool/system resolver
        let res = self.resolve_via_pool_or_system(host).await;
        match res {
            Ok(ans) => {
                let mut ips = ans.ips;
                if !self.ipv6_enabled {
                    ips.retain(|ip| ip.is_ipv4());
                }
                if ips.is_empty() {
                    #[cfg(feature = "dns_cache")]
                    if let Ok(c) = self.cache.lock() {
                        c.put_negative(cache_key.clone());
                    } else {
                        tracing::error!(target: "sb_core::dns", "cache lock poisoned on put_negative");
                    }
                    #[cfg(feature = "metrics")]
                    ::metrics::counter!("dns_error_total", "class"=>"empty").increment(1);
                    #[cfg(feature = "metrics")]
                    ::metrics::counter!("dns_query_total", "hit"=>"miss", "family"=>"ANY", "source"=>"system", "rcode"=>"nodata").increment(1);
                    Ok(DnsAnswer::new(
                        ips,
                        ans.ttl,
                        cache::Source::System,
                        cache::Rcode::NoError,
                    ))
                } else {
                    #[cfg(feature = "dns_cache")]
                    {
                        let answer = DnsAnswer::new(
                            ips.clone(),
                            ans.ttl,
                            cache::Source::System,
                            cache::Rcode::NoError,
                        );
                        if let Ok(c) = self.cache.lock() {
                            c.put(cache_key.clone(), answer);
                        } else {
                            tracing::error!(target: "sb_core::dns", "cache lock poisoned on put");
                        }
                    }
                    #[cfg(feature = "metrics")]
                    ::metrics::counter!("dns_query_total", "hit"=>"miss", "family"=>"ANY", "source"=>"system", "rcode"=>"ok").increment(1);
                    Ok(DnsAnswer::new(
                        ips,
                        ans.ttl,
                        cache::Source::System,
                        cache::Rcode::NoError,
                    ))
                }
            }
            Err(_e) => {
                #[cfg(feature = "dns_cache")]
                if let Ok(c) = self.cache.lock() {
                    c.put_negative(cache_key.clone());
                } else {
                    tracing::error!(target: "sb_core::dns", "cache lock poisoned on put_negative");
                }
                #[cfg(feature = "metrics")]
                ::metrics::counter!("dns_error_total", "class"=>"resolve").increment(1);
                #[cfg(feature = "metrics")]
                ::metrics::counter!("dns_query_total", "hit"=>"miss", "family"=>"ANY", "source"=>"system", "rcode"=>"error").increment(1);
                Err(_e)
            }
        }
    }

    async fn resolve_via_pool_or_system(&self, host: &str) -> Result<DnsAnswer> {
        // inflight global/per-host gating
        let host_lc = host.to_ascii_lowercase();
        // 构建或获取 per-host semaphore，然后通过 RAII 守卫获取两个 permit
        let host_sem = {
            if let Ok(mut g) = self.inflight_per_host.lock() {
                g.entry(host_lc.clone())
                    .or_insert_with(|| {
                        Arc::new(tokio::sync::Semaphore::new(
                            std::env::var("SB_DNS_PER_HOST_INFLIGHT")
                                .ok()
                                .and_then(|v| v.parse::<usize>().ok())
                                .unwrap_or(2),
                        ))
                    })
                    .clone()
            } else {
                tracing::warn!(target: "sb_core::dns", host=%host_lc, "per-host inflight lock poisoned; falling back to global only");
                Arc::new(tokio::sync::Semaphore::new(1))
            }
        };
        let _inflight = InflightGuards::acquire(&self.inflight_global, &host_sem).await;
        // Build upstream pool from env
        let pool_raw = std::env::var("SB_DNS_POOL").unwrap_or_else(|_| "system".to_string());
        let upstreams = parse_pool(&pool_raw);
        // strategy
        let strategy = std::env::var("SB_DNS_POOL_STRATEGY").unwrap_or_else(|_| "race".to_string());
        let race_window_ms = std::env::var("SB_DNS_RACE_WINDOW_MS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(50);
        let he_order = std::env::var("SB_DNS_HE_ORDER").unwrap_or_else(|_| "A_FIRST".to_string());
        let he_race_ms = std::env::var("SB_DNS_HE_RACE_MS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(30);
        let timeout_ms = std::env::var("SB_DNS_UDP_TIMEOUT_MS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(200);

        if upstreams.is_empty() {
            return self.inner.resolve(host).await;
        }

        // 查询逻辑……
        let out = match strategy.as_str() {
            "race" => {
                resolve_race(
                    &upstreams,
                    host,
                    he_order.as_str(),
                    he_race_ms,
                    timeout_ms,
                    race_window_ms,
                    self,
                )
                .await
            }
            "sequential" => {
                resolve_sequential(
                    &upstreams,
                    host,
                    he_order.as_str(),
                    he_race_ms,
                    timeout_ms,
                    self,
                )
                .await
            }
            _ => {
                resolve_fanout(
                    &upstreams,
                    host,
                    he_order.as_str(),
                    he_race_ms,
                    timeout_ms,
                    self,
                )
                .await
            }
        };
        out
    }
}

#[derive(Clone, Debug)]
enum Upstream {
    System,
    Udp(std::net::SocketAddr),
    Doh(String),
    Dot(std::net::SocketAddr),
    Unsupported(String),
}

#[derive(Clone, Debug)]
struct UpHealth {
    fail_count: u32,
    down_until: std::time::Instant,
}

fn up_key(up: &Upstream) -> String {
    match up {
        Upstream::System => "system".to_string(),
        Upstream::Udp(sa) => format!("udp://{}", sa),
        Upstream::Doh(u) => format!("doh://{}", u),
        Upstream::Dot(sa) => format!("dot://{}", sa),
        Upstream::Unsupported(s) => s.clone(),
    }
}

fn parse_pool(s: &str) -> Vec<Upstream> {
    let mut out = Vec::new();
    for tok in s.split(',').map(|x| x.trim()).filter(|x| !x.is_empty()) {
        if tok.eq_ignore_ascii_case("system") {
            out.push(Upstream::System);
            continue;
        }
        if let Some(addr) = tok.strip_prefix("udp:") {
            if let Ok(sa) = addr.parse::<std::net::SocketAddr>() {
                out.push(Upstream::Udp(sa));
                continue;
            }
        }
        if let Some(url) = tok.strip_prefix("doh:") {
            // behind feature; placeholder
            out.push(Upstream::Doh(url.to_string()));
            continue;
        }
        if let Some(addr) = tok.strip_prefix("dot:") {
            if let Ok(sa) = addr.parse::<std::net::SocketAddr>() {
                out.push(Upstream::Dot(sa));
                continue;
            }
        }
        // unsupported fallback
        out.push(Upstream::Unsupported(tok.to_string()));
    }
    out
}

async fn query_one(
    handle: ResolverHandle,
    up: Upstream,
    host: String,
    _he_order: &str,
    _he_race_ms: u64,
    timeout_ms: u64,
) -> Result<(Vec<IpAddr>, Duration)> {
    let _start = std::time::Instant::now();
    let mut ips: Vec<IpAddr> = Vec::new();
    let ttl: Duration;
    match up.clone() {
        Upstream::System => {
            // System resolver combines both families already
            let iter = tokio::time::timeout(
                Duration::from_millis(timeout_ms),
                tokio::net::lookup_host((host.as_str(), 0)),
            )
            .await??;
            for sa in iter {
                ips.push(sa.ip());
            }
            ttl = Duration::from_secs(
                std::env::var("SB_DNS_DEFAULT_TTL_S")
                    .ok()
                    .and_then(|v| v.parse::<u64>().ok())
                    .unwrap_or(60),
            );
            #[cfg(feature="metrics")]
            ::metrics::counter!("dns_upstream_select_total", "strategy"=>"pool", "upstream"=>"system", "kind"=>"system").increment(1);
        }
        Upstream::Udp(_sa) => {
            #[cfg(feature = "dns_udp")]
            {
                use crate::dns::udp::build_query;
                use tokio::net::UdpSocket as TokioUdpSocket;
                use tokio::time::{timeout, Duration as TokioDuration};
                let q_a = {
                    let sa = _sa;
                    let h2 = host.clone();
                    async move {
                        let req = build_query(&h2, 1)?;
                        let sock = TokioUdpSocket::bind("0.0.0.0:0").await?;
                        let _ = sock.send_to(&req, sa).await?;
                        let mut buf = [0u8; 1500];
                        let (n, _from) = timeout(
                            TokioDuration::from_millis(timeout_ms),
                            sock.recv_from(&mut buf),
                        )
                        .await??;
                        crate::dns::udp::parse_answers(&buf[..n], 1)
                    }
                };
                let q_aaaa = {
                    let sa = _sa;
                    let h2 = host.clone();
                    async move {
                        let req = build_query(&h2, 28)?;
                        let sock = TokioUdpSocket::bind("0.0.0.0:0").await?;
                        let _ = sock.send_to(&req, sa).await?;
                        let mut buf = [0u8; 1500];
                        let (n, _from) = timeout(
                            TokioDuration::from_millis(timeout_ms),
                            sock.recv_from(&mut buf),
                        )
                        .await??;
                        crate::dns::udp::parse_answers(&buf[..n], 28)
                    }
                };
                let he_delay = Duration::from_millis(_he_race_ms);
                let mut min_ttl: Option<u32> = None;
                match _he_order {
                    o if o.eq_ignore_ascii_case("AAAA_FIRST") => {
                        let aaaa = tokio::spawn(q_aaaa);
                        tokio::time::sleep(he_delay).await;
                        let a = tokio::spawn(q_a);
                        if let Ok(Ok((v6, t6))) = aaaa.await {
                            ips.extend(v6);
                            min_ttl = min_ttl.min(t6).or(t6);
                        }
                        if let Ok(Ok((v4, t4))) = a.await {
                            ips.extend(v4);
                            min_ttl = min_ttl.min(t4).or(t4);
                        }
                    }
                    _ => {
                        let a = tokio::spawn(q_a);
                        tokio::time::sleep(he_delay).await;
                        let aaaa = tokio::spawn(q_aaaa);
                        if let Ok(Ok((v4, t4))) = a.await {
                            ips.extend(v4);
                            min_ttl = min_ttl.min(t4).or(t4);
                        }
                        if let Ok(Ok((v6, t6))) = aaaa.await {
                            ips.extend(v6);
                            min_ttl = min_ttl.min(t6).or(t6);
                        }
                    }
                }
                ttl = min_ttl
                    .map(|s| Duration::from_secs(s as u64))
                    .unwrap_or_else(|| {
                        Duration::from_secs(
                            std::env::var("SB_DNS_DEFAULT_TTL_S")
                                .ok()
                                .and_then(|v| v.parse::<u64>().ok())
                                .unwrap_or(60),
                        )
                    });
                #[cfg(feature="metrics")]
                ::metrics::counter!("dns_upstream_select_total", "strategy"=>"pool", "upstream"=>format!("udp://{}", _sa), "kind"=>"udp").increment(1);
            }
            #[cfg(not(feature = "dns_udp"))]
            {
                // Feature off: behave as empty
                ttl = Duration::from_secs(60);
            }
        }
        Upstream::Doh(_url) => {
            #[cfg(feature = "dns_doh")]
            {
                let url = _url.clone();
                let q_a = {
                    let url = url.clone();
                    let h2 = host.clone();
                    async move { crate::dns::doh::query_doh_once(&url, &h2, 1, timeout_ms).await }
                };
                let q_aaaa = {
                    let url = url.clone();
                    let h2 = host.clone();
                    async move { crate::dns::doh::query_doh_once(&url, &h2, 28, timeout_ms).await }
                };
                let he_delay = Duration::from_millis(_he_race_ms);
                let mut min_ttl: Option<u32> = None;
                match _he_order {
                    o if o.eq_ignore_ascii_case("AAAA_FIRST") => {
                        let aaaa = tokio::spawn(q_aaaa);
                        tokio::time::sleep(he_delay).await;
                        let a = tokio::spawn(q_a);
                        if let Ok(Ok((v6, t6))) = aaaa.await {
                            ips.extend(v6);
                            min_ttl = min_ttl.min(t6).or(t6);
                        }
                        if let Ok(Ok((v4, t4))) = a.await {
                            ips.extend(v4);
                            min_ttl = min_ttl.min(t4).or(t4);
                        }
                    }
                    _ => {
                        let a = tokio::spawn(q_a);
                        tokio::time::sleep(he_delay).await;
                        let aaaa = tokio::spawn(q_aaaa);
                        if let Ok(Ok((v4, t4))) = a.await {
                            ips.extend(v4);
                            min_ttl = min_ttl.min(t4).or(t4);
                        }
                        if let Ok(Ok((v6, t6))) = aaaa.await {
                            ips.extend(v6);
                            min_ttl = min_ttl.min(t6).or(t6);
                        }
                    }
                }
                ttl = min_ttl
                    .map(|s| Duration::from_secs(s as u64))
                    .unwrap_or_else(|| {
                        Duration::from_secs(
                            std::env::var("SB_DNS_DEFAULT_TTL_S")
                                .ok()
                                .and_then(|v| v.parse::<u64>().ok())
                                .unwrap_or(60),
                        )
                    });
                #[cfg(feature="metrics")]
                ::metrics::counter!("dns_upstream_select_total", "strategy"=>"pool", "upstream"=>up_key(&up), "kind"=>"doh").increment(1);
            }
            #[cfg(not(feature = "dns_doh"))]
            {
                return Err(anyhow::anyhow!("dns_doh feature disabled"));
            }
        }
        Upstream::Dot(sa) => {
            #[cfg(not(all(feature = "dns_dot", feature = "tls_rustls")))]
            let _ = sa; // Suppress unused warning when feature is disabled
            #[cfg(all(feature = "dns_dot", feature = "tls_rustls"))]
            {
                let h = host.clone();
                let q_a =
                    async move { crate::dns::dot::query_dot_once(sa, &h, 1, timeout_ms).await };
                let h2 = host.clone();
                let q_aaaa =
                    async move { crate::dns::dot::query_dot_once(sa, &h2, 28, timeout_ms).await };
                let he_delay = Duration::from_millis(_he_race_ms);
                let mut min_ttl: Option<u32> = None;
                let a = tokio::spawn(q_a);
                tokio::time::sleep(he_delay).await;
                let aaaa = tokio::spawn(q_aaaa);
                if let Ok(Ok((v4, t4))) = a.await {
                    ips.extend(v4);
                    min_ttl = min_ttl.min(t4).or(t4);
                }
                if let Ok(Ok((v6, t6))) = aaaa.await {
                    ips.extend(v6);
                    min_ttl = min_ttl.min(t6).or(t6);
                }
                ttl = min_ttl
                    .map(|s| Duration::from_secs(s as u64))
                    .unwrap_or_else(|| {
                        Duration::from_secs(
                            std::env::var("SB_DNS_DEFAULT_TTL_S")
                                .ok()
                                .and_then(|v| v.parse::<u64>().ok())
                                .unwrap_or(60),
                        )
                    });
                #[cfg(feature="metrics")]
                ::metrics::counter!("dns_upstream_select_total", "strategy"=>"pool", "upstream"=>up_key(&up), "kind"=>"dot").increment(1);
            }
            #[cfg(not(feature = "dns_dot"))]
            {
                return Err(anyhow::anyhow!("dns_dot feature disabled"));
            }
        }
        Upstream::Unsupported(s) => {
            return Err(anyhow::anyhow!(format!("unsupported upstream: {}", s)));
        }
    }
    // latency metric
    #[cfg(feature = "metrics")]
    {
        let elapsed = _start.elapsed().as_millis() as f64;
        let kind = match up {
            Upstream::System => "system",
            Upstream::Udp(_) => "udp",
            Upstream::Doh(_) => "doh",
            Upstream::Dot(_) => "dot",
            Upstream::Unsupported(_) => "unsupported",
        };
        let up = up_key(&up);
        ::metrics::histogram!("dns_query_latency_ms", "upstream"=>up, "kind"=>kind).record(elapsed);
    }
    if !ips.is_empty() {
        // Mark success
        mark_upstream_success(&handle, &up_key(&up));
        Ok((ips, ttl))
    } else {
        mark_upstream_fail(&handle, &up_key(&up), "io");
        Err(anyhow::anyhow!("empty"))
    }
}

async fn resolve_race(
    upstreams: &[Upstream],
    host: &str,
    he_order: &str,
    he_race_ms: u64,
    timeout_ms: u64,
    race_win_ms: u64,
    h: &ResolverHandle,
) -> Result<DnsAnswer> {
    use tokio::sync::mpsc;
    let (tx, mut rx) = mpsc::channel::<Result<(Vec<IpAddr>, Duration)>>(upstreams.len());
    let now = std::time::Instant::now();
    let eligible: Vec<_> = upstreams
        .iter()
        .filter(|&u| {
            let key = up_key(u);
            match h.up_health.lock() {
                Ok(map) => match map.get(&key) {
                    Some(st) => now >= st.down_until,
                    None => true,
                },
                Err(_) => true,
            }
        })
        .cloned()
        .collect();
    let chosen = if eligible.is_empty() {
        #[cfg(feature = "metrics")]
        ::metrics::counter!("dns_pool_degraded_total", "strategy"=>"race", "reason"=>"all_down")
            .increment(1);
        upstreams.to_vec()
    } else {
        eligible
    };
    for (i, up) in chosen.into_iter().enumerate() {
        let txc = tx.clone();
        let hname = host.to_string();
        let heo = he_order.to_string();
        let handle = h.clone();
        tokio::spawn(async move {
            if i > 0 {
                tokio::time::sleep(Duration::from_millis(race_win_ms * i as u64)).await;
            }
            let res = query_one(handle, up, hname, &heo, he_race_ms, timeout_ms).await;
            let _ = txc.send(res).await;
        });
    }
    drop(tx);
    if let Some(first) = rx.recv().await {
        match first {
            Ok((ips, ttl)) => {
                return Ok(DnsAnswer::new(
                    ips,
                    ttl,
                    cache::Source::Upstream,
                    cache::Rcode::NoError,
                ))
            }
            Err(e) => return Err(e),
        }
    }
    Err(anyhow::anyhow!("dns/race: no upstreams"))
}

async fn resolve_sequential(
    upstreams: &[Upstream],
    host: &str,
    he_order: &str,
    he_race_ms: u64,
    timeout_ms: u64,
    h: &ResolverHandle,
) -> Result<DnsAnswer> {
    let mut last_err: Option<anyhow::Error> = None;
    for up in upstreams {
        let res = query_one(
            h.clone(),
            up.clone(),
            host.to_string(),
            he_order,
            he_race_ms,
            timeout_ms,
        )
        .await;
        match res {
            Ok((ips, ttl)) => {
                return Ok(DnsAnswer::new(
                    ips,
                    ttl,
                    cache::Source::Upstream,
                    cache::Rcode::NoError,
                ))
            }
            Err(e) => {
                last_err = Some(e);
                continue;
            }
        }
    }
    Err(last_err.unwrap_or_else(|| anyhow::anyhow!("dns/sequential: all failed")))
}

async fn resolve_fanout(
    upstreams: &[Upstream],
    host: &str,
    he_order: &str,
    he_race_ms: u64,
    timeout_ms: u64,
    h: &ResolverHandle,
) -> Result<DnsAnswer> {
    use futures::future::join_all;
    let futs = upstreams.iter().cloned().map(|up| {
        query_one(
            h.clone(),
            up,
            host.to_string(),
            he_order,
            he_race_ms,
            timeout_ms,
        )
    });
    let results = join_all(futs).await;
    let mut ips: Vec<IpAddr> = Vec::new();
    let mut min_ttl: Option<Duration> = None;
    let mut any_ok = false;
    for (mut part, ttl) in results.into_iter().flatten() {
        any_ok = true;
        for ip in part.drain(..) {
            if !ips.contains(&ip) {
                ips.push(ip);
            }
        }
        min_ttl = Some(min_ttl.map_or(ttl, |x| x.min(ttl)));
    }
    if !any_ok {
        return Err(anyhow::anyhow!("dns/fanout: all failed"));
    }
    Ok(DnsAnswer::new(
        ips,
        min_ttl.unwrap_or_else(|| Duration::from_secs(60)),
        cache::Source::Upstream,
        cache::Rcode::NoError,
    ))
}

fn mark_upstream_fail(h: &ResolverHandle, key: &str, _reason: &str) {
    let mut map = match h.up_health.lock() {
        Ok(g) => g,
        Err(_e) => {
            tracing::error!(target: "sb_core::dns", upstream=%key, "up_health lock poisoned on fail");
            return;
        }
    };
    let st = map.entry(key.to_string()).or_insert(UpHealth {
        fail_count: 0,
        down_until: std::time::Instant::now(),
    });
    st.fail_count = st.fail_count.saturating_add(1);
    let exp = st.fail_count.min(5) as u32;
    let factor = 1u64 << exp;
    let backoff_ms = (100u64).saturating_mul(factor).min(2000);
    let backoff = Duration::from_millis(backoff_ms.min(2000));
    st.down_until = std::time::Instant::now() + backoff;
    #[cfg(feature = "metrics")]
    {
        ::metrics::gauge!("dns_upstream_state", "upstream"=>key.to_string(), "kind"=>if key.starts_with("udp://"){"udp"} else if key=="system" {"system"} else {"other"}, "state"=>"down").set(0.0);
        ::metrics::counter!("dns_pool_errors_total", "upstream"=>key.to_string(), "reason"=>_reason.to_string()).increment(1);
    }
}

fn mark_upstream_success(h: &ResolverHandle, key: &str) {
    let mut map = match h.up_health.lock() {
        Ok(g) => g,
        Err(_e) => {
            tracing::error!(target: "sb_core::dns", upstream=%key, "up_health lock poisoned on success");
            return;
        }
    };
    let st = map.entry(key.to_string()).or_insert(UpHealth {
        fail_count: 0,
        down_until: std::time::Instant::now(),
    });
    st.fail_count = 0;
    st.down_until = std::time::Instant::now();
    #[cfg(feature="metrics")]
    ::metrics::gauge!("dns_upstream_state", "upstream"=>key.to_string(), "kind"=>if key.starts_with("udp://"){"udp"} else if key=="system" {"system"} else {"other"}, "state"=>"up").set(1.0);
}

/// Implement the Resolver trait for ResolverHandle to bridge the interface gap
#[async_trait]
impl Resolver for ResolverHandle {
    async fn resolve(&self, domain: &str) -> Result<DnsAnswer> {
        // Disambiguate to call the inherent method, not the trait method
        ResolverHandle::resolve(self, domain).await
    }

    fn name(&self) -> &str {
        "resolver_handle"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    #[tokio::test]
    async fn raii_guard_releases_permits() {
        let g = Arc::new(tokio::sync::Semaphore::new(1));
        let h = Arc::new(tokio::sync::Semaphore::new(1));
        assert_eq!(g.available_permits(), 1);
        assert_eq!(h.available_permits(), 1);
        {
            let _guard = InflightGuards::acquire(&g, &h).await;
            // 被占用
            assert_eq!(g.available_permits(), 0);
            assert_eq!(h.available_permits(), 0);
        }
        // Drop 后释放
        assert_eq!(g.available_permits(), 1);
        assert_eq!(h.available_permits(), 1);
    }

    #[tokio::test]
    async fn prefetch_guard_path_ok() {
        // 只要 acquire/drop 不 panic 即可（行为与上个测试等价）
        let g = Arc::new(tokio::sync::Semaphore::new(2));
        let h = Arc::new(tokio::sync::Semaphore::new(2));
        let a = InflightGuards::acquire(&g, &h).await;
        let b = InflightGuards::acquire(&g, &h).await;
        drop(a);
        drop(b);
        assert_eq!(g.available_permits(), 2);
        assert_eq!(h.available_permits(), 2);
    }
}
