//! 路由决策引擎（与编译化 RouterIndex 对接）
//! 目标：读路径无锁（通过 Arc<RouterIndex> 快照），默认直连，预算降级仅在"未定→默认"计数

use std::future::Future;
use std::net::IpAddr;
use std::pin::Pin;
#[cfg(feature = "router_cache_lru_demo")]
use std::sync::Mutex;
use std::sync::{Arc, RwLock};
use std::time::Instant;
// no PhantomData needed in the compatibility layer

use super::{
    normalize_host, router_index_decide_exact_suffix, router_index_decide_geosite,
    router_index_decide_ip, router_index_decide_transport_port, runtime_override_udp, shared_index,
    RouterIndex,
};
use crate::geoip::lookup_with_metrics_decision;
use crate::outbound::RouteTarget;

/// 兼容历史导出：在大多数调用场景里只使用 `RouterHandle`
pub struct RouterHandle {
    idx: Arc<RwLock<Arc<RouterIndex>>>,
    resolver: Option<Arc<dyn DnsResolve>>,
    /// 决策缓存（可选）：(观测到的 generation, LRU)
    #[cfg(feature = "router_cache_lru_demo")]
    cache: Option<Mutex<(u64, lru::LruCache<String, &'static str>)>>,
    #[cfg(not(feature = "router_cache_lru_demo"))]
    cache: Option<()>,
    #[cfg(feature = "geoip_mmdb")]
    geoip: Option<std::sync::Arc<crate::geoip::mmdb::GeoIp>>,
    #[cfg(feature = "geoip_mmdb")]
    geoip_mux: Option<crate::geoip::multi::GeoMux>,
    #[cfg(feature = "geoip_mmdb")]
    geoip_source: Option<String>,
    #[cfg(not(feature = "geoip_mmdb"))]
    geoip: Option<()>,
    #[cfg(not(feature = "geoip_mmdb"))]
    geoip_mux: Option<()>,
    #[cfg(not(feature = "geoip_mmdb"))]
    geoip_source: Option<()>,
    /// Enhanced GeoIP database support
    geoip_db: Option<std::sync::Arc<crate::router::geo::GeoIpDb>>,
    /// Enhanced GeoSite database support
    geosite_db: Option<std::sync::Arc<crate::router::geo::GeoSiteDb>>,
}

impl std::fmt::Debug for RouterHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RouterHandle")
            .field("resolver", &self.resolver.is_some())
            .field("cache", &self.cache.is_some())
            .finish()
    }
}

/// DNS 解析结果：复用现有 DnsResult 口径，便于统一打点
#[derive(Debug, Clone)]
pub enum DnsResult {
    Ok(Vec<IpAddr>),
    Miss,    // 解析成功但无记录
    Timeout, // 超时
    Error,   // 其他错误
}

/// 可插拔 DNS 解析器接口：避免强耦合 DNS 模块，便于测试与替换
pub trait DnsResolve: Send + Sync + 'static {
    /// 解析 host，超时语义由实现处理；返回统一的 DnsResult 枚举
    fn resolve<'a>(
        &'a self,
        host: &'a str,
        timeout_ms: u64,
    ) -> Pin<Box<dyn Future<Output = DnsResult> + Send + 'a>>;
}

impl RouterHandle {
    /// 同步构造：为了避免在非 async 语境阻塞，这里仅基于 ENV 内联规则初始化；
    /// 若存在文件热重载需求，请直接调用 `router_index_from_env_with_reload().await` 在上层注入。
    pub fn from_env() -> Self {
        // 复用共享索引（内部含一次性初始化与可选热重载）
        let shared = shared_index();
        // 可选缓存开关
        #[cfg(feature = "router_cache_lru_demo")]
        let cache = {
            let use_cache = std::env::var("SB_ROUTER_DECISION_CACHE")
                .ok()
                .map(|v| v == "1")
                .unwrap_or(false);
            let cap = std::env::var("SB_ROUTER_DECISION_CACHE_CAP")
                .ok()
                .and_then(|v| v.parse::<usize>().ok())
                .unwrap_or(1024);
            if use_cache {
                Some(Mutex::new((
                    0u64,
                    lru::LruCache::new(std::num::NonZeroUsize::new(cap).unwrap_or_else(|| {
                        // SAFETY: 1024 is a non-zero constant; constructing NonZeroUsize is sound.
                        unsafe { std::num::NonZeroUsize::new_unchecked(1024) }
                    })),
                )))
            } else {
                None
            }
        };
        #[cfg(not(feature = "router_cache_lru_demo"))]
        let cache = None;
        let mut handle = Self {
            idx: shared,
            resolver: None,
            cache,
            #[cfg(feature = "geoip_mmdb")]
            geoip: None,
            #[cfg(feature = "geoip_mmdb")]
            geoip_mux: None,
            #[cfg(feature = "geoip_mmdb")]
            geoip_source: None,
            #[cfg(not(feature = "geoip_mmdb"))]
            geoip: None,
            #[cfg(not(feature = "geoip_mmdb"))]
            geoip_mux: None,
            #[cfg(not(feature = "geoip_mmdb"))]
            geoip_source: None,
            geoip_db: None,
            geosite_db: None,
        };
        #[cfg(feature = "geoip_mmdb")]
        handle.init_geoip_if_env();
        handle
    }

    #[cfg(feature = "router_cache_lru_demo")]
    pub(crate) fn lru_snapshot(&self) -> Option<(usize, usize, u64, u64)> {
        if let Some(c) = &self.cache {
            let g = c.lock().unwrap_or_else(|e| e.into_inner());
            Some((g.1.len(), g.1.cap().get(), 0, 0)) // size, capacity, hits, misses (simplified)
        } else {
            None
        }
    }

    #[cfg(feature = "router_cache_lru_demo")]
    pub(crate) fn lru_clear(&self) {
        if let Some(c) = &self.cache {
            let mut g = c.lock().unwrap_or_else(|e| e.into_inner());
            g.1.clear();
        }
    }

    /// 注入解析器（链式）
    pub fn with_resolver(mut self, r: Arc<dyn DnsResolve>) -> Self {
        self.resolver = Some(r);
        self
    }

    /// Set GeoIP database for enhanced IP geolocation support
    ///
    /// # Arguments
    /// * `geoip_db` - GeoIP database instance
    ///
    /// # Returns
    /// * `Self` - RouterHandle with GeoIP database configured
    pub fn with_geoip_db(mut self, geoip_db: std::sync::Arc<crate::router::geo::GeoIpDb>) -> Self {
        self.geoip_db = Some(geoip_db);
        self
    }

    /// Load GeoIP database from file path
    ///
    /// # Arguments
    /// * `path` - Path to GeoIP database file
    ///
    /// # Returns
    /// * `Result<Self, SbError>` - RouterHandle with loaded GeoIP database or error
    pub fn with_geoip_file<P: AsRef<std::path::Path>>(
        mut self,
        path: P,
    ) -> crate::error::SbResult<Self> {
        let geoip_db = crate::router::geo::GeoIpDb::load_from_file(path.as_ref())?;
        self.geoip_db = Some(std::sync::Arc::new(geoip_db));
        Ok(self)
    }

    /// Get GeoIP database reference
    ///
    /// # Returns
    /// * `Option<&Arc<GeoIpDb>>` - Reference to GeoIP database if available
    pub fn geoip_db(&self) -> Option<&std::sync::Arc<crate::router::geo::GeoIpDb>> {
        self.geoip_db.as_ref()
    }

    /// Set GeoSite database for enhanced domain categorization support
    ///
    /// # Arguments
    /// * `geosite_db` - GeoSite database instance
    ///
    /// # Returns
    /// * `Self` - RouterHandle with GeoSite database configured
    pub fn with_geosite_db(
        mut self,
        geosite_db: std::sync::Arc<crate::router::geo::GeoSiteDb>,
    ) -> Self {
        self.geosite_db = Some(geosite_db);
        self
    }

    /// Load GeoSite database from file path
    ///
    /// # Arguments
    /// * `path` - Path to GeoSite database file
    ///
    /// # Returns
    /// * `Result<Self, SbError>` - RouterHandle with loaded GeoSite database or error
    pub fn with_geosite_file<P: AsRef<std::path::Path>>(
        mut self,
        path: P,
    ) -> crate::error::SbResult<Self> {
        let geosite_db = crate::router::geo::GeoSiteDb::load_from_file(path.as_ref())?;
        self.geosite_db = Some(std::sync::Arc::new(geosite_db));
        Ok(self)
    }

    /// Get GeoSite database reference
    ///
    /// # Returns
    /// * `Option<&Arc<GeoSiteDb>>` - Reference to GeoSite database if available
    pub fn geosite_db(&self) -> Option<&std::sync::Arc<crate::router::geo::GeoSiteDb>> {
        self.geosite_db.as_ref()
    }

    /// Enhanced GeoIP lookup using the new GeoIpDb
    ///
    /// This method first tries the enhanced GeoIpDb, then falls back to the legacy lookup
    ///
    /// # Arguments
    /// * `ip` - IP address to look up
    /// * `idx` - Router index containing GeoIP rules
    ///
    /// # Returns
    /// * `Option<&'static str>` - Routing decision if GeoIP match found
    pub fn enhanced_geoip_lookup(
        &self,
        ip: IpAddr,
        idx: &crate::router::RouterIndex,
    ) -> Option<&'static str> {
        // First try the enhanced GeoIpDb if available
        if let Some(geoip_db) = &self.geoip_db {
            if let Some(country_code) = geoip_db.lookup_country(ip) {
                // Check against GeoIP rules in the router index
                for (cc, decision) in &idx.geoip_rules {
                    if cc.eq_ignore_ascii_case(&country_code) {
                        #[cfg(feature = "metrics")]
                        metrics::counter!("geoip_lookup_total", "source"=>"enhanced_db", "result"=>"hit").increment(1);
                        return Some(*decision);
                    }
                }
                #[cfg(feature = "metrics")]
                metrics::counter!("geoip_lookup_total", "source"=>"enhanced_db", "result"=>"miss")
                    .increment(1);
            }
        }

        // Fall back to legacy GeoIP lookup
        if let Some(decision) = lookup_with_metrics_decision(ip) {
            #[cfg(feature = "metrics")]
            metrics::counter!("geoip_lookup_total", "source"=>"legacy", "result"=>"hit")
                .increment(1);
            return Some(decision);
        }

        #[cfg(feature = "metrics")]
        metrics::counter!("geoip_lookup_total", "source"=>"legacy", "result"=>"miss").increment(1);
        None
    }

    /// Enhanced GeoSite lookup using the new GeoSiteDb
    ///
    /// This method checks if a domain matches any GeoSite category rules
    ///
    /// # Arguments
    /// * `domain` - Domain to look up
    /// * `idx` - Router index containing GeoSite rules
    ///
    /// # Returns
    /// * `Option<&'static str>` - Routing decision if GeoSite match found
    pub fn enhanced_geosite_lookup(
        &self,
        domain: &str,
        idx: &crate::router::RouterIndex,
    ) -> Option<&'static str> {
        // Try the enhanced GeoSiteDb if available
        if let Some(geosite_db) = &self.geosite_db {
            // Check against GeoSite rules in the router index
            for (category, decision) in &idx.geosite_rules {
                if geosite_db.match_domain(domain, category) {
                    #[cfg(feature = "metrics")]
                    metrics::counter!("geosite_lookup_total", "source"=>"enhanced_db", "result"=>"hit").increment(1);
                    return Some(*decision);
                }
            }
            #[cfg(feature = "metrics")]
            metrics::counter!("geosite_lookup_total", "source"=>"enhanced_db", "result"=>"miss")
                .increment(1);
        }

        None
    }

    /// 注入 DNS 模块的 Resolver（通过桥接器）
    pub fn with_dns_resolver(mut self, resolver: Arc<dyn crate::dns::Resolver>) -> Self {
        let bridge = super::dns_bridge::DnsResolverBridge::new(resolver);
        self.resolver = Some(Arc::new(bridge));
        self
    }

    /// 检查是否已配置 DNS 解析器
    pub fn has_dns_resolver(&self) -> bool {
        self.resolver.is_some()
    }

    #[inline]
    fn cache_try_get(&self, host_norm: &str) -> Option<&'static str> {
        #[cfg(feature = "router_cache_lru_demo")]
        {
            let Some(c) = &self.cache else { return None };
            // 检查 generation
            let gen = self.idx.read().ok().map(|a| a.gen).unwrap_or(0);
            let mut g = c.lock().unwrap_or_else(|e| e.into_inner());
            if g.0 != gen {
                // generation 变化：清空并更新
                #[cfg(feature = "metrics")]
                metrics::counter!("router_decision_cache_total", "result"=>"invalidate")
                    .increment(1);
                g.0 = gen;
                g.1.clear();
                return None;
            }
            if let Some(v) = g.1.get(host_norm) {
                #[cfg(feature = "metrics")]
                metrics::counter!("router_decision_cache_total", "result"=>"hit").increment(1);
                return Some(*v);
            }
            #[cfg(feature = "metrics")]
            metrics::counter!("router_decision_cache_total", "result"=>"miss").increment(1);
            None
        }
        #[cfg(not(feature = "router_cache_lru_demo"))]
        {
            let _ = host_norm;
            None
        }
    }

    #[inline]
    fn cache_put(&self, host_norm: &str, dec: &'static str) {
        #[cfg(feature = "router_cache_lru_demo")]
        {
            let Some(c) = &self.cache else { return };
            let gen = self.idx.read().ok().map(|a| a.gen).unwrap_or(0);
            let mut g = c.lock().unwrap_or_else(|e| e.into_inner());
            if g.0 != gen {
                // 先对齐 generation
                g.0 = gen;
                g.1.clear();
            }
            g.1.put(host_norm.to_string(), dec);
        }
        #[cfg(not(feature = "router_cache_lru_demo"))]
        {
            let _ = (host_norm, dec);
        }
    }

    async fn resolve_with_fallback(&self, host: &str, timeout_ms: u64) -> DnsResult {
        if let Some(r) = &self.resolver {
            let result = r.resolve(host, timeout_ms).await;

            // Record DNS cache hit/miss metrics based on result
            #[cfg(feature = "metrics")]
            match &result {
                DnsResult::Ok(_) => {
                    metrics::counter!("dns_cache_hit_total", "kind" => "hit").increment(1);
                }
                DnsResult::Miss | DnsResult::Timeout | DnsResult::Error => {
                    metrics::counter!("dns_cache_hit_total", "kind" => "miss").increment(1);
                }
            }

            return result;
        }

        // Record cache miss for fallback resolution
        #[cfg(feature = "metrics")]
        metrics::counter!("dns_cache_hit_total", "kind" => "miss").increment(1);

        // 内置回退：tokio::net::lookup_host + timeout（最佳努力，不引入额外依赖）
        #[cfg(feature = "dns_udp")]
        {
            use tokio::net::lookup_host;
            use tokio::time::timeout;
            let fut = async move {
                match lookup_host((host, 0)).await {
                    Ok(iter) => {
                        let mut ips = Vec::new();
                        for sa in iter {
                            ips.push(sa.ip());
                        }
                        if ips.is_empty() {
                            DnsResult::Miss
                        } else {
                            DnsResult::Ok(ips)
                        }
                    }
                    Err(_) => DnsResult::Error,
                }
            };
            match timeout(std::time::Duration::from_millis(timeout_ms), fut).await {
                Ok(rc) => rc,
                Err(_) => DnsResult::Timeout,
            }
        }
        #[cfg(not(feature = "dns_udp"))]
        {
            let _ = (host, timeout_ms);
            DnsResult::Error
        }
    }

    /// 兼容旧 API：从 Router 构造 RouterHandle
    pub fn new(_router: Router) -> Self {
        // 忽略传入的 router，使用共享索引
        Self::from_env()
    }

    /// 兼容旧 API：替换内部路由器（实际上是 no-op，因为使用共享索引）
    pub fn replace(&self, _router: Router) {
        // no-op：新架构使用共享索引，不支持运行时替换
    }

    /// Replace the router index (for hot reloading)
    pub async fn replace_index(&self, new_index: Arc<RouterIndex>) -> Result<(), String> {
        let mut idx = self
            .idx
            .write()
            .map_err(|e| format!("Failed to acquire write lock: {}", e))?;

        // Increment generation to track changes
        let mut new_index_with_gen = (*new_index).clone();
        new_index_with_gen.gen = idx.gen + 1;

        *idx = Arc::new(new_index_with_gen);
        Ok(())
    }

    /// Get current router generation
    pub async fn current_generation(&self) -> u64 {
        let idx = self.idx.read().unwrap_or_else(|e| e.into_inner());
        idx.gen
    }

    /// Create a mock router handle for testing
    pub fn new_mock() -> Self {
        use crate::router::RouterIndex;
        use std::collections::HashMap;

        let mock_index = Arc::new(RouterIndex {
            exact: HashMap::new(),
            suffix: Vec::new(),
            suffix_map: HashMap::new(),
            port_rules: HashMap::new(),
            port_ranges: Vec::new(),
            transport_tcp: None,
            transport_udp: None,
            cidr4: Vec::new(),
            cidr6: Vec::new(),
            cidr4_buckets: vec![Vec::new(); 33],
            cidr6_buckets: vec![Vec::new(); 129],
            geoip_rules: Vec::new(),
            geosite_rules: Vec::new(),
            #[cfg(feature = "router_keyword")]
            keyword_rules: Vec::new(),
            #[cfg(feature = "router_keyword")]
            keyword_idx: None,
            default: "direct",
            gen: 1,
            checksum: [0u8; 32],
        });

        Self {
            idx: Arc::new(RwLock::new(mock_index)),
            resolver: None,
            #[cfg(feature = "router_cache_lru_demo")]
            cache: None,
            #[cfg(not(feature = "router_cache_lru_demo"))]
            cache: None,
            #[cfg(feature = "geoip_mmdb")]
            geoip: None,
            #[cfg(feature = "geoip_mmdb")]
            geoip_mux: None,
            #[cfg(feature = "geoip_mmdb")]
            geoip_source: None,
            #[cfg(not(feature = "geoip_mmdb"))]
            geoip: None,
            #[cfg(not(feature = "geoip_mmdb"))]
            geoip_mux: None,
            #[cfg(not(feature = "geoip_mmdb"))]
            geoip_source: None,
            geoip_db: None,
            geosite_db: None,
        }
    }

    /// 测试专用构造函数
    pub fn new_for_tests() -> Self {
        Self::from_env()
    }

    /// UDP 决策：基于 UdpTargetAddr 进行路由，同步版本
    pub fn decide_udp(&self, target: &crate::net::datagram::UdpTargetAddr) -> &'static str {
        let host_str = match target {
            crate::net::datagram::UdpTargetAddr::Ip(addr) => addr.ip().to_string(),
            crate::net::datagram::UdpTargetAddr::Domain { host, .. } => host.clone(),
        };

        // 基于共享索引决策
        let idx = { self.idx.read().unwrap_or_else(|e| e.into_inner()).clone() };

        // Check exact/suffix first
        if let Some(d) = super::router_index_decide_exact_suffix(&idx, &host_str) {
            return d;
        }

        // Check GeoSite rules if database is available
        if let Some(geosite_db) = &self.geosite_db {
            if let Some(d) = super::router_index_decide_geosite(&idx, &host_str, geosite_db) {
                return d;
            }
        }

        // Check IP rules
        if let Ok(ip) = host_str.parse::<IpAddr>() {
            if let Some(d) = super::router_index_decide_ip(&idx, ip) {
                return d;
            }
        }

        idx.default
    }

    /// 基于当前索引快照进行 UDP 决策（最小可用版）
    pub async fn decide_udp_async(&self, host: &str) -> &'static str {
        let started = Instant::now();
        let budget = std::env::var("SB_ROUTER_DECIDE_BUDGET_MS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(5);
        let idx = { self.idx.read().unwrap_or_else(|e| e.into_inner()).clone() };
        let host_norm: String = normalize_host(host);
        // 复合缓存键：transport|host_norm（UDP 无端口）
        let cache_key = format!("udp|{}", host_norm);
        // 运行时覆盖（仅调试）
        if let Some((d, _tag)) = runtime_override_udp(&host_norm) {
            #[cfg(feature = "metrics")]
            metrics::counter!("router_decide_reason_total", "kind"=>_tag).increment(1);
            #[cfg(feature = "metrics")]
            metrics::histogram!("router_decide_latency_ms_bucket")
                .record(started.elapsed().as_millis() as f64);
            return d;
        }
        // 缓存命中直接返回
        if let Some(dec) = self.cache_try_get(&cache_key) {
            #[cfg(feature = "metrics")]
            metrics::histogram!("router_decide_latency_ms_bucket")
                .record(started.elapsed().as_millis() as f64);
            #[cfg(feature = "metrics")]
            metrics::counter!("router_decide_reason_total", "kind"=>"cache").increment(1);
            return dec;
        }

        // 1) exact/suffix 快路
        if let Some(d) = router_index_decide_exact_suffix(&idx, &host_norm) {
            self.cache_put(&cache_key, d);
            #[cfg(feature = "metrics")]
            {
                metrics::histogram!("router_decide_latency_ms_bucket")
                    .record(started.elapsed().as_millis() as f64);
                let kind = if idx.exact.contains_key(&host_norm) {
                    "exact"
                } else {
                    "suffix"
                };
                metrics::counter!("router_decide_reason_total", "kind"=>kind).increment(1);
            }
            return d;
        }

        // 1.5) GeoSite domain categorization
        if let Some(geosite_db) = &self.geosite_db {
            if let Some(d) = router_index_decide_geosite(&idx, &host_norm, geosite_db) {
                self.cache_put(&cache_key, d);
                #[cfg(feature = "metrics")]
                {
                    metrics::histogram!("router_decide_latency_ms_bucket")
                        .record(started.elapsed().as_millis() as f64);
                    metrics::counter!("router_decide_reason_total", "kind"=>"geosite").increment(1);
                }
                return d;
            }
        }

        // 2) 字面量 IP
        if let Ok(ip) = host_norm.parse::<IpAddr>() {
            if let Some(d) = router_index_decide_ip(&idx, ip) {
                self.cache_put(&cache_key, d);
                #[cfg(feature = "metrics")]
                {
                    metrics::histogram!("router_decide_latency_ms_bucket")
                        .record(started.elapsed().as_millis() as f64);
                    metrics::counter!("router_decide_reason_total", "kind"=>"ip").increment(1);
                }
                return d;
            }
        }

        // 3) （可选）DNS → IP → 规则 / GeoIP
        let try_dns = std::env::var("SB_ROUTER_DNS")
            .ok()
            .map(|v| v == "1")
            .unwrap_or(false);
        let try_geoip = std::env::var("SB_GEOIP_ENABLE")
            .ok()
            .map(|v| v == "1")
            .unwrap_or(false);
        if try_dns {
            {
                let timeout_ms = std::env::var("SB_ROUTER_DNS_TIMEOUT_MS")
                    .ok()
                    .and_then(|v| v.parse::<u64>().ok())
                    .unwrap_or(300);
                let dns_started = Instant::now();
                // 解析
                let resolved = self.resolve_with_fallback(&host_norm, timeout_ms).await;
                let _dns_elapsed = dns_started.elapsed().as_millis() as f64;
                #[cfg(feature = "metrics")]
                metrics::histogram!("router_dns_resolve_ms_bucket").record(_dns_elapsed);
                match resolved {
                    DnsResult::Ok(ips) => {
                        #[cfg(feature = "metrics")]
                        metrics::counter!("router_dns_resolve_total", "rcode"=>"ok").increment(1);
                        // 先按规则匹配
                        for ip in &ips {
                            if let Some(d) = router_index_decide_ip(&idx, *ip) {
                                self.cache_put(&cache_key, d);
                                #[cfg(feature = "metrics")]
                                {
                                    metrics::histogram!("router_decide_latency_ms_bucket")
                                        .record(started.elapsed().as_millis() as f64);
                                    metrics::counter!("router_decide_reason_total", "kind"=>"dns_ip").increment(1);
                                }
                                return d;
                            }
                        }
                        // 再尝试 GeoIP（任一 IP 命中即返回）
                        if try_geoip {
                            for ip in ips {
                                if let Some(d) = self.enhanced_geoip_lookup(ip, &idx) {
                                    self.cache_put(&cache_key, d);
                                    #[cfg(feature = "metrics")]
                                    {
                                        metrics::histogram!("router_decide_latency_ms_bucket")
                                            .record(started.elapsed().as_millis() as f64);
                                        metrics::counter!("router_decide_reason_total", "kind"=>"dns_geoip").increment(1);
                                    }
                                    return d;
                                }
                            }
                        }
                    }
                    DnsResult::Miss => {
                        #[cfg(feature = "metrics")]
                        metrics::counter!("router_dns_resolve_total", "rcode"=>"miss").increment(1);
                    }
                    DnsResult::Timeout => {
                        #[cfg(feature = "metrics")]
                        metrics::counter!("router_dns_resolve_total", "rcode"=>"timeout")
                            .increment(1);
                    }
                    DnsResult::Error => {
                        #[cfg(feature = "metrics")]
                        metrics::counter!("router_dns_resolve_total", "rcode"=>"error")
                            .increment(1);
                    }
                }
                // 预算短路：如果 DNS 解析已耗尽整体预算，直接返回默认并打点降级
                // 仅用于调试/统计；避免未使用告警
                let _elapsed_ms = started.elapsed().as_millis() as u64;
                if _elapsed_ms > budget {
                    #[cfg(feature = "metrics")]
                    {
                        metrics::histogram!("router_decide_latency_ms_bucket")
                            .record(_elapsed_ms as f64);
                        metrics::counter!("router_degrade_total", "reason"=>"budget").increment(1);
                    }
                    self.cache_put(&cache_key, idx.default);
                    return idx.default;
                }
            }
        }

        // 4) 传输/端口兜底（UDP 场景：transport=udp，port 不可用）
        if let Some(d) = router_index_decide_transport_port(&idx, None, Some("udp")) {
            self.cache_put(&cache_key, d);
            #[cfg(feature = "metrics")]
            metrics::histogram!("router_decide_latency_ms_bucket")
                .record(started.elapsed().as_millis() as f64);
            #[cfg(feature = "metrics")]
            metrics::counter!("router_decide_reason_total", "kind"=>"transport").increment(1);
            return d;
        }

        // 5) 默认退回，并在超预算时计 degrade（仅"未定→默认"触发）
        let dec = idx.default;
        // 仅用于调试/统计；避免未使用告警
        let _elapsed_ms = started.elapsed().as_millis() as u64;
        #[cfg(feature = "metrics")]
        {
            metrics::histogram!("router_decide_latency_ms_bucket").record(_elapsed_ms as f64);
            if _elapsed_ms > budget {
                metrics::counter!("router_degrade_total", "reason"=>"budget").increment(1);
            }
            metrics::counter!("router_decide_reason_total", "kind"=>"default").increment(1);
        }
        self.cache_put(&cache_key, dec);
        dec
    }

    /// 旧接口适配：根据上下文进行路由并返回 RouteTarget（不做 DNS，仅 exact/suffix/IP/default）
    pub fn select_ctx_and_record(&self, ctx: RouteCtx) -> RouteTarget {
        // 拿快照
        let idx = { self.idx.read().unwrap_or_else(|e| e.into_inner()).clone() };
        // host 优先
        if let Some(h) = ctx.host {
            if let Some(d) = router_index_decide_exact_suffix(&idx, h) {
                return RouteTarget::Named(d.to_string());
            }
            // host 可能是字面量 IP:PORT
            if let Some((raw, _)) = h.rsplit_once(':') {
                if let Ok(ip) = raw.parse::<IpAddr>() {
                    if let Some(d) = router_index_decide_ip(&idx, ip) {
                        return RouteTarget::Named(d.to_string());
                    }
                }
            } else if let Ok(ip) = h.parse::<IpAddr>() {
                if let Some(d) = router_index_decide_ip(&idx, ip) {
                    return RouteTarget::Named(d.to_string());
                }
            }
        }
        // 明确 IP 兜底
        if let Some(ip) = ctx.ip {
            if let Some(d) = router_index_decide_ip(&idx, ip) {
                return RouteTarget::Named(d.to_string());
            }
        }
        RouteTarget::Named(idx.default.to_string())
    }
}

// Explain-only: export a read-only JSON view of rules (real snapshot)
#[cfg(feature = "explain")]
impl RouterHandle {
    /// Export a stable JSON snapshot of routing rules for offline explain.
    /// This is a read-only snapshot and does not mutate runtime state.
    pub fn export_rules_json(&self) -> Result<serde_json::Value, String> {
        use serde_json::json;
        let guard = self
            .idx
            .read()
            .map_err(|_| "router index lock poisoned".to_string())?;
        let idx = guard.clone();

        // Build CIDR list (v4 + v6)
        let mut cidr = Vec::new();
        for (n, to) in &idx.cidr4 {
            let net = format!("{}/{}", n.net, n.mask);
            cidr.push(json!({ "net": net, "to": *to, "when": json!({}) }));
        }
        for (n, to) in &idx.cidr6 {
            let net = format!("{}/{}", n.net, n.mask);
            cidr.push(json!({ "net": net, "to": *to, "when": json!({}) }));
        }

        // Suffix rules
        let mut suffix = Vec::new();
        for (s, to) in &idx.suffix {
            suffix.push(json!({ "suffix": s, "to": *to, "when": json!({}) }));
        }

        // Exact rules
        let mut exact: Vec<(String, &'static str)> =
            idx.exact.iter().map(|(k, v)| (k.clone(), *v)).collect();
        // Optional: provide stable ordering for readability
        exact.sort_by(|a, b| a.0.cmp(&b.0));
        let exact = exact
            .into_iter()
            .map(|(h, to)| json!({ "host": h, "to": to, "when": json!({}) }))
            .collect::<Vec<_>>();

        // Geo rules (placeholder for now)
        let mut geo = Vec::new();
        if let Some(rules) = self.rules_geo() {
            for r in rules {
                geo.push(json!({
                    "cc": r.country, "to": r.to_name, "when": r.when_json,
                }));
            }
        }

        // Runtime override view (best-effort, parsed from SB_ROUTER_OVERRIDE)
        let mut ov_exact = Vec::new();
        let mut ov_suffix = Vec::new();
        let mut ov_default: Option<String> = None;
        if let Ok(raw) = std::env::var("SB_ROUTER_OVERRIDE") {
            if !raw.trim().is_empty() {
                for seg in raw.split(|c| c == ',' || c == ';') {
                    let s = seg.trim();
                    if s.is_empty() {
                        continue;
                    }
                    let (k, v) = match s.split_once('=') {
                        Some((a, b)) => (a.trim(), b.trim()),
                        None => continue,
                    };
                    if k.eq_ignore_ascii_case("default") {
                        ov_default = Some(v.to_string());
                        continue;
                    }
                    if let Some((kind, pat)) = k.split_once(':') {
                        match kind.to_ascii_lowercase().as_str() {
                            "exact" => {
                                ov_exact.push(
                                    json!({ "host": pat.to_string(), "to": v, "when": json!({}) }),
                                );
                            }
                            "suffix" => {
                                let patt = pat.trim_start_matches('.');
                                ov_suffix.push(json!({ "suffix": patt.to_string(), "to": v, "when": json!({}) }));
                            }
                            _ => {}
                        }
                    }
                }
            }
        }

        Ok(json!({
            "cidr": cidr,
            "suffix": suffix,
            "exact": exact,
            "geo": geo,
            "ov_exact": ov_exact,
            "ov_suffix": ov_suffix,
            "ov_default": ov_default.unwrap_or_default(),
        }))
    }

    pub fn export_and_rebuild(&self) -> Result<(), String> {
        let snapshot = self.export_rules_json()?;
        super::explain_bridge::rebuild_index(&snapshot)
    }

    /// Explain 旁路可选地查询 IP→国家码（未接入则返回 None）
    #[cfg(feature = "explain")]
    pub fn geo_cc(&self, _ip: std::net::IpAddr) -> Option<String> {
        #[cfg(feature = "geoip_mmdb")]
        {
            let mut provider_seen = false;
            if let Some(mux) = self.geoip_mux.as_ref() {
                provider_seen = true;
                if let Some((source, cc)) = mux.lookup(_ip) {
                    #[cfg(feature = "metrics")]
                    metrics::counter!("geoip_lookup_total", "source"=>source.as_str().to_string())
                        .increment(1);
                    return Some(cc);
                }
            }
            if let Some(geo) = self.geoip.as_ref() {
                provider_seen = true;
                if let Some(geo_info) = geo.lookup(_ip) {
                    if let Some(cc) = geo_info.country_code {
                        #[cfg(feature = "metrics")]
                        {
                            let label = self.geoip_source.as_deref().unwrap_or("legacy");
                            metrics::counter!("geoip_lookup_total", "source"=>label.to_string())
                                .increment(1);
                        }
                        return Some(cc);
                    }
                }
            }
            #[cfg(feature = "metrics")]
            if provider_seen {
                metrics::counter!("geoip_lookup_total", "source"=>"miss").increment(1);
            }
        }
        None
    }

    /// 返回 geo 规则的只读视图（占位，实际实现需接入真实数据）
    pub fn rules_geo(&self) -> Option<Vec<GeoRuleView>> {
        None
    }

    /// 返回 exact 规则的只读视图（占位）
    pub fn rules_exact(&self) -> Option<Vec<ExactRuleView>> {
        None
    }
}

// Placeholder structs for geo and exact rule views
#[cfg(feature = "explain")]
pub struct GeoRuleView {
    pub country: String,
    pub to_name: String,
    pub when_json: serde_json::Value,
}

#[cfg(feature = "explain")]
pub struct ExactRuleView {
    pub host: String,
    pub to_name: String,
    pub when_json: serde_json::Value,
}

/// 兼容历史导出（占位类型，避免下游编译失败；如未使用可忽略）
#[derive(Clone, Copy, Debug)]
pub enum Transport {
    Tcp,
    Udp,
}

/// 旧接口上下文（按 sb-adapters 预期提供字段）
#[derive(Clone, Copy, Debug)]
pub struct RouteCtx<'a> {
    pub host: Option<&'a str>,
    pub ip: Option<IpAddr>,
    pub port: Option<u16>,
    pub transport: Transport,
}

// ===== 兼容层：Rule / CompositeRule / Router（旧 API 期望） =====

/// 旧版决策：最小实现，内部以 &'static str 表示目标名（例如 "direct"/某 outbound 名）
#[derive(Debug, Clone, Copy)]
pub enum RouteDecision {
    Named(&'static str),
    Direct,
    Proxy,
    Reject,
}
impl RouteDecision {
    pub fn as_str(&self) -> &'static str {
        match *self {
            RouteDecision::Named(s) => s,
            RouteDecision::Direct => "direct",
            RouteDecision::Proxy => "proxy",
            RouteDecision::Reject => "reject",
        }
    }
}
impl PartialEq<&str> for RouteDecision {
    fn eq(&self, other: &&str) -> bool {
        self.as_str() == *other
    }
}
impl From<RouteDecision> for String {
    fn from(decision: RouteDecision) -> String {
        decision.as_str().to_string()
    }
}

/// 旧版复合规则：保留 sb-config 使用到的字段名
/// - domain_suffix/ip_cidr/port 多为 Vec<String>
/// - transport 在 sb-config 中为 Option<String>
/// - target 使用 **根导出** 的 crate::RouteTarget，确保两侧类型一致
#[allow(non_snake_case)]
pub struct CompositeRule<
    DS = Vec<String>,
    CIDR = Vec<String>,
    PORT = Vec<String>,
    TRANS = Option<String>,
    // 关键：将目标类型默认设为 crate::outbound::RouteTarget，以兼容 sb-config 的导入
    TARGET = RouteTarget,
> {
    pub domain_suffix: DS,
    pub ip_cidr: CIDR,
    pub port: PORT,
    pub transport: TRANS,
    pub target: TARGET,
}

/// 旧版规则枚举：仅实现 sb-config 侧用到的两个变体
/// - DomainSuffix 只收 **(String, crate::RouteTarget)** 两个参数以匹配 sb-config 的调用
pub enum Rule<
    DS = Vec<String>,
    CIDR = Vec<String>,
    PORT = Vec<String>,
    TRANS = Option<String>,
    // 同上：默认目标类型跟随 sb-config 的 RouteTarget
    TARGET = RouteTarget,
> {
    Composite(CompositeRule<DS, CIDR, PORT, TRANS, TARGET>),
    DomainSuffix(String, TARGET),
}

/// 旧版 Router：仅提供构造与 set_rules"吞掉"规则（不改变运行时逻辑）
#[allow(dead_code)]
pub struct Router {
    #[allow(dead_code)]
    default: &'static str,
}

impl Default for Router {
    fn default() -> Self {
        Self { default: "direct" }
    }
}

impl Router {
    /// Create a minimal router for testing
    pub fn new_minimal() -> Self {
        Self { default: "direct" }
    }

    /// Make routing decision
    pub fn decide(&self, _ctx: &super::RouteCtx) -> super::RouteDecision {
        // Simplified implementation - return default decision
        super::RouteDecision {
            target: self.default.to_string(),
            matched_rule: None,
        }
    }

    /// 允许任意类型作为"默认出口"参数（例如 sb-config 的 OutboundKind::Direct）
    /// 占位实现仅用于满足类型期望，行为上默认仍为 "direct"。
    pub fn with_default<T>(_default: T) -> Self {
        Self { default: "direct" }
    }

    /// 吞掉 sb-config 下发的规则列表；新架构实际路由由编译化索引承担
    pub fn set_rules<DS, CIDR, PORT, TRANS, TARGET>(
        &mut self,
        _rules: Vec<Rule<DS, CIDR, PORT, TRANS, TARGET>>,
    ) {
        // no-op：兼容旧 API，不影响新索引与决策路径
    }
}

/// 调试用 Explain：返回命中路径与决策。非热路径，生产不建议频繁调用。
#[derive(Debug, Clone)]
pub struct DecisionExplain {
    pub decision: String,
    pub reason: String,
    pub reason_kind: String,
    #[cfg(feature = "router_cache_explain")]
    pub cache_status: Option<String>, // "hit" | "miss" | None (if cache not used)
}

pub fn decide_http_explain(target: &str) -> DecisionExplain {
    let idx = {
        shared_index()
            .read()
            .unwrap_or_else(|e| {
                eprintln!("RwLock poisoned; proceeding with inner guard");
                e.into_inner()
            })
            .clone()
    };
    let (host_raw, port_opt) = if let Some((h, p)) = target.rsplit_once(':') {
        (h, p.parse::<u16>().ok())
    } else {
        (target, None)
    };
    let host = normalize_host(host_raw);
    if let Some(d) = super::router_index_decide_exact_suffix(&idx, &host) {
        let k = if idx.exact.contains_key(&host) {
            "exact"
        } else {
            "suffix"
        };
        return DecisionExplain {
            decision: d.to_string(),
            reason: format!("{} matched host={}", k, host),
            reason_kind: k.into(),
            #[cfg(feature = "router_cache_explain")]
            cache_status: None,
        };
    }
    #[cfg(feature = "router_keyword")]
    {
        if let Some(index) = &idx.keyword_idx {
            if let Some(i) = index.find_idx(&host) {
                let dec = index
                    .decs
                    .get(i)
                    .cloned()
                    .unwrap_or_else(|| idx.default.to_string());
                return DecisionExplain {
                    decision: dec,
                    reason: format!("keyword matched host={}", host),
                    reason_kind: "keyword".into(),
                    #[cfg(feature = "router_cache_explain")]
                    cache_status: None,
                };
            }
        }
    }
    if let Ok(ip) = host.parse::<IpAddr>() {
        if let Some(d) = super::router_index_decide_ip(&idx, ip) {
            return DecisionExplain {
                decision: d.to_string(),
                reason: format!("ip matched ip={}", ip),
                reason_kind: "ip".into(),
                #[cfg(feature = "router_cache_explain")]
                cache_status: None,
            };
        }
    }
    if let Some(d) = super::router_index_decide_transport_port(&idx, port_opt, Some("tcp")) {
        let k = if port_opt.is_some() {
            "port"
        } else {
            "transport"
        };
        return DecisionExplain {
            decision: d.to_string(),
            reason: format!("transport/port matched transport=tcp port={:?}", port_opt),
            reason_kind: k.into(),
            #[cfg(feature = "router_cache_explain")]
            cache_status: None,
        };
    }
    DecisionExplain {
        decision: idx.default.to_string(),
        reason: "default".into(),
        reason_kind: "default".into(),
        #[cfg(feature = "router_cache_explain")]
        cache_status: None,
    }
}

pub async fn decide_udp_async_explain(handle: &RouterHandle, host: &str) -> DecisionExplain {
    let idx = {
        handle
            .idx
            .read()
            .unwrap_or_else(|e| {
                eprintln!("RwLock poisoned; proceeding with inner guard");
                e.into_inner()
            })
            .clone()
    };
    let host_norm = normalize_host(host);
    if let Some(d) = super::router_index_decide_exact_suffix(&idx, &host_norm) {
        let k = if idx.exact.contains_key(&host_norm) {
            "exact"
        } else {
            "suffix"
        };
        return DecisionExplain {
            decision: d.to_string(),
            reason: format!("{} matched host={}", k, host_norm),
            reason_kind: k.into(),
            #[cfg(feature = "router_cache_explain")]
            cache_status: None,
        };
    }
    #[cfg(feature = "router_keyword")]
    {
        if let Some(index) = &idx.keyword_idx {
            if let Some(i) = index.find_idx(&host_norm) {
                let dec = index
                    .decs
                    .get(i)
                    .cloned()
                    .unwrap_or_else(|| idx.default.to_string());
                return DecisionExplain {
                    decision: dec,
                    reason: format!("keyword matched host={}", host_norm),
                    reason_kind: "keyword".into(),
                    #[cfg(feature = "router_cache_explain")]
                    cache_status: None,
                };
            }
        }
    }
    if let Ok(ip) = host_norm.parse::<IpAddr>() {
        if let Some(d) = super::router_index_decide_ip(&idx, ip) {
            return DecisionExplain {
                decision: d.to_string(),
                reason: format!("ip matched ip={}", ip),
                reason_kind: "ip".into(),
                #[cfg(feature = "router_cache_explain")]
                cache_status: None,
            };
        }
    }
    // DNS → IP → 规则/GeoIP（若开启）
    let try_dns = std::env::var("SB_ROUTER_DNS")
        .ok()
        .map(|v| v == "1")
        .unwrap_or(false);
    let try_geoip = std::env::var("SB_GEOIP_ENABLE")
        .ok()
        .map(|v| v == "1")
        .unwrap_or(false);
    if try_dns {
        let timeout_ms = std::env::var("SB_ROUTER_DNS_TIMEOUT_MS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(300);
        match handle.resolve_with_fallback(&host_norm, timeout_ms).await {
            DnsResult::Ok(ips) => {
                for ip in &ips {
                    if let Some(d) = super::router_index_decide_ip(&idx, *ip) {
                        return DecisionExplain {
                            decision: d.to_string(),
                            reason: format!("dns->ip matched ip={}", ip),
                            reason_kind: "dns_ip".into(),
                            #[cfg(feature = "router_cache_explain")]
                            cache_status: None,
                        };
                    }
                }
                if try_geoip {
                    for ip in ips {
                        if let Some(d) = lookup_with_metrics_decision(ip) {
                            return DecisionExplain {
                                decision: d.to_string(),
                                reason: format!("dns->geoip matched ip={}", ip),
                                reason_kind: "dns_geoip".into(),
                                #[cfg(feature = "router_cache_explain")]
                                cache_status: None,
                            };
                        }
                    }
                }
            }
            DnsResult::Miss => {}
            DnsResult::Timeout | DnsResult::Error => {}
        }
    }
    if let Some(d) = super::router_index_decide_transport_port(&idx, None, Some("udp")) {
        return DecisionExplain {
            decision: d.to_string(),
            reason: "transport/port matched transport=udp".into(),
            reason_kind: "transport".into(),
            #[cfg(feature = "router_cache_explain")]
            cache_status: None,
        };
    }
    DecisionExplain {
        decision: idx.default.to_string(),
        reason: "default".into(),
        reason_kind: "default".into(),
        #[cfg(feature = "router_cache_explain")]
        cache_status: None,
    }
}

// ---------------- R11: bench feature 下的只读辅助 ----------------
#[cfg(feature = "bench")]
impl RouterHandle {
    /// 返回当前 gen（只读），便于基准与可视化记录
    pub fn current_gen(&self) -> u64 {
        self.idx.read().unwrap_or_else(|e| e.into_inner()).gen
    }

    /// Get a read lock on the router index for explain functionality
    pub fn get_index(&self) -> std::sync::RwLockReadGuard<'_, Arc<RouterIndex>> {
        self.idx.read().unwrap_or_else(|e| {
            eprintln!("RwLock poisoned; proceeding with inner guard");
            e.into_inner()
        })
    }

    /// Get reference to the GeoIP database for explain functionality
    pub fn get_geoip_db(&self) -> Option<&std::sync::Arc<crate::router::geo::GeoIpDb>> {
        self.geoip_db.as_ref()
    }
}

#[cfg(feature = "geoip_mmdb")]
impl RouterHandle {
    pub(crate) fn init_geoip_if_env(&mut self) {
        use std::time::Duration;
        self.geoip_mux = crate::geoip::multi::GeoMux::from_env().ok();
        self.geoip = None;
        self.geoip_source = None;
        if let Ok(path) = std::env::var("SB_GEOIP_MMDB") {
            let cap = std::env::var("SB_GEOIP_CACHE")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(8192);
            let ttl = std::env::var("SB_GEOIP_TTL")
                .ok()
                .and_then(|v| humantime::parse_duration(&v).ok())
                .unwrap_or(Duration::from_secs(600));
            match crate::geoip::mmdb::GeoIp::open(std::path::Path::new(&path), cap, ttl) {
                Ok(geo) => {
                    self.geoip = Some(std::sync::Arc::new(geo));
                    self.geoip_source = Some(path);
                }
                Err(err) => {
                    tracing::warn!("failed to open mmdb: {:?} at {:?}", err, path)
                }
            }
        }
    }
}

impl RouterHandle {
    /// Get a snapshot of the current RouterIndex (for read-only analysis/explain)
    pub fn index_snapshot(&self) -> Arc<RouterIndex> {
        self.idx.read().unwrap_or_else(|e| e.into_inner()).clone()
    }
}
