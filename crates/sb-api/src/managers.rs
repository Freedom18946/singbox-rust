//! API layer managers for connection tracking, DNS, and other services
//! API 层管理器，用于连接跟踪、DNS 和其他服务
//!
//! This module contains the state managers that bridge the API layer with the core logic.
//! They are responsible for maintaining ephemeral state needed for API responses, such as
//! active connection lists, DNS caches for API queries, and external provider statuses.
//!
//! 本模块包含将 API 层与核心逻辑连接起来的状态管理器。它们负责维护 API 响应所需的
//! 临时状态，例如活动连接列表、API 查询的 DNS 缓存以及外部提供者状态。

use crate::{error::ApiResult, types::TrafficStats};
use std::{
    collections::HashMap,
    future::Future,
    net::SocketAddr,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::sync::{RwLock, watch};
use uuid::Uuid;

/// Async function type for fetching provider content from a URL.
///
/// Production code wraps `sb_subscribe::http::fetch_text`; tests use mocks.
pub type FetchFn = Arc<
    dyn Fn(&str) -> Pin<Box<dyn Future<Output = Result<String, String>> + Send>> + Send + Sync,
>;

#[cfg(feature = "provider-reload")]
fn production_fetch() -> FetchFn {
    Arc::new(|url| {
        let url = url.to_string();
        Box::pin(async move {
            sb_subscribe::http::fetch_text(&url)
                .await
                .map_err(|err| err.to_string())
        })
    })
}

/// Represents an active network connection
/// 表示一个活动的网络连接
///
/// Used by `ConnectionManager` to track traffic for the dashboard.
/// 用于 `ConnectionManager` 跟踪仪表盘的流量。
#[derive(Debug, Clone)]
pub struct Connection {
    /// Unique connection identifier
    /// 唯一连接标识符
    pub id: String,
    /// Source address (client)
    /// 源地址（客户端）
    pub source: SocketAddr,
    /// Destination address (target)
    /// 目的地址（目标）
    pub destination: String,
    /// Selected outbound proxy
    /// 选定的出站代理
    pub proxy: String,
    /// Connection start time
    /// 连接开始时间
    pub start_time: Instant,
    /// Bytes uploaded
    /// 上传字节数
    pub upload: Arc<AtomicU64>,
    /// Bytes downloaded
    /// 下载字节数
    pub download: Arc<AtomicU64>,
    /// Connection type (TCP/UDP)
    /// 连接类型（TCP/UDP）
    pub network: String,
    /// Rule that matched this connection
    /// 匹配此连接的规则
    pub rule: String,
    /// Chain of proxies used
    /// 使用的代理链
    pub chains: Vec<String>,
}

impl Connection {
    /// Create a new connection.
    /// 创建新连接。
    pub fn new(
        source: SocketAddr,
        destination: String,
        proxy: String,
        network: String,
        rule: String,
    ) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            source,
            destination,
            proxy: proxy.clone(),
            start_time: Instant::now(),
            upload: Arc::new(AtomicU64::new(0)),
            download: Arc::new(AtomicU64::new(0)),
            network,
            rule,
            chains: vec![proxy],
        }
    }

    /// Update upload bytes.
    /// 更新上传字节数。
    pub fn add_upload(&self, bytes: u64) {
        self.upload.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Update download bytes.
    /// 更新下载字节数。
    pub fn add_download(&self, bytes: u64) {
        self.download.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Get current upload bytes.
    /// 获取当前上传字节数。
    pub fn get_upload(&self) -> u64 {
        self.upload.load(Ordering::Relaxed)
    }

    /// Get current download bytes.
    /// 获取当前下载字节数。
    pub fn get_download(&self) -> u64 {
        self.download.load(Ordering::Relaxed)
    }

    /// Get connection duration.
    /// 获取连接持续时间。
    pub fn duration(&self) -> Duration {
        self.start_time.elapsed()
    }
}

/// Manager for tracking active connections
/// 活动连接跟踪管理器
///
/// # Strategic Role / 战略角色
///
/// The `ConnectionManager` is the source of truth for the "Connections" page in dashboards.
/// It aggregates data from `sb-core`'s traffic handlers and presents a unified view of
/// who is connecting to what.
///
/// `ConnectionManager` 是仪表盘中“连接”页面的事实来源。它聚合来自 `sb-core` 流量处理程序
/// 的数据，并提供关于谁连接到哪里的统一视图。
#[derive(Debug)]
pub struct ConnectionManager {
    /// Active connections by ID
    /// 按 ID 存储的活动连接
    connections: Arc<RwLock<HashMap<String, Connection>>>,
    /// Global traffic statistics
    /// 全局流量统计
    global_stats: Arc<TrafficStats>,
}

impl ConnectionManager {
    /// Create a new connection manager.
    /// 创建新的连接管理器。
    pub fn new() -> Self {
        Self {
            connections: Arc::new(RwLock::new(HashMap::new())),
            global_stats: Arc::new(TrafficStats::default()),
        }
    }

    /// Add a new connection.
    /// 添加新连接。
    pub async fn add_connection(&self, connection: Connection) -> ApiResult<()> {
        let mut connections = self.connections.write().await;
        connections.insert(connection.id.clone(), connection);
        Ok(())
    }

    /// Remove a connection by ID.
    /// 按 ID 移除连接。
    pub async fn remove_connection(&self, id: &str) -> ApiResult<bool> {
        let mut connections = self.connections.write().await;
        Ok(connections.remove(id).is_some())
    }

    /// Get all active connections.
    /// 获取所有活动连接。
    pub async fn get_connections(&self) -> ApiResult<Vec<Connection>> {
        let connections = self.connections.read().await;
        Ok(connections.values().cloned().collect())
    }

    /// Get connection by ID.
    /// 按 ID 获取连接。
    pub async fn get_connection(&self, id: &str) -> ApiResult<Option<Connection>> {
        let connections = self.connections.read().await;
        Ok(connections.get(id).cloned())
    }

    /// Close all connections.
    /// 关闭所有连接。
    pub async fn close_all_connections(&self) -> ApiResult<usize> {
        let mut connections = self.connections.write().await;
        let count = connections.len();
        connections.clear();
        Ok(count)
    }

    /// Get connection count.
    /// 获取连接数量。
    pub async fn get_connection_count(&self) -> usize {
        let connections = self.connections.read().await;
        connections.len()
    }

    /// Update global traffic statistics.
    /// 更新全局流量统计。
    pub fn update_global_traffic(&self, upload: u64, download: u64) {
        self.global_stats.add_traffic(upload, download);
    }

    /// Get global traffic statistics.
    /// 获取全局流量统计。
    pub fn get_global_stats(&self) -> Arc<TrafficStats> {
        Arc::clone(&self.global_stats)
    }
}

impl Default for ConnectionManager {
    fn default() -> Self {
        Self::new()
    }
}

/// DNS cache entry
/// DNS 缓存条目
#[derive(Debug, Clone)]
pub struct DnsCacheEntry {
    /// Resolved IP addresses
    /// 解析的 IP 地址
    pub addresses: Vec<SocketAddr>,
    /// Cache entry expiration time
    /// 缓存条目过期时间
    pub expires_at: Instant,
    /// Query type (A, AAAA, etc.)
    /// 查询类型（A, AAAA 等）
    pub query_type: String,
}

/// DNS resolver with caching capabilities
/// 具有缓存功能的 DNS 解析器
///
/// # Strategic Role / 战略角色
///
/// While `sb-core` has its own DNS stack for routing, this `DnsResolver` is specifically
/// for the API layer (e.g., for the "DNS Query" tool in dashboards) and for supporting
/// Clash's "FakeIP" mode where the API needs to resolve fake IPs back to domains for display.
///
/// 虽然 `sb-core` 有自己的用于路由的 DNS 栈，但此 `DnsResolver` 专门用于 API 层
/// （例如仪表盘中的“DNS 查询”工具）以及支持 Clash 的 "FakeIP" 模式，在该模式下，
/// API 需要将伪造 IP 解析回域名以进行显示。
#[derive(Debug)]
pub struct DnsResolver {
    /// DNS cache entries
    /// DNS 缓存条目
    cache: Arc<RwLock<HashMap<String, DnsCacheEntry>>>,
    /// Fake IP mappings (for Clash compatibility)
    /// 伪造 IP 映射（用于 Clash 兼容性）
    fake_ip_mappings: Arc<RwLock<HashMap<String, String>>>,
    /// DNS server configuration
    /// DNS 服务器配置
    #[allow(dead_code)]
    dns_servers: Vec<SocketAddr>,
}

impl DnsResolver {
    /// Create a new DNS resolver.
    /// 创建新的 DNS 解析器。
    ///
    /// # Panics
    /// This function will panic if hardcoded DNS server addresses are invalid (should never happen).
    #[allow(clippy::expect_used)]
    pub fn new() -> Self {
        Self {
            cache: Arc::new(RwLock::new(HashMap::new())),
            fake_ip_mappings: Arc::new(RwLock::new(HashMap::new())),
            dns_servers: vec![
                "8.8.8.8:53"
                    .parse()
                    .expect("hardcoded DNS server must be valid"),
                "1.1.1.1:53"
                    .parse()
                    .expect("hardcoded DNS server must be valid"),
            ],
        }
    }

    /// Flush DNS cache.
    /// 清空 DNS 缓存。
    pub async fn flush_dns_cache(&self) -> ApiResult<()> {
        let mut cache = self.cache.write().await;
        let cleared = cache.len();
        cache.clear();
        log::info!("DNS cache flushed, {} entries cleared", cleared);
        Ok(())
    }

    /// Flush fake IP cache.
    /// 清空伪造 IP 缓存。
    pub async fn flush_fake_ip_cache(&self) -> ApiResult<()> {
        let count = sb_core::dns::fakeip::reset();
        let mut fake_ips = self.fake_ip_mappings.write().await;
        fake_ips.clear();
        log::info!("Fake IP cache flushed, {} entries cleared", count);
        Ok(())
    }

    /// Get cache statistics.
    /// 获取缓存统计信息。
    pub async fn get_cache_stats(&self) -> (usize, usize) {
        let cache = self.cache.read().await;
        (cache.len(), sb_core::dns::fakeip::mapping_count())
    }

    /// Add fake IP mapping.
    /// 添加伪造 IP 映射。
    pub async fn add_fake_ip_mapping(&self, domain: String, fake_ip: String) -> ApiResult<()> {
        let mut fake_ips = self.fake_ip_mappings.write().await;
        fake_ips.insert(domain, fake_ip);
        Ok(())
    }

    /// Resolve fake IP to domain.
    /// 将伪造 IP 解析为域名。
    pub async fn resolve_fake_ip(&self, fake_ip: &str) -> Option<String> {
        fake_ip
            .parse()
            .ok()
            .and_then(|ip| sb_core::dns::fakeip::lookup_domain(&ip))
    }

    /// Query DNS for a domain.
    /// 查询域名的 DNS。
    ///
    /// This performs a DNS query and returns the resolved IP addresses.
    /// The query is cached with TTL for performance.
    /// 这将执行 DNS 查询并返回解析的 IP 地址。
    /// 查询结果会缓存 TTL 时间以提高性能。
    pub async fn query_dns(&self, name: &str, query_type: &str) -> ApiResult<Vec<String>> {
        // Check cache first
        let cache = self.cache.read().await;
        if let Some(entry) = cache.get(name) {
            if entry.expires_at > Instant::now() && entry.query_type == query_type {
                log::debug!("DNS cache hit for {} ({})", name, query_type);
                return Ok(entry.addresses.iter().map(|a| a.ip().to_string()).collect());
            }
        }
        drop(cache);

        log::info!("Performing DNS query for {} (type: {})", name, query_type);

        if sb_core::dns::fakeip::enabled() && matches!(query_type, "A" | "AAAA") {
            let ip = if query_type == "AAAA" {
                sb_core::dns::fakeip::allocate_v6(name)
            } else {
                sb_core::dns::fakeip::allocate_v4(name)
            };
            let addresses = vec![SocketAddr::new(ip, 0)];
            let cache_entry = DnsCacheEntry {
                addresses: addresses.clone(),
                expires_at: Instant::now() + Duration::from_secs(300),
                query_type: query_type.to_string(),
            };
            let mut cache = self.cache.write().await;
            cache.insert(name.to_string(), cache_entry);
            return Ok(vec![ip.to_string()]);
        }

        // Perform actual DNS query using tokio's resolver
        let addresses = match query_type {
            "A" | "AAAA" => {
                // Use tokio's DNS resolver
                match tokio::net::lookup_host(format!("{}:0", name)).await {
                    Ok(addrs) => {
                        let filtered: Vec<SocketAddr> = addrs
                            .filter(|addr| {
                                if query_type == "A" {
                                    addr.is_ipv4()
                                } else {
                                    addr.is_ipv6()
                                }
                            })
                            .collect();

                        if filtered.is_empty() {
                            // If no addresses of requested type, return all
                            tokio::net::lookup_host(format!("{}:0", name))
                                .await
                                .map_err(|e| crate::error::ApiError::Internal { source: e.into() })?
                                .collect::<Vec<_>>()
                        } else {
                            filtered
                        }
                    }
                    Err(e) => {
                        log::error!("DNS query failed for {}: {}", name, e);
                        return Err(crate::error::ApiError::Internal { source: e.into() });
                    }
                }
            }
            _ => {
                // Unsupported query type, fallback to A record
                log::warn!(
                    "Unsupported DNS query type {}, falling back to A",
                    query_type
                );
                tokio::net::lookup_host(format!("{}:0", name))
                    .await
                    .map_err(|e| crate::error::ApiError::Internal { source: e.into() })?
                    .filter(|addr| addr.is_ipv4())
                    .collect::<Vec<_>>()
            }
        };

        if addresses.is_empty() {
            log::warn!(
                "DNS query returned no results for {} ({})",
                name,
                query_type
            );
            return Ok(Vec::new());
        }

        // Cache the result
        let cache_entry = DnsCacheEntry {
            addresses: addresses.clone(),
            expires_at: Instant::now() + Duration::from_secs(300), // 5 minute TTL
            query_type: query_type.to_string(),
        };

        let mut cache = self.cache.write().await;
        cache.insert(name.to_string(), cache_entry);

        Ok(addresses.iter().map(|a| a.ip().to_string()).collect())
    }
}

impl Default for DnsResolver {
    fn default() -> Self {
        Self::new()
    }
}

/// Provider for proxy/rule management
/// 代理/规则管理提供者
#[derive(Debug, Clone)]
pub struct Provider {
    /// Provider name
    /// 提供者名称
    pub name: String,
    /// Provider type (proxy/rule)
    /// 提供者类型（代理/规则）
    pub provider_type: String,
    /// Provider URL for remote updates
    /// 用于远程更新的提供者 URL
    pub url: Option<String>,
    /// Update interval in seconds
    /// 更新间隔（秒）
    pub update_interval: u64,
    /// Last update time
    /// 上次更新时间
    pub last_update: Option<Instant>,
    /// Provider health status
    /// 提供者健康状态
    pub healthy: bool,
    /// Provider content (proxies or rules)
    /// 提供者内容（代理或规则）
    pub content: String,
}

impl Provider {
    /// Create a new provider.
    /// 创建新的提供者。
    pub fn new(name: String, provider_type: String) -> Self {
        Self {
            name,
            provider_type,
            url: None,
            update_interval: 3600, // 1 hour default
            last_update: None,
            healthy: true,
            content: String::new(),
        }
    }

    /// Check if provider needs update.
    /// 检查提供者是否需要更新。
    pub fn needs_update(&self) -> bool {
        if let Some(last_update) = self.last_update {
            last_update.elapsed().as_secs() > self.update_interval
        } else {
            true
        }
    }

    /// Mark provider as updated.
    pub fn mark_updated(&mut self) {
        self.last_update = Some(Instant::now());
    }
}

/// Manager for proxy and rule providers
/// 代理和规则提供者管理器
///
/// # Strategic Role / 战略角色
///
/// Manages external resources (subscription URLs, rule sets). It handles the fetching,
/// parsing, and updating of these resources, ensuring the core has the latest routing data
/// without blocking the main proxy loop.
///
/// 管理外部资源（订阅 URL、规则集）。它处理这些资源的获取、解析和更新，确保核心
/// 拥有最新的路由数据，而不会阻塞主代理循环。
pub struct ProviderManager {
    /// Proxy providers
    proxy_providers: Arc<RwLock<HashMap<String, Provider>>>,
    /// Rule providers
    rule_providers: Arc<RwLock<HashMap<String, Provider>>>,
    /// Injected URL fetcher (production wraps sb_subscribe; tests use mocks)
    fetch_fn: FetchFn,
    /// Outbound registry for health-check TCP probes
    outbound_registry: Option<Arc<sb_core::outbound::OutboundRegistryHandle>>,
    /// Health-check probe target (default: RouteTarget::direct())
    probe_target: sb_core::outbound::RouteTarget,
    /// Health-check probe endpoint (default: www.gstatic.com:443)
    probe_endpoint: sb_core::outbound::Endpoint,
    /// Background sweep interval (default 60s, overridable for tests)
    tick_interval: Duration,
    /// Handle to the background update task
    bg_task_handle: std::sync::Mutex<Option<tokio::task::JoinHandle<()>>>,
    /// Optional channel to send reload messages to the Supervisor for hot-reload.
    /// When set, successful fetches parse content and send `UpdateProviders`.
    reload_tx: Option<tokio::sync::mpsc::Sender<sb_core::runtime::supervisor::ReloadMsg>>,
}

impl ProviderManager {
    /// Create a new provider manager with an injected fetch function.
    pub fn new(fetch_fn: FetchFn) -> Self {
        Self {
            proxy_providers: Arc::new(RwLock::new(HashMap::new())),
            rule_providers: Arc::new(RwLock::new(HashMap::new())),
            fetch_fn,
            outbound_registry: None,
            probe_target: sb_core::outbound::RouteTarget::direct(),
            probe_endpoint: sb_core::outbound::Endpoint::Domain(
                "www.gstatic.com".into(),
                443,
            ),
            tick_interval: Duration::from_secs(60),
            bg_task_handle: std::sync::Mutex::new(None),
            reload_tx: None,
        }
    }

    /// Set the outbound registry for health-check TCP probes.
    #[must_use]
    pub fn with_outbound_registry(
        mut self,
        registry: Arc<sb_core::outbound::OutboundRegistryHandle>,
    ) -> Self {
        self.outbound_registry = Some(registry);
        self
    }

    /// Set the reload channel for provider hot-reload.
    /// When set, successful provider fetches will parse the content and
    /// send `ReloadMsg::UpdateProviders` to the Supervisor.
    #[must_use]
    pub fn with_reload_channel(
        mut self,
        tx: tokio::sync::mpsc::Sender<sb_core::runtime::supervisor::ReloadMsg>,
    ) -> Self {
        self.reload_tx = Some(tx);
        self
    }

    /// Override the background tick interval (useful for tests).
    #[must_use]
    pub fn with_tick_interval(mut self, interval: Duration) -> Self {
        self.tick_interval = interval;
        self
    }

    /// Add a proxy provider.
    /// 添加代理提供者。
    pub async fn add_proxy_provider(&self, provider: Provider) -> ApiResult<()> {
        let mut providers = self.proxy_providers.write().await;
        providers.insert(provider.name.clone(), provider);
        Ok(())
    }

    /// Add a rule provider.
    /// 添加规则提供者。
    pub async fn add_rule_provider(&self, provider: Provider) -> ApiResult<()> {
        let mut providers = self.rule_providers.write().await;
        providers.insert(provider.name.clone(), provider);
        Ok(())
    }

    /// Get all proxy providers.
    /// 获取所有代理提供者。
    pub async fn get_proxy_providers(&self) -> ApiResult<HashMap<String, Provider>> {
        let providers = self.proxy_providers.read().await;
        Ok(providers.clone())
    }

    /// Get all rule providers.
    /// 获取所有规则提供者。
    pub async fn get_rule_providers(&self) -> ApiResult<HashMap<String, Provider>> {
        let providers = self.rule_providers.read().await;
        Ok(providers.clone())
    }

    /// Get proxy provider by name.
    /// 按名称获取代理提供者。
    pub async fn get_proxy_provider(&self, name: &str) -> ApiResult<Option<Provider>> {
        let providers = self.proxy_providers.read().await;
        Ok(providers.get(name).cloned())
    }

    /// Get rule provider by name.
    /// 按名称获取规则提供者。
    pub async fn get_rule_provider(&self, name: &str) -> ApiResult<Option<Provider>> {
        let providers = self.rule_providers.read().await;
        Ok(providers.get(name).cloned())
    }

    /// Update provider (fetch new content from its URL).
    /// If the `provider-reload` feature is enabled and a reload channel is set,
    /// successful fetches with changed content will trigger a hot-reload.
    pub async fn update_provider(&self, name: &str, is_proxy_provider: bool) -> ApiResult<bool> {
        let providers = if is_proxy_provider {
            &self.proxy_providers
        } else {
            &self.rule_providers
        };

        // Extract URL and old content under read lock
        let (url, old_content) = {
            let lock = providers.read().await;
            match lock.get(name) {
                Some(p) => (p.url.clone(), p.content.clone()),
                None => return Ok(false),
            }
        };

        if let Some(url) = url {
            match (self.fetch_fn)(&url).await {
                Ok(content) => {
                    let content_changed = old_content != content;
                    let mut lock = providers.write().await;
                    if let Some(p) = lock.get_mut(name) {
                        p.content = content.clone();
                        p.mark_updated();
                        p.healthy = true;
                    }
                    drop(lock);

                    // Trigger hot-reload if content changed
                    if content_changed {
                        if let Some(ref tx) = self.reload_tx {
                            Self::try_send_provider_reload(tx, name, &content, is_proxy_provider).await;
                        }
                    }
                }
                Err(e) => {
                    log::warn!("Failed to fetch provider '{}' from {}: {}", name, url, e);
                    let mut lock = providers.write().await;
                    if let Some(p) = lock.get_mut(name) {
                        p.healthy = false;
                        p.mark_updated();
                    }
                }
            }
        } else {
            // File-based provider — no URL to fetch, just stamp updated
            let mut lock = providers.write().await;
            if let Some(p) = lock.get_mut(name) {
                p.mark_updated();
            }
        }

        Ok(true)
    }

    /// Health check provider via outbound TCP probe.
    pub async fn health_check_provider(
        &self,
        name: &str,
        is_proxy_provider: bool,
    ) -> ApiResult<bool> {
        let providers = if is_proxy_provider {
            &self.proxy_providers
        } else {
            &self.rule_providers
        };

        // Check the provider exists
        {
            let lock = providers.read().await;
            if !lock.contains_key(name) {
                return Ok(false);
            }
        }

        let healthy = if let Some(ref registry) = self.outbound_registry {
            let ep = self.probe_endpoint.clone();
            let target = self.probe_target.clone();
            match tokio::time::timeout(
                Duration::from_secs(5),
                registry.connect_tcp(&target, ep),
            )
            .await
            {
                Ok(Ok(_stream)) => true,
                Ok(Err(e)) => {
                    log::warn!("Health check for '{}' failed: {}", name, e);
                    false
                }
                Err(_) => {
                    log::warn!("Health check for '{}' timed out", name);
                    false
                }
            }
        } else {
            // No registry — graceful degradation, assume healthy
            true
        };

        {
            let mut lock = providers.write().await;
            if let Some(p) = lock.get_mut(name) {
                p.healthy = healthy;
            }
        }

        Ok(healthy)
    }

    /// Start the background update loop. Spawns a tokio task that sweeps
    /// all providers on `self.tick_interval` and fetches stale ones.
    pub fn start_background_updates(
        self: &Arc<Self>,
        mut shutdown_rx: watch::Receiver<bool>,
    ) {
        let weak = Arc::downgrade(self);
        let interval = self.tick_interval;

        let handle = tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = tokio::time::sleep(interval) => {}
                    result = shutdown_rx.changed() => {
                        match result {
                            Ok(()) if *shutdown_rx.borrow() => {
                                log::info!("Provider background updater shutting down");
                                return;
                            }
                            Err(_) => {
                                log::info!("Provider shutdown channel closed");
                                return;
                            }
                            _ => continue,
                        }
                    }
                }

                let Some(mgr) = weak.upgrade() else {
                    log::debug!("ProviderManager dropped, stopping background updates");
                    return;
                };

                mgr.tick_updates().await;
            }
        });

        if let Ok(mut guard) = self.bg_task_handle.lock() {
            *guard = Some(handle);
        }
    }

    /// Single sweep: collect stale providers, fetch their URLs, update content.
    async fn tick_updates(&self) {
        // Collect stale proxy providers
        let stale_proxy: Vec<(String, String)> = {
            let lock = self.proxy_providers.read().await;
            lock.iter()
                .filter(|(_, p)| p.needs_update() && p.url.is_some())
                .map(|(name, p)| (name.clone(), p.url.clone().unwrap_or_default()))
                .collect()
        };

        // Collect stale rule providers
        let stale_rule: Vec<(String, String)> = {
            let lock = self.rule_providers.read().await;
            lock.iter()
                .filter(|(_, p)| p.needs_update() && p.url.is_some())
                .map(|(name, p)| (name.clone(), p.url.clone().unwrap_or_default()))
                .collect()
        };

        let reload_tx = self.reload_tx.as_ref();

        for (name, url) in &stale_proxy {
            Self::fetch_and_update(&self.fetch_fn, &self.proxy_providers, name, url, true, reload_tx).await;
        }
        for (name, url) in &stale_rule {
            Self::fetch_and_update(&self.fetch_fn, &self.rule_providers, name, url, false, reload_tx).await;
        }
    }

    /// Fetch a URL and update the named provider in the given map.
    /// When `reload_tx` is available and `provider-reload` feature is enabled,
    /// parses the fetched content and sends a hot-reload message to the Supervisor.
    async fn fetch_and_update(
        fetch_fn: &FetchFn,
        providers: &Arc<RwLock<HashMap<String, Provider>>>,
        name: &str,
        url: &str,
        is_proxy: bool,
        reload_tx: Option<&tokio::sync::mpsc::Sender<sb_core::runtime::supervisor::ReloadMsg>>,
    ) {
        match fetch_fn(url).await {
            Ok(content) => {
                let mut lock = providers.write().await;
                if let Some(p) = lock.get_mut(name) {
                    let content_changed = p.content != content;
                    log::info!("Background update: fetched provider '{}'", name);
                    p.content = content.clone();
                    p.mark_updated();
                    p.healthy = true;

                    // If content changed and reload channel available, parse and send update
                    if content_changed {
                        if let Some(tx) = reload_tx {
                            Self::try_send_provider_reload(tx, name, &content, is_proxy).await;
                        }
                    }
                }
            }
            Err(e) => {
                log::warn!("Background update: failed to fetch '{}': {}", name, e);
                let mut lock = providers.write().await;
                if let Some(p) = lock.get_mut(name) {
                    p.healthy = false;
                    p.mark_updated();
                }
            }
        }
    }

    /// Parse fetched provider content and send a `ReloadMsg::UpdateProviders`
    /// to the Supervisor. Requires the `provider-reload` feature.
    #[cfg(feature = "provider-reload")]
    async fn try_send_provider_reload(
        tx: &tokio::sync::mpsc::Sender<sb_core::runtime::supervisor::ReloadMsg>,
        name: &str,
        content: &str,
        is_proxy: bool,
    ) {
        use sb_core::runtime::supervisor::ReloadMsg;

        let (outbounds, rules) = if is_proxy {
            match sb_subscribe::provider_parse::parse_proxy_content(content) {
                Ok(obs) => {
                    log::info!(
                        "Provider '{}': parsed {} outbound(s) for hot-reload",
                        name,
                        obs.len()
                    );
                    (obs, Vec::new())
                }
                Err(e) => {
                    log::warn!(
                        "Provider '{}': failed to parse proxy content: {}",
                        name,
                        e
                    );
                    return;
                }
            }
        } else {
            match sb_subscribe::provider_parse::parse_rule_content(content) {
                Ok(rules) => {
                    log::info!(
                        "Provider '{}': parsed {} rule(s) for hot-reload",
                        name,
                        rules.len()
                    );
                    (Vec::new(), rules)
                }
                Err(e) => {
                    log::warn!(
                        "Provider '{}': failed to parse rule content: {}",
                        name,
                        e
                    );
                    return;
                }
            }
        };

        if outbounds.is_empty() && rules.is_empty() {
            return;
        }

        let msg = ReloadMsg::UpdateProviders {
            outbounds,
            rules,
            provider_name: name.to_string(),
        };

        if let Err(e) = tx.send(msg).await {
            log::error!(
                "Provider '{}': failed to send reload message: {}",
                name,
                e
            );
        }
    }

    /// No-op when `provider-reload` feature is not enabled.
    #[cfg(not(feature = "provider-reload"))]
    async fn try_send_provider_reload(
        _tx: &tokio::sync::mpsc::Sender<sb_core::runtime::supervisor::ReloadMsg>,
        _name: &str,
        _content: &str,
        _is_proxy: bool,
    ) {
        // Feature not enabled — skip parsing and reload
    }
}

impl std::fmt::Debug for ProviderManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProviderManager")
            .field("tick_interval", &self.tick_interval)
            .field("has_reload_tx", &self.reload_tx.is_some())
            .finish_non_exhaustive()
    }
}

impl Default for ProviderManager {
    fn default() -> Self {
        #[cfg(feature = "provider-reload")]
        {
            return Self::new(production_fetch());
        }

        #[cfg(not(feature = "provider-reload"))]
        let noop_fetch: FetchFn = Arc::new(|_url| {
            Box::pin(async { Err("no fetch function configured".to_string()) })
        });
        #[cfg(not(feature = "provider-reload"))]
        {
            Self::new(noop_fetch)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    fn mock_fetch(body: &'static str) -> FetchFn {
        Arc::new(move |_url| Box::pin(async move { Ok(body.to_string()) }))
    }

    fn counting_fetch(body: &'static str) -> (FetchFn, Arc<AtomicUsize>) {
        let count = Arc::new(AtomicUsize::new(0));
        let c = count.clone();
        let f: FetchFn = Arc::new(move |_url| {
            c.fetch_add(1, Ordering::SeqCst);
            let b = body;
            Box::pin(async move { Ok(b.to_string()) })
        });
        (f, count)
    }

    fn failing_fetch() -> FetchFn {
        Arc::new(|_url| Box::pin(async { Err("network error".to_string()) }))
    }

    fn make_provider(name: &str, url: Option<&str>) -> Provider {
        let mut p = Provider::new(name.to_string(), "proxy".to_string());
        p.url = url.map(|s| s.to_string());
        p
    }

    // ── T4 tests ──

    #[tokio::test]
    async fn test_on_demand_update_fetches_url() {
        let mgr = ProviderManager::new(mock_fetch("proxy-list-v2"));
        let mut p = make_provider("sub1", Some("https://example.com/sub"));
        p.content = "old-content".into();
        mgr.add_proxy_provider(p).await.unwrap();

        let found = mgr.update_provider("sub1", true).await.unwrap();
        assert!(found);

        let updated = mgr.get_proxy_provider("sub1").await.unwrap().unwrap();
        assert_eq!(updated.content, "proxy-list-v2");
        assert!(updated.healthy);
        assert!(updated.last_update.is_some());
    }

    #[tokio::test]
    async fn test_on_demand_update_nonexistent_returns_false() {
        let mgr = ProviderManager::default();
        let found = mgr.update_provider("nope", true).await.unwrap();
        assert!(!found);
    }

    #[tokio::test]
    async fn test_on_demand_update_marks_unhealthy_on_failure() {
        let mgr = ProviderManager::new(failing_fetch());
        mgr.add_proxy_provider(make_provider("sub1", Some("https://example.com/sub")))
            .await
            .unwrap();

        let found = mgr.update_provider("sub1", true).await.unwrap();
        assert!(found);

        let p = mgr.get_proxy_provider("sub1").await.unwrap().unwrap();
        assert!(!p.healthy);
    }

    #[tokio::test]
    async fn test_on_demand_update_no_url_just_stamps() {
        let mgr = ProviderManager::default();
        mgr.add_proxy_provider(make_provider("local", None))
            .await
            .unwrap();

        let found = mgr.update_provider("local", true).await.unwrap();
        assert!(found);

        let p = mgr.get_proxy_provider("local").await.unwrap().unwrap();
        assert!(p.last_update.is_some());
    }

    #[tokio::test]
    async fn test_background_update_fetches_stale_providers() {
        let (fetch, count) = counting_fetch("fresh-content");
        let mgr = Arc::new(
            ProviderManager::new(fetch).with_tick_interval(Duration::from_millis(50)),
        );

        // Provider with no last_update → needs_update() == true
        mgr.add_proxy_provider(make_provider("sub1", Some("https://example.com")))
            .await
            .unwrap();

        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        mgr.start_background_updates(shutdown_rx);

        // Wait for at least one tick
        tokio::time::sleep(Duration::from_millis(120)).await;
        let _ = shutdown_tx.send(true);

        assert!(count.load(Ordering::SeqCst) >= 1, "fetch should have been called");
        let p = mgr.get_proxy_provider("sub1").await.unwrap().unwrap();
        assert_eq!(p.content, "fresh-content");
        assert!(p.healthy);
    }

    #[tokio::test]
    async fn test_background_update_skips_non_stale_providers() {
        let (fetch, count) = counting_fetch("should-not-appear");
        let mgr = Arc::new(
            ProviderManager::new(fetch).with_tick_interval(Duration::from_millis(50)),
        );

        // Provider that was just updated → needs_update() == false
        let mut p = make_provider("sub1", Some("https://example.com"));
        p.mark_updated();
        p.update_interval = 3600; // 1 hour
        mgr.add_proxy_provider(p).await.unwrap();

        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        mgr.start_background_updates(shutdown_rx);

        tokio::time::sleep(Duration::from_millis(120)).await;
        let _ = shutdown_tx.send(true);

        assert_eq!(count.load(Ordering::SeqCst), 0, "fetch should NOT have been called");
    }

    #[tokio::test]
    async fn test_background_update_marks_unhealthy_on_fetch_failure() {
        let mgr = Arc::new(
            ProviderManager::new(failing_fetch()).with_tick_interval(Duration::from_millis(50)),
        );

        mgr.add_proxy_provider(make_provider("sub1", Some("https://example.com")))
            .await
            .unwrap();

        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        mgr.start_background_updates(shutdown_rx);

        tokio::time::sleep(Duration::from_millis(120)).await;
        let _ = shutdown_tx.send(true);

        let p = mgr.get_proxy_provider("sub1").await.unwrap().unwrap();
        assert!(!p.healthy);
    }

    // ── T5 tests ──

    #[tokio::test]
    async fn test_health_check_without_registry_returns_healthy() {
        let mgr = ProviderManager::default();
        mgr.add_proxy_provider(make_provider("sub1", Some("https://example.com")))
            .await
            .unwrap();

        let healthy = mgr.health_check_provider("sub1", true).await.unwrap();
        assert!(healthy, "without registry, should gracefully return healthy");
    }

    #[tokio::test]
    async fn test_health_check_nonexistent_returns_false() {
        let mgr = ProviderManager::default();
        let result = mgr.health_check_provider("nope", true).await.unwrap();
        assert!(!result);
    }

    #[tokio::test]
    async fn test_health_check_with_block_outbound_marks_unhealthy() {
        use sb_core::outbound::{
            Endpoint, OutboundImpl, OutboundRegistry, OutboundRegistryHandle, RouteTarget,
        };

        // Register a "block-probe" outbound that always returns PermissionDenied
        let mut reg = OutboundRegistry::default();
        reg.insert("block-probe".into(), OutboundImpl::Block);
        let handle = Arc::new(OutboundRegistryHandle::new(reg));

        let noop_fetch: FetchFn = Arc::new(|_| {
            Box::pin(async { Err("unused".into()) })
        });
        let mut mgr = ProviderManager::new(noop_fetch)
            .with_outbound_registry(handle);
        // Point the probe at the Named "block-probe" outbound
        mgr.probe_target = RouteTarget::Named("block-probe".into());
        mgr.probe_endpoint = Endpoint::Domain("www.gstatic.com".into(), 443);

        mgr.add_proxy_provider(make_provider("sub1", Some("https://example.com")))
            .await
            .unwrap();

        let healthy = mgr.health_check_provider("sub1", true).await.unwrap();
        assert!(!healthy, "Block outbound should make health check fail");

        // Verify the provider was marked unhealthy
        let p = mgr.get_proxy_provider("sub1").await.unwrap().unwrap();
        assert!(!p.healthy);
    }
}
