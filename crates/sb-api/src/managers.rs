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
    net::SocketAddr,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};
use tokio::sync::RwLock;
use uuid::Uuid;

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
        let mut fake_ips = self.fake_ip_mappings.write().await;
        let count = fake_ips.len();
        fake_ips.clear();
        log::info!("Fake IP cache flushed, {} entries cleared", count);
        Ok(())
    }

    /// Get cache statistics.
    /// 获取缓存统计信息。
    pub async fn get_cache_stats(&self) -> (usize, usize) {
        let cache = self.cache.read().await;
        let fake_ips = self.fake_ip_mappings.read().await;
        (cache.len(), fake_ips.len())
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
        let fake_ips = self.fake_ip_mappings.read().await;
        fake_ips
            .iter()
            .find(|(_, ip)| ip.as_str() == fake_ip)
            .map(|(domain, _)| domain.clone())
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
    /// 标记提供者为已更新。
    pub fn mark_updated(&mut self) {
        self.last_update = Some(Instant::now());
    }

    /// Perform health check.
    /// 执行健康检查。
    pub async fn health_check(&mut self) -> ApiResult<bool> {
        // Simple health check - in real implementation, this would
        // ping the provider URL or validate content
        self.healthy = true;
        Ok(self.healthy)
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
#[derive(Debug)]
pub struct ProviderManager {
    /// Proxy providers
    /// 代理提供者
    proxy_providers: Arc<RwLock<HashMap<String, Provider>>>,
    /// Rule providers
    /// 规则提供者
    rule_providers: Arc<RwLock<HashMap<String, Provider>>>,
}

impl ProviderManager {
    /// Create a new provider manager.
    /// 创建新的提供者管理器。
    pub fn new() -> Self {
        Self {
            proxy_providers: Arc::new(RwLock::new(HashMap::new())),
            rule_providers: Arc::new(RwLock::new(HashMap::new())),
        }
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

    /// Update provider (fetch new content).
    /// 更新提供者（获取新内容）。
    pub async fn update_provider(&self, name: &str, is_proxy_provider: bool) -> ApiResult<bool> {
        if is_proxy_provider {
            let mut providers = self.proxy_providers.write().await;
            if let Some(provider) = providers.get_mut(name) {
                provider.mark_updated();
                provider.healthy = true;
                return Ok(true);
            }
        } else {
            let mut providers = self.rule_providers.write().await;
            if let Some(provider) = providers.get_mut(name) {
                provider.mark_updated();
                provider.healthy = true;
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Health check provider.
    /// 健康检查提供者。
    pub async fn health_check_provider(
        &self,
        name: &str,
        is_proxy_provider: bool,
    ) -> ApiResult<bool> {
        if is_proxy_provider {
            let mut providers = self.proxy_providers.write().await;
            if let Some(provider) = providers.get_mut(name) {
                return provider.health_check().await;
            }
        } else {
            let mut providers = self.rule_providers.write().await;
            if let Some(provider) = providers.get_mut(name) {
                return provider.health_check().await;
            }
        }
        Ok(false)
    }
}

impl Default for ProviderManager {
    fn default() -> Self {
        Self::new()
    }
}
