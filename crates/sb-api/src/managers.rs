//! API layer managers for connection tracking, DNS, and other services

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
#[derive(Debug, Clone)]
pub struct Connection {
    /// Unique connection identifier
    pub id: String,
    /// Source address (client)
    pub source: SocketAddr,
    /// Destination address (target)
    pub destination: String,
    /// Selected outbound proxy
    pub proxy: String,
    /// Connection start time
    pub start_time: Instant,
    /// Bytes uploaded
    pub upload: Arc<AtomicU64>,
    /// Bytes downloaded
    pub download: Arc<AtomicU64>,
    /// Connection type (TCP/UDP)
    pub network: String,
    /// Rule that matched this connection
    pub rule: String,
    /// Chain of proxies used
    pub chains: Vec<String>,
}

impl Connection {
    /// Create a new connection
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

    /// Update upload bytes
    pub fn add_upload(&self, bytes: u64) {
        self.upload.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Update download bytes
    pub fn add_download(&self, bytes: u64) {
        self.download.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Get current upload bytes
    pub fn get_upload(&self) -> u64 {
        self.upload.load(Ordering::Relaxed)
    }

    /// Get current download bytes
    pub fn get_download(&self) -> u64 {
        self.download.load(Ordering::Relaxed)
    }

    /// Get connection duration
    pub fn duration(&self) -> Duration {
        self.start_time.elapsed()
    }
}

/// Manager for tracking active connections
#[derive(Debug)]
pub struct ConnectionManager {
    /// Active connections by ID
    connections: Arc<RwLock<HashMap<String, Connection>>>,
    /// Global traffic statistics
    global_stats: Arc<TrafficStats>,
}

impl ConnectionManager {
    /// Create a new connection manager
    pub fn new() -> Self {
        Self {
            connections: Arc::new(RwLock::new(HashMap::new())),
            global_stats: Arc::new(TrafficStats::default()),
        }
    }

    /// Add a new connection
    pub async fn add_connection(&self, connection: Connection) -> ApiResult<()> {
        let mut connections = self.connections.write().await;
        connections.insert(connection.id.clone(), connection);
        Ok(())
    }

    /// Remove a connection by ID
    pub async fn remove_connection(&self, id: &str) -> ApiResult<bool> {
        let mut connections = self.connections.write().await;
        Ok(connections.remove(id).is_some())
    }

    /// Get all active connections
    pub async fn get_connections(&self) -> ApiResult<Vec<Connection>> {
        let connections = self.connections.read().await;
        Ok(connections.values().cloned().collect())
    }

    /// Get connection by ID
    pub async fn get_connection(&self, id: &str) -> ApiResult<Option<Connection>> {
        let connections = self.connections.read().await;
        Ok(connections.get(id).cloned())
    }

    /// Close all connections
    pub async fn close_all_connections(&self) -> ApiResult<usize> {
        let mut connections = self.connections.write().await;
        let count = connections.len();
        connections.clear();
        Ok(count)
    }

    /// Get connection count
    pub async fn get_connection_count(&self) -> usize {
        let connections = self.connections.read().await;
        connections.len()
    }

    /// Update global traffic statistics
    pub fn update_global_traffic(&self, upload: u64, download: u64) {
        self.global_stats.add_traffic(upload, download);
    }

    /// Get global traffic statistics
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
#[derive(Debug, Clone)]
pub struct DnsCacheEntry {
    /// Resolved IP addresses
    pub addresses: Vec<SocketAddr>,
    /// Cache entry expiration time
    pub expires_at: Instant,
    /// Query type (A, AAAA, etc.)
    pub query_type: String,
}

/// DNS resolver with caching capabilities
#[derive(Debug)]
pub struct DnsResolver {
    /// DNS cache entries
    cache: Arc<RwLock<HashMap<String, DnsCacheEntry>>>,
    /// Fake IP mappings (for Clash compatibility)
    fake_ip_mappings: Arc<RwLock<HashMap<String, String>>>,
    /// DNS server configuration
    dns_servers: Vec<SocketAddr>,
}

impl DnsResolver {
    /// Create a new DNS resolver
    pub fn new() -> Self {
        Self {
            cache: Arc::new(RwLock::new(HashMap::new())),
            fake_ip_mappings: Arc::new(RwLock::new(HashMap::new())),
            dns_servers: vec![
                "8.8.8.8:53".parse().expect("Valid DNS server"),
                "1.1.1.1:53".parse().expect("Valid DNS server"),
            ],
        }
    }

    /// Flush DNS cache
    pub async fn flush_dns_cache(&self) -> ApiResult<()> {
        let mut cache = self.cache.write().await;
        cache.clear();
        log::info!("DNS cache flushed, {} entries cleared", cache.len());
        Ok(())
    }

    /// Flush fake IP cache
    pub async fn flush_fake_ip_cache(&self) -> ApiResult<()> {
        let mut fake_ips = self.fake_ip_mappings.write().await;
        let count = fake_ips.len();
        fake_ips.clear();
        log::info!("Fake IP cache flushed, {} entries cleared", count);
        Ok(())
    }

    /// Get cache statistics
    pub async fn get_cache_stats(&self) -> (usize, usize) {
        let cache = self.cache.read().await;
        let fake_ips = self.fake_ip_mappings.read().await;
        (cache.len(), fake_ips.len())
    }

    /// Add fake IP mapping
    pub async fn add_fake_ip_mapping(&self, domain: String, fake_ip: String) -> ApiResult<()> {
        let mut fake_ips = self.fake_ip_mappings.write().await;
        fake_ips.insert(domain, fake_ip);
        Ok(())
    }

    /// Resolve fake IP to domain
    pub async fn resolve_fake_ip(&self, fake_ip: &str) -> Option<String> {
        let fake_ips = self.fake_ip_mappings.read().await;
        fake_ips
            .iter()
            .find(|(_, ip)| ip.as_str() == fake_ip)
            .map(|(domain, _)| domain.clone())
    }
}

impl Default for DnsResolver {
    fn default() -> Self {
        Self::new()
    }
}

/// Provider for proxy/rule management
#[derive(Debug, Clone)]
pub struct Provider {
    /// Provider name
    pub name: String,
    /// Provider type (proxy/rule)
    pub provider_type: String,
    /// Provider URL for remote updates
    pub url: Option<String>,
    /// Update interval in seconds
    pub update_interval: u64,
    /// Last update time
    pub last_update: Option<Instant>,
    /// Provider health status
    pub healthy: bool,
    /// Provider content (proxies or rules)
    pub content: String,
}

impl Provider {
    /// Create a new provider
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

    /// Check if provider needs update
    pub fn needs_update(&self) -> bool {
        if let Some(last_update) = self.last_update {
            last_update.elapsed().as_secs() > self.update_interval
        } else {
            true
        }
    }

    /// Mark provider as updated
    pub fn mark_updated(&mut self) {
        self.last_update = Some(Instant::now());
    }

    /// Perform health check
    pub async fn health_check(&mut self) -> ApiResult<bool> {
        // Simple health check - in real implementation, this would
        // ping the provider URL or validate content
        self.healthy = true;
        Ok(self.healthy)
    }
}

/// Manager for proxy and rule providers
#[derive(Debug)]
pub struct ProviderManager {
    /// Proxy providers
    proxy_providers: Arc<RwLock<HashMap<String, Provider>>>,
    /// Rule providers
    rule_providers: Arc<RwLock<HashMap<String, Provider>>>,
}

impl ProviderManager {
    /// Create a new provider manager
    pub fn new() -> Self {
        Self {
            proxy_providers: Arc::new(RwLock::new(HashMap::new())),
            rule_providers: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Add a proxy provider
    pub async fn add_proxy_provider(&self, provider: Provider) -> ApiResult<()> {
        let mut providers = self.proxy_providers.write().await;
        providers.insert(provider.name.clone(), provider);
        Ok(())
    }

    /// Add a rule provider
    pub async fn add_rule_provider(&self, provider: Provider) -> ApiResult<()> {
        let mut providers = self.rule_providers.write().await;
        providers.insert(provider.name.clone(), provider);
        Ok(())
    }

    /// Get all proxy providers
    pub async fn get_proxy_providers(&self) -> ApiResult<HashMap<String, Provider>> {
        let providers = self.proxy_providers.read().await;
        Ok(providers.clone())
    }

    /// Get all rule providers
    pub async fn get_rule_providers(&self) -> ApiResult<HashMap<String, Provider>> {
        let providers = self.rule_providers.read().await;
        Ok(providers.clone())
    }

    /// Get proxy provider by name
    pub async fn get_proxy_provider(&self, name: &str) -> ApiResult<Option<Provider>> {
        let providers = self.proxy_providers.read().await;
        Ok(providers.get(name).cloned())
    }

    /// Get rule provider by name
    pub async fn get_rule_provider(&self, name: &str) -> ApiResult<Option<Provider>> {
        let providers = self.rule_providers.read().await;
        Ok(providers.get(name).cloned())
    }

    /// Update provider (fetch new content)
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

    /// Health check provider
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
