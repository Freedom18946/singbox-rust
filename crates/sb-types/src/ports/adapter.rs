//! Adapter-facing runtime contracts.
//!
//! These ports model the stable surface that protocol adapters and control
//! services consume. Concrete implementations live in `sb-core` and
//! `sb-adapters`; this crate keeps only lightweight shared shapes.

use crate::errors::CoreError;
use crate::ports::{BoxFuture, BoxedStream, DnsCacheStats};
use crate::session::{InboundTag, TargetAddr};
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

/// Network kind for route/adapter data-plane calls.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NetworkKind {
    Tcp,
    Udp,
}

/// Metadata supplied by inbounds/endpoints before router dispatch.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RouteMetadata {
    pub inbound: Option<InboundTag>,
    pub inbound_type: Option<String>,
    pub network: Option<NetworkKind>,
    pub source: Option<TargetAddr>,
    pub destination: Option<TargetAddr>,
    pub original_destination: Option<TargetAddr>,
    pub user: Option<String>,
    pub protocol: Option<String>,
    pub process_name: Option<String>,
    pub process_path: Option<String>,
}

/// Out-of-band packet metadata.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PacketMetadata {
    pub source: Option<SocketAddr>,
    pub destination: Option<SocketAddr>,
    pub oob: Vec<u8>,
}

/// Close hook used by routed connection wrappers.
pub type CloseHook = Box<dyn FnOnce() + Send + 'static>;

/// Handles routed TCP/stream connections.
pub trait StreamHandlerPort: Send + Sync + 'static {
    fn handle_stream(
        &self,
        stream: BoxedStream,
        metadata: RouteMetadata,
        on_close: Option<CloseHook>,
    ) -> BoxFuture<'_, Result<(), CoreError>>;
}

/// Handles routed UDP packet connections or individual datagrams.
pub trait PacketHandlerPort: Send + Sync + 'static {
    fn handle_packet(
        &self,
        packet: Vec<u8>,
        metadata: RouteMetadata,
        packet_metadata: PacketMetadata,
    ) -> BoxFuture<'_, Result<Vec<u8>, CoreError>>;
}

/// Router pre-match result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PreMatchResult {
    Continue,
    Bypass(TargetAddr),
    Reject(String),
}

/// Metadata advertised by a rule set.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RuleSetMetadata {
    pub contains_process_rule: bool,
    pub contains_wifi_rule: bool,
    pub contains_ip_cidr_rule: bool,
}

/// Token returned by rule-set update registration.
pub trait RuleSetUpdateToken: Send + Sync + std::fmt::Debug + 'static {
    fn unregister(&self);
}

/// Callback invoked when a rule set changes.
pub type RuleSetUpdateCallback = Arc<dyn Fn(Arc<dyn RuleSetPort>) + Send + Sync + 'static>;

/// Stable rule-set consumer contract.
pub trait RuleSetPort: Send + Sync + std::fmt::Debug + 'static {
    fn name(&self) -> &str;
    fn metadata(&self) -> RuleSetMetadata;
    fn contains_ip(&self, _ip: IpAddr) -> bool {
        false
    }
    fn register_callback(
        &self,
        _callback: RuleSetUpdateCallback,
    ) -> Option<Arc<dyn RuleSetUpdateToken>> {
        None
    }
}

/// Router contract consumed by endpoint/inbound adapters.
pub trait RouterPort: Send + Sync + std::fmt::Debug + 'static {
    fn pre_match(
        &self,
        metadata: RouteMetadata,
        timeout: Duration,
        support_bypass: bool,
    ) -> BoxFuture<'_, Result<PreMatchResult, CoreError>>;

    fn route_stream(
        &self,
        stream: BoxedStream,
        metadata: RouteMetadata,
        on_close: Option<CloseHook>,
    ) -> BoxFuture<'_, Result<(), CoreError>>;

    fn route_packet(
        &self,
        packet: Vec<u8>,
        metadata: RouteMetadata,
        packet_metadata: PacketMetadata,
    ) -> BoxFuture<'_, Result<Vec<u8>, CoreError>>;

    fn rule_set(&self, tag: &str) -> Option<Arc<dyn RuleSetPort>>;
    fn append_tracker(&self, tracker: Arc<dyn ConnectionTrackerPort>);
    fn reset_network(&self);
}

/// Router/control-plane connection tracker hook.
pub trait ConnectionTrackerPort: Send + Sync + std::fmt::Debug + 'static {
    fn routed_stream(&self, metadata: &RouteMetadata, rule: Option<&str>, outbound: Option<&str>);
    fn routed_packet(&self, metadata: &RouteMetadata, rule: Option<&str>, outbound: Option<&str>);
}

/// DNS query options shared across DNS router/client consumers.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DnsQueryOptions {
    pub transport: Option<String>,
    pub strategy: Option<String>,
    pub lookup_strategy: Option<String>,
    pub disable_cache: bool,
    pub rewrite_ttl: Option<u32>,
    pub client_subnet: Option<String>,
}

/// DNS router contract.
pub trait DnsRouterPort: Send + Sync + std::fmt::Debug + 'static {
    fn exchange(
        &self,
        message: Vec<u8>,
        options: DnsQueryOptions,
        metadata: RouteMetadata,
    ) -> BoxFuture<'_, Result<Vec<u8>, CoreError>>;

    fn lookup(
        &self,
        domain: &str,
        options: DnsQueryOptions,
        metadata: RouteMetadata,
    ) -> BoxFuture<'_, Result<Vec<IpAddr>, CoreError>>;

    fn clear_cache(&self);
    fn cache_stats(&self) -> DnsCacheStats;
    fn lookup_reverse_mapping(&self, ip: IpAddr) -> Option<String>;
    fn reset_network(&self);
}

/// FakeIP allocation metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct FakeIpMetadata {
    pub inet4_current_u32: u32,
    pub inet6_current_u128: u128,
}

/// FakeIP persistence contract.
pub trait FakeIpStoragePort: Send + Sync + std::fmt::Debug + 'static {
    fn load_metadata(&self) -> Option<FakeIpMetadata>;
    fn save_metadata(&self, metadata: FakeIpMetadata);
    fn save_mapping(&self, domain: &str, ip: IpAddr);
    fn load_domain(&self, domain: &str, is_ipv6: bool) -> Option<IpAddr>;
    fn load_address(&self, ip: IpAddr) -> Option<String>;
    fn reset(&self) -> Result<(), CoreError>;
}

/// Resolver DNS rejection cache contract.
pub trait RdrcStorePort: Send + Sync + std::fmt::Debug + 'static {
    fn load_rdrc(&self, transport_name: &str, q_name: &str, q_type: u16) -> bool;
    fn save_rdrc(&self, transport_name: &str, q_name: &str, q_type: u16) -> Result<(), CoreError>;
}

/// Persisted rule-set payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SavedRuleSetBinary {
    pub content: Vec<u8>,
    pub last_updated: SystemTime,
    pub last_etag: String,
}

/// CacheFile contract used by Clash, selector/urltest, DNS, FakeIP, and rule sets.
pub trait CacheFilePort:
    FakeIpStoragePort + RdrcStorePort + Send + Sync + std::fmt::Debug + 'static
{
    fn store_fakeip(&self) -> bool;
    fn store_rdrc(&self) -> bool;
    fn load_mode(&self) -> Option<String>;
    fn store_mode(&self, mode: &str) -> Result<(), CoreError>;
    fn load_selected(&self, group: &str) -> Option<String>;
    fn store_selected(&self, group: &str, selected: &str) -> Result<(), CoreError>;
    fn load_group_expand(&self, group: &str) -> Option<bool>;
    fn store_group_expand(&self, group: &str, expand: bool) -> Result<(), CoreError>;
    fn load_rule_set(&self, tag: &str) -> Option<SavedRuleSetBinary>;
    fn save_rule_set(&self, tag: &str, set: SavedRuleSetBinary) -> Result<(), CoreError>;
}

/// URLTest history entry.
#[derive(Debug, Clone)]
pub struct UrlTestHistory {
    pub time: SystemTime,
    pub delay: u16,
}

/// URLTest history storage contract.
pub trait UrlTestHistoryPort: Send + Sync + std::fmt::Debug + 'static {
    fn load_history(&self, tag: &str) -> Option<UrlTestHistory>;
    fn store_history(&self, tag: &str, history: UrlTestHistory);
    fn delete_history(&self, tag: &str);
}

/// Clash operating mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ClashMode {
    Global,
    Rule,
    Direct,
}

/// Clash server adapter contract.
pub trait ClashServerPort: ConnectionTrackerPort + Send + Sync + std::fmt::Debug + 'static {
    fn mode(&self) -> String;
    fn mode_list(&self) -> Vec<String>;
    fn set_mode(&self, mode: &str) -> Result<(), CoreError>;
    fn history_storage(&self) -> Option<Arc<dyn UrlTestHistoryPort>>;
}

/// V2Ray stats service contract.
pub trait V2RayStatsPort: ConnectionTrackerPort + Send + Sync + std::fmt::Debug + 'static {
    fn query(&self, pattern: &str, reset: bool) -> Vec<(String, i64)>;
}

/// V2Ray server contract.
pub trait ManagedApiServerPort: Send + Sync + std::fmt::Debug + 'static {
    fn stats_service(&self) -> Option<Arc<dyn V2RayStatsPort>>;
}

/// Time service contract.
pub trait TimePort: Send + Sync + std::fmt::Debug + 'static {
    fn now(&self) -> SystemTime;
}

/// Certificate store contract.
pub trait CertificateStorePort: Send + Sync + std::fmt::Debug + 'static {
    fn root_pool(&self) -> Option<Vec<String>>;
}

/// Bundle of adapter-visible runtime services.
#[derive(Clone, Default)]
pub struct AdapterServicePorts {
    pub router: Option<Arc<dyn RouterPort>>,
    pub dns_router: Option<Arc<dyn DnsRouterPort>>,
    pub cache_file: Option<Arc<dyn CacheFilePort>>,
    pub urltest_history: Option<Arc<dyn UrlTestHistoryPort>>,
    pub clash_server: Option<Arc<dyn ClashServerPort>>,
    pub v2ray_server: Option<Arc<dyn ManagedApiServerPort>>,
    pub time_service: Option<Arc<dyn TimePort>>,
    pub certificate_store: Option<Arc<dyn CertificateStorePort>>,
}

impl std::fmt::Debug for AdapterServicePorts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AdapterServicePorts")
            .field("router", &self.router.is_some())
            .field("dns_router", &self.dns_router.is_some())
            .field("cache_file", &self.cache_file.is_some())
            .field("urltest_history", &self.urltest_history.is_some())
            .field("clash_server", &self.clash_server.is_some())
            .field("v2ray_server", &self.v2ray_server.is_some())
            .field("time_service", &self.time_service.is_some())
            .field("certificate_store", &self.certificate_store.is_some())
            .finish()
    }
}
