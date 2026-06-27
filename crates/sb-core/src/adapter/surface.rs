//! Adapter-facing service-port bridge.
//!
//! This module converts the existing `sb-core` runtime context into stable
//! `sb-types` ports. It is intentionally additive: concrete runtime ownership
//! stays in the existing managers and services.

use crate::context::{
    CacheFile, CertificateStore, ContextRegistry, TimeService, URLTestHistoryStorage, V2RayServer,
};
use crate::dns::dns_router::DnsRouter;
use crate::services::v2ray_api::StatsManager;
use sb_types::ports::{
    AdapterServicePorts, BoxFuture, CacheFilePort, CertificateStorePort, ClashServerPort,
    CloseHook, ConnectionTrackerPort, DnsCacheStats, DnsQueryOptions, DnsRouterPort,
    FakeIpMetadata as PortFakeIpMetadata, FakeIpStoragePort, PacketMetadata, PreMatchResult,
    RdrcStorePort, RouteMetadata, RouterPort, RuleSetPort, SavedRuleSetBinary, TimePort,
    UrlTestHistory, UrlTestHistoryPort, V2RayServerPort, V2RayStatsPort,
};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

/// Adapter-visible runtime service bundle.
#[derive(Clone, Debug)]
pub struct AdapterServices {
    ports: AdapterServicePorts,
}

impl AdapterServices {
    /// Build an adapter service bundle from the current runtime context registry.
    #[must_use]
    pub fn from_context_registry(context: &ContextRegistry) -> Self {
        Self::from_context_registry_with_dns_router(context, None)
    }

    /// Build an adapter service bundle and include an injected DNS router when available.
    #[must_use]
    pub fn from_context_registry_with_dns_router(
        context: &ContextRegistry,
        dns_router: Option<Arc<dyn DnsRouter>>,
    ) -> Self {
        Self {
            ports: AdapterServicePorts {
                router: Some(Arc::new(UnsupportedRouterPort)),
                dns_router: dns_router
                    .map(|router| Arc::new(DnsRouterPortAdapter::new(router)) as _),
                cache_file: context
                    .cache_file
                    .as_ref()
                    .map(|cache| Arc::new(CacheFilePortAdapter::new(cache.clone())) as _),
                urltest_history: context
                    .urltest_history
                    .as_ref()
                    .map(|history| Arc::new(UrlTestHistoryPortAdapter::new(history.clone())) as _),
                clash_server: Some(Arc::new(GlobalClashPort::new(context.cache_file.clone()))),
                v2ray_server: context
                    .v2ray_server
                    .as_ref()
                    .map(|server| Arc::new(V2RayServerPortAdapter::new(server.clone())) as _),
                time_service: context
                    .time_service
                    .as_ref()
                    .map(|time| Arc::new(TimePortAdapter::new(time.clone())) as _),
                certificate_store: context
                    .certificate_store
                    .as_ref()
                    .map(|store| Arc::new(CertificateStorePortAdapter::new(store.clone())) as _),
            },
        }
    }

    #[must_use]
    pub fn ports(&self) -> &AdapterServicePorts {
        &self.ports
    }

    #[must_use]
    pub fn into_ports(self) -> AdapterServicePorts {
        self.ports
    }
}

#[derive(Debug)]
struct UnsupportedRouterPort;

impl RouterPort for UnsupportedRouterPort {
    fn pre_match(
        &self,
        _metadata: RouteMetadata,
        _timeout: Duration,
        _support_bypass: bool,
    ) -> BoxFuture<'_, Result<PreMatchResult, sb_types::CoreError>> {
        Box::pin(async { Ok(PreMatchResult::Continue) })
    }

    fn route_stream(
        &self,
        _stream: sb_types::ports::BoxedStream,
        _metadata: RouteMetadata,
        on_close: Option<CloseHook>,
    ) -> BoxFuture<'_, Result<(), sb_types::CoreError>> {
        Box::pin(async move {
            if let Some(on_close) = on_close {
                on_close();
            }
            Err(sb_types::CoreError::policy(
                "router port is not wired for direct stream dispatch",
            ))
        })
    }

    fn route_packet(
        &self,
        _packet: Vec<u8>,
        _metadata: RouteMetadata,
        _packet_metadata: PacketMetadata,
    ) -> BoxFuture<'_, Result<Vec<u8>, sb_types::CoreError>> {
        Box::pin(async {
            Err(sb_types::CoreError::policy(
                "router port is not wired for direct packet dispatch",
            ))
        })
    }

    fn rule_set(&self, _tag: &str) -> Option<Arc<dyn RuleSetPort>> {
        None
    }

    fn append_tracker(&self, _tracker: Arc<dyn ConnectionTrackerPort>) {}

    fn reset_network(&self) {}
}

#[derive(Clone)]
pub struct DnsRouterPortAdapter {
    inner: Arc<dyn crate::dns::dns_router::DnsRouter>,
}

impl DnsRouterPortAdapter {
    #[must_use]
    pub fn new(inner: Arc<dyn crate::dns::dns_router::DnsRouter>) -> Self {
        Self { inner }
    }
}

impl std::fmt::Debug for DnsRouterPortAdapter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DnsRouterPortAdapter")
            .finish_non_exhaustive()
    }
}

impl DnsRouterPort for DnsRouterPortAdapter {
    fn exchange(
        &self,
        message: Vec<u8>,
        _options: DnsQueryOptions,
        _metadata: RouteMetadata,
    ) -> BoxFuture<'_, Result<Vec<u8>, sb_types::CoreError>> {
        let inner = self.inner.clone();
        Box::pin(async move {
            inner
                .exchange(&crate::dns::dns_router::DnsQueryContext::new(), &message)
                .await
                .map_err(|error| sb_types::CoreError::dns(error.to_string()))
        })
    }

    fn lookup(
        &self,
        domain: &str,
        _options: DnsQueryOptions,
        _metadata: RouteMetadata,
    ) -> BoxFuture<'_, Result<Vec<IpAddr>, sb_types::CoreError>> {
        let inner = self.inner.clone();
        let domain = domain.to_string();
        Box::pin(async move {
            inner
                .lookup(&crate::dns::dns_router::DnsQueryContext::new(), &domain)
                .await
                .map_err(|error| sb_types::CoreError::dns(error.to_string()))
        })
    }

    fn clear_cache(&self) {
        self.inner.clear_cache();
    }

    fn cache_stats(&self) -> DnsCacheStats {
        DnsCacheStats::default()
    }

    fn lookup_reverse_mapping(&self, ip: IpAddr) -> Option<String> {
        self.inner.lookup_reverse_mapping(&ip)
    }

    fn reset_network(&self) {}
}

#[derive(Clone)]
struct CacheFilePortAdapter {
    inner: Arc<dyn CacheFile>,
}

impl CacheFilePortAdapter {
    fn new(inner: Arc<dyn CacheFile>) -> Self {
        Self { inner }
    }
}

impl std::fmt::Debug for CacheFilePortAdapter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CacheFilePortAdapter")
            .finish_non_exhaustive()
    }
}

impl FakeIpStoragePort for CacheFilePortAdapter {
    fn load_metadata(&self) -> Option<PortFakeIpMetadata> {
        self.inner
            .load_fakeip_metadata()
            .map(|metadata| PortFakeIpMetadata {
                inet4_current_u32: metadata.inet4_current_u32,
                inet6_current_u128: metadata.inet6_current_u128,
            })
    }

    fn save_metadata(&self, metadata: PortFakeIpMetadata) {
        self.inner
            .save_fakeip_metadata(crate::dns::fakeip::FakeIpMetadata {
                inet4_current_u32: metadata.inet4_current_u32,
                inet6_current_u128: metadata.inet6_current_u128,
            });
    }

    fn save_mapping(&self, domain: &str, ip: IpAddr) {
        self.inner.store_fakeip_mapping(domain, ip);
    }

    fn load_domain(&self, domain: &str, is_ipv6: bool) -> Option<IpAddr> {
        self.inner
            .get_fakeip_by_domain(domain)
            .filter(|ip| ip.is_ipv6() == is_ipv6)
    }

    fn load_address(&self, ip: IpAddr) -> Option<String> {
        self.inner.get_domain_by_fakeip(&ip)
    }

    fn reset(&self) -> Result<(), sb_types::CoreError> {
        self.inner
            .reset_fakeip()
            .map_err(|error| sb_types::CoreError::io(error.to_string()))
    }
}

impl RdrcStorePort for CacheFilePortAdapter {
    fn load_rdrc(&self, transport_name: &str, q_name: &str, q_type: u16) -> bool {
        self.inner
            .check_rdrc_rejection(transport_name, q_name, q_type)
    }

    fn save_rdrc(
        &self,
        transport_name: &str,
        q_name: &str,
        q_type: u16,
    ) -> Result<(), sb_types::CoreError> {
        self.inner
            .save_rdrc_rejection(transport_name, q_name, q_type)
            .map_err(|error| sb_types::CoreError::io(error.to_string()))
    }
}

impl CacheFilePort for CacheFilePortAdapter {
    fn store_fakeip(&self) -> bool {
        self.inner.store_fakeip()
    }

    fn store_rdrc(&self) -> bool {
        self.inner.store_rdrc()
    }

    fn load_mode(&self) -> Option<String> {
        self.inner.get_clash_mode()
    }

    fn store_mode(&self, mode: &str) -> Result<(), sb_types::CoreError> {
        self.inner.set_clash_mode(mode.to_string());
        Ok(())
    }

    fn load_selected(&self, group: &str) -> Option<String> {
        self.inner.get_selected(group)
    }

    fn store_selected(&self, group: &str, selected: &str) -> Result<(), sb_types::CoreError> {
        self.inner.set_selected(group, selected);
        Ok(())
    }

    fn load_group_expand(&self, group: &str) -> Option<bool> {
        self.inner.get_expand(group)
    }

    fn store_group_expand(&self, group: &str, expand: bool) -> Result<(), sb_types::CoreError> {
        self.inner.set_expand(group, expand);
        Ok(())
    }

    fn load_rule_set(&self, tag: &str) -> Option<SavedRuleSetBinary> {
        self.inner
            .get_rule_set(tag)
            .map(|content| SavedRuleSetBinary {
                content,
                last_updated: SystemTime::UNIX_EPOCH,
                last_etag: String::new(),
            })
    }

    fn save_rule_set(&self, tag: &str, set: SavedRuleSetBinary) -> Result<(), sb_types::CoreError> {
        self.inner.store_rule_set(tag, set.content);
        Ok(())
    }
}

#[derive(Clone)]
struct UrlTestHistoryPortAdapter {
    inner: Arc<dyn URLTestHistoryStorage>,
}

impl UrlTestHistoryPortAdapter {
    fn new(inner: Arc<dyn URLTestHistoryStorage>) -> Self {
        Self { inner }
    }
}

impl std::fmt::Debug for UrlTestHistoryPortAdapter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UrlTestHistoryPortAdapter")
            .finish_non_exhaustive()
    }
}

impl UrlTestHistoryPort for UrlTestHistoryPortAdapter {
    fn load_history(&self, tag: &str) -> Option<UrlTestHistory> {
        self.inner.load(tag).map(|history| UrlTestHistory {
            time: history.time,
            delay: history.delay,
        })
    }

    fn store_history(&self, tag: &str, history: UrlTestHistory) {
        self.inner.store(
            tag,
            crate::context::URLTestHistory {
                time: history.time,
                delay: history.delay,
            },
        );
    }

    fn delete_history(&self, tag: &str) {
        self.inner.delete(tag);
    }
}

#[derive(Clone)]
struct GlobalClashPort {
    cache_file: Option<Arc<dyn CacheFile>>,
}

impl GlobalClashPort {
    fn new(cache_file: Option<Arc<dyn CacheFile>>) -> Self {
        Self { cache_file }
    }
}

impl std::fmt::Debug for GlobalClashPort {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GlobalClashPort").finish_non_exhaustive()
    }
}

impl ConnectionTrackerPort for GlobalClashPort {
    fn routed_stream(
        &self,
        _metadata: &RouteMetadata,
        _rule: Option<&str>,
        _outbound: Option<&str>,
    ) {
    }

    fn routed_packet(
        &self,
        _metadata: &RouteMetadata,
        _rule: Option<&str>,
        _outbound: Option<&str>,
    ) {
    }
}

impl ClashServerPort for GlobalClashPort {
    fn mode(&self) -> String {
        crate::adapter::clash::get_mode().to_string()
    }

    fn mode_list(&self) -> Vec<String> {
        vec!["global".into(), "rule".into(), "direct".into()]
    }

    fn set_mode(&self, mode: &str) -> Result<(), sb_types::CoreError> {
        let mode = mode
            .parse()
            .map_err(|error: String| sb_types::CoreError::policy(error))?;
        crate::adapter::clash::set_mode(mode);
        if let Some(cache) = &self.cache_file {
            cache.set_clash_mode(mode.to_string());
        }
        Ok(())
    }

    fn history_storage(&self) -> Option<Arc<dyn UrlTestHistoryPort>> {
        None
    }
}

#[derive(Clone)]
struct V2RayStatsPortAdapter {
    inner: Arc<StatsManager>,
}

impl std::fmt::Debug for V2RayStatsPortAdapter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("V2RayStatsPortAdapter")
            .finish_non_exhaustive()
    }
}

impl ConnectionTrackerPort for V2RayStatsPortAdapter {
    fn routed_stream(
        &self,
        _metadata: &RouteMetadata,
        _rule: Option<&str>,
        _outbound: Option<&str>,
    ) {
    }

    fn routed_packet(
        &self,
        _metadata: &RouteMetadata,
        _rule: Option<&str>,
        _outbound: Option<&str>,
    ) {
    }
}

impl V2RayStatsPort for V2RayStatsPortAdapter {
    fn query(&self, pattern: &str, reset: bool) -> Vec<(String, i64)> {
        self.inner
            .query_stats(&[pattern.to_string()], false, reset)
            .into_iter()
            .map(|(name, value)| (name, value as i64))
            .collect()
    }
}

#[derive(Clone)]
struct V2RayServerPortAdapter {
    inner: Arc<dyn V2RayServer>,
}

impl V2RayServerPortAdapter {
    fn new(inner: Arc<dyn V2RayServer>) -> Self {
        Self { inner }
    }
}

impl std::fmt::Debug for V2RayServerPortAdapter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("V2RayServerPortAdapter")
            .finish_non_exhaustive()
    }
}

impl V2RayServerPort for V2RayServerPortAdapter {
    fn stats_service(&self) -> Option<Arc<dyn V2RayStatsPort>> {
        self.inner
            .stats()
            .map(|stats| Arc::new(V2RayStatsPortAdapter { inner: stats }) as _)
    }
}

#[derive(Clone)]
struct TimePortAdapter {
    inner: Arc<dyn TimeService>,
}

impl TimePortAdapter {
    fn new(inner: Arc<dyn TimeService>) -> Self {
        Self { inner }
    }
}

impl std::fmt::Debug for TimePortAdapter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TimePortAdapter").finish_non_exhaustive()
    }
}

impl TimePort for TimePortAdapter {
    fn now(&self) -> SystemTime {
        self.inner.now()
    }
}

#[derive(Clone)]
struct CertificateStorePortAdapter {
    inner: Arc<dyn CertificateStore>,
}

impl CertificateStorePortAdapter {
    fn new(inner: Arc<dyn CertificateStore>) -> Self {
        Self { inner }
    }
}

impl std::fmt::Debug for CertificateStorePortAdapter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CertificateStorePortAdapter")
            .finish_non_exhaustive()
    }
}

impl CertificateStorePort for CertificateStorePortAdapter {
    fn root_pool(&self) -> Option<Vec<String>> {
        self.inner.root_pool()
    }
}
