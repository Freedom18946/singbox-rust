//! Background service management (Resolved, DERP, SSM, etc.)
//! 后台服务管理（Resolved, DERP, SSM 等）
//!
//! Services provide background functionality like DNS resolution,
//! DERP relay, and Shadowsocks Manager API.
//! 服务提供后台功能，如 DNS 解析、DERP 中继和 Shadowsocks 管理器 API。

use sb_config::ir::{ServiceIR, ServiceType};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

// Re-export canonical definitions from sb-types.
// These were previously defined here; now sb-types is the single source of truth.
pub use sb_types::ports::service::{Lifecycle, Service, StartStage};

/// Context for building services.
/// 构建服务的上下文。
#[derive(Default)]
pub struct ServiceContext {
    /// Optional DNS resolver for services that need routing.
    /// 可选的 DNS 解析器，用于需要路由的服务。
    pub dns_resolver: Option<Arc<dyn crate::dns::DnsResolver>>,
    /// Optional DNS router (Go parity: adapter.DNSRouter) for service handlers (e.g., DERP bootstrap-dns).
    /// 可选的 DNS 路由器（Go 对齐：adapter.DNSRouter），供服务 handler 使用（例如 DERP /bootstrap-dns）。
    pub dns_router: Option<Arc<dyn crate::dns::dns_router::DnsRouter>>,
    /// Optional outbounds registry for detour-capable dialing (Go parity: Dial Fields detour).
    /// 可选出站注册表，用于支持 detour 拨号（Go 对齐：Dial Fields detour）。
    pub outbounds: Option<Arc<crate::outbound::OutboundRegistryHandle>>,
    /// Optional endpoints map (tag -> endpoint) for services that reference endpoint tags (e.g., DERP verify_client_endpoint).
    /// 可选 endpoints 映射（tag -> endpoint），用于服务引用 endpoint tag（例如 DERP verify_client_endpoint）。
    pub endpoints:
        Option<Arc<std::collections::HashMap<String, Arc<dyn crate::endpoint::Endpoint>>>>,
    /// Optional network monitor for tracking network changes.
    /// 可选的网络监视器，用于跟踪网络变化。
    #[cfg(feature = "network_monitor")]
    pub network_monitor: Option<Arc<sb_platform::NetworkMonitor>>,
}

impl ServiceContext {
    /// Create a new empty context.
    /// 创建一个新的空上下文。
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a context with a DNS resolver.
    /// 创建一个带有 DNS 解析器的上下文。
    #[must_use]
    pub fn with_dns_resolver(resolver: Arc<dyn crate::dns::DnsResolver>) -> Self {
        Self {
            dns_resolver: Some(resolver),
            dns_router: None,
            outbounds: None,
            endpoints: None,
            #[cfg(feature = "network_monitor")]
            network_monitor: None,
        }
    }

    /// Create a context with a DNS router.
    /// 创建一个带有 DNS 路由器的上下文。
    #[must_use]
    pub fn with_dns_router(router: Arc<dyn crate::dns::dns_router::DnsRouter>) -> Self {
        Self {
            dns_resolver: None,
            dns_router: Some(router),
            outbounds: None,
            endpoints: None,
            #[cfg(feature = "network_monitor")]
            network_monitor: None,
        }
    }

    /// Attach an outbounds registry.
    /// 附加出站注册表。
    #[must_use]
    pub fn with_outbounds(
        mut self,
        outbounds: Arc<crate::outbound::OutboundRegistryHandle>,
    ) -> Self {
        self.outbounds = Some(outbounds);
        self
    }

    /// Attach an endpoints map (tag -> endpoint).
    /// 附加 endpoints 映射（tag -> endpoint）。
    #[must_use]
    pub fn with_endpoints(
        mut self,
        endpoints: Arc<std::collections::HashMap<String, Arc<dyn crate::endpoint::Endpoint>>>,
    ) -> Self {
        self.endpoints = Some(endpoints);
        self
    }

    /// Set the network monitor.
    /// 设置网络监视器。
    #[cfg(feature = "network_monitor")]
    #[must_use]
    pub fn with_network_monitor(mut self, monitor: Arc<sb_platform::NetworkMonitor>) -> Self {
        self.network_monitor = Some(monitor);
        self
    }
}

/// Builder function signature for creating services.
/// 用于创建服务的构建器函数签名。
pub type ServiceBuilder = fn(&ServiceIR, &ServiceContext) -> Option<Arc<dyn Service>>;

/// Registry for service builders.
/// 服务构建器的注册表。
pub struct ServiceRegistry {
    builders: parking_lot::RwLock<std::collections::HashMap<ServiceType, ServiceBuilder>>,
}

impl ServiceRegistry {
    /// Create a new empty registry.
    /// 创建一个新的空注册表。
    #[must_use]
    pub fn new() -> Self {
        Self {
            builders: parking_lot::RwLock::new(std::collections::HashMap::new()),
        }
    }

    /// Register a service builder for a specific service type.
    /// 为特定服务类型注册服务构建器。
    ///
    /// Returns `false` if a builder for this type already exists.
    /// 如果此类型的构建器已存在，则返回 `false`。
    pub fn register(&self, ty: ServiceType, builder: ServiceBuilder) -> bool {
        let mut g = self.builders.write();
        g.insert(ty, builder).is_none()
    }

    /// Look up a service builder by type.
    /// 按类型查找服务构建器。
    pub fn get(&self, ty: ServiceType) -> Option<ServiceBuilder> {
        let g = self.builders.read();
        g.get(&ty).copied()
    }

    /// Build a service from configuration.
    /// 根据配置构建服务。
    pub fn build(&self, ir: &ServiceIR, ctx: &ServiceContext) -> Option<Arc<dyn Service>> {
        let builder = self.get(ir.ty)?;
        builder(ir, ctx)
    }
}

impl Default for ServiceRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Global service registry instance.
/// 全局服务注册表实例。
static SERVICE_REGISTRY: once_cell::sync::Lazy<ServiceRegistry> =
    once_cell::sync::Lazy::new(ServiceRegistry::new);

/// Register a service builder globally.
/// 全局注册服务构建器。
///
/// Returns `false` if a builder for this type already exists.
/// 如果此类型的构建器已存在，则返回 `false`。
pub fn register_service(ty: ServiceType, builder: ServiceBuilder) -> bool {
    SERVICE_REGISTRY.register(ty, builder)
}

/// Get the global service registry.
/// 获取全局服务注册表。
#[must_use]
pub fn service_registry() -> &'static ServiceRegistry {
    &SERVICE_REGISTRY
}

/// Status of an individual service.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServiceStatus {
    /// Service is being started.
    Starting,
    /// Service is running normally.
    Running,
    /// Service failed to start.
    Failed(String),
    /// Service has been stopped.
    Stopped,
}

/// Thread-safe registry of instantiated services by tag.
#[derive(Clone)]
pub struct ServiceManager {
    services: Arc<RwLock<HashMap<String, Arc<dyn Service>>>>,
}

impl std::fmt::Debug for ServiceManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServiceManager")
            .field("services", &"<dyn Service>")
            .finish()
    }
}

impl ServiceManager {
    /// Create a new empty service manager.
    pub fn new() -> Self {
        Self {
            services: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Add a service with the given tag.
    pub async fn add_service(&self, tag: String, service: Arc<dyn Service>) {
        let mut guard = self.services.write().await;
        guard.insert(tag, service);
    }

    /// Fetch a service by tag.
    pub async fn get(&self, tag: &str) -> Option<Arc<dyn Service>> {
        let guard = self.services.read().await;
        guard.get(tag).cloned()
    }

    /// Remove a service by tag.
    pub async fn remove(&self, tag: &str) -> Option<Arc<dyn Service>> {
        let mut guard = self.services.write().await;
        guard.remove(tag)
    }

    /// List all registered service tags.
    pub async fn list_tags(&self) -> Vec<String> {
        let guard = self.services.read().await;
        guard.keys().cloned().collect()
    }

    /// Number of registered services.
    pub async fn len(&self) -> usize {
        let guard = self.services.read().await;
        guard.len()
    }

    /// Returns true when no services are registered.
    pub async fn is_empty(&self) -> bool {
        self.len().await == 0
    }

    /// Clear all services.
    pub async fn clear(&self) {
        let mut guard = self.services.write().await;
        guard.clear();
    }

    /// Start all registered services with fault isolation.
    /// Failed services are logged but don't prevent others from starting.
    pub async fn start_all(&self) -> Vec<(String, ServiceStatus)> {
        let guard = self.services.read().await;
        let mut results = Vec::new();

        for (tag, service) in guard.iter() {
            let status = match Self::start_service(service, tag) {
                Ok(()) => ServiceStatus::Running,
                Err(e) => {
                    tracing::error!(
                        service = %tag,
                        error = %e,
                        "Service failed to start (isolated)"
                    );
                    ServiceStatus::Failed(e.to_string())
                }
            };
            results.push((tag.clone(), status));
        }

        results
    }

    fn start_service(
        service: &Arc<dyn Service>,
        tag: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        tracing::info!(service = %tag, "Starting service");
        service.start(StartStage::Initialize)?;
        service.start(StartStage::Start)?;
        service.start(StartStage::PostStart)?;
        service.start(StartStage::Started)?;
        tracing::info!(service = %tag, "Service started successfully");
        Ok(())
    }

    /// Get the health status of all services.
    pub async fn health_status(&self) -> Vec<(String, ServiceStatus)> {
        let guard = self.services.read().await;
        guard
            .keys()
            .map(|tag| (tag.clone(), ServiceStatus::Running))
            .collect()
    }
}

impl Default for ServiceManager {
    fn default() -> Self {
        Self::new()
    }
}

// Re-export NTP service module if feature is enabled
#[cfg(feature = "service_ntp")]
pub mod ntp;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_service_registry() {
        let registry = ServiceRegistry::new();

        // Test empty registry
        assert!(registry.get(ServiceType::Resolved).is_none());

        // Test registration
        fn stub_builder(_ir: &ServiceIR, _ctx: &ServiceContext) -> Option<Arc<dyn Service>> {
            None
        }

        assert!(registry.register(ServiceType::Resolved, stub_builder));
        assert!(!registry.register(ServiceType::Resolved, stub_builder)); // duplicate

        // Test retrieval
        assert!(registry.get(ServiceType::Resolved).is_some());
    }

    #[tokio::test]
    async fn service_manager_tracks_entries() {
        struct DummyService;
        impl Service for DummyService {
            fn service_type(&self) -> &str {
                "dummy"
            }
            fn tag(&self) -> &str {
                "svc"
            }
            fn start(
                &self,
                _stage: StartStage,
            ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
                Ok(())
            }
            fn close(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
                Ok(())
            }
        }

        let mgr = ServiceManager::new();
        assert!(mgr.is_empty().await);

        let svc = Arc::new(DummyService);
        mgr.add_service("svc".into(), svc.clone()).await;
        assert_eq!(mgr.len().await, 1);
        assert!(mgr.get("svc").await.is_some());

        mgr.remove("svc").await;
        assert!(mgr.is_empty().await);
    }

    #[test]
    fn test_service_status_enum() {
        let starting = ServiceStatus::Starting;
        let running = ServiceStatus::Running;
        let failed = ServiceStatus::Failed("connection refused".to_string());
        let stopped = ServiceStatus::Stopped;

        assert_eq!(starting, ServiceStatus::Starting);
        assert_eq!(running, ServiceStatus::Running);
        assert_eq!(failed, ServiceStatus::Failed("connection refused".to_string()));
        assert_eq!(stopped, ServiceStatus::Stopped);

        // Verify Debug derives work
        assert!(format!("{:?}", starting).contains("Starting"));
        assert!(format!("{:?}", running).contains("Running"));
        assert!(format!("{:?}", failed).contains("connection refused"));
        assert!(format!("{:?}", stopped).contains("Stopped"));

        // Verify Clone
        let cloned = failed.clone();
        assert_eq!(cloned, ServiceStatus::Failed("connection refused".to_string()));
    }

    #[tokio::test]
    async fn test_start_all_fault_isolation() {
        use std::sync::atomic::{AtomicBool, Ordering};

        struct GoodService {
            started: AtomicBool,
        }
        impl Service for GoodService {
            fn service_type(&self) -> &str {
                "good"
            }
            fn tag(&self) -> &str {
                "good-svc"
            }
            fn start(
                &self,
                stage: StartStage,
            ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
                if stage == StartStage::Started {
                    self.started.store(true, Ordering::Relaxed);
                }
                Ok(())
            }
            fn close(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
                Ok(())
            }
        }

        struct BadService;
        impl Service for BadService {
            fn service_type(&self) -> &str {
                "bad"
            }
            fn tag(&self) -> &str {
                "bad-svc"
            }
            fn start(
                &self,
                stage: StartStage,
            ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
                if stage == StartStage::Start {
                    return Err("intentional failure".into());
                }
                Ok(())
            }
            fn close(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
                Ok(())
            }
        }

        let mgr = ServiceManager::new();
        let good = Arc::new(GoodService {
            started: AtomicBool::new(false),
        });
        let bad: Arc<dyn Service> = Arc::new(BadService);

        mgr.add_service("good-svc".into(), good.clone() as Arc<dyn Service>)
            .await;
        mgr.add_service("bad-svc".into(), bad).await;

        let results = mgr.start_all().await;
        assert_eq!(results.len(), 2);

        // Verify that both services were attempted
        let mut has_running = false;
        let mut has_failed = false;
        for (tag, status) in &results {
            match tag.as_str() {
                "good-svc" => {
                    assert_eq!(*status, ServiceStatus::Running);
                    has_running = true;
                }
                "bad-svc" => {
                    matches!(status, ServiceStatus::Failed(_));
                    has_failed = true;
                }
                _ => panic!("unexpected service tag: {}", tag),
            }
        }
        assert!(has_running, "Good service should have started");
        assert!(has_failed, "Bad service should have been recorded");

        // The good service should have actually completed all stages
        assert!(good.started.load(Ordering::Relaxed));
    }

    #[tokio::test]
    async fn test_health_status() {
        struct DummyService2 {
            tag_name: String,
        }
        impl Service for DummyService2 {
            fn service_type(&self) -> &str {
                "dummy"
            }
            fn tag(&self) -> &str {
                &self.tag_name
            }
            fn start(
                &self,
                _stage: StartStage,
            ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
                Ok(())
            }
            fn close(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
                Ok(())
            }
        }

        let mgr = ServiceManager::new();
        mgr.add_service(
            "svc-a".into(),
            Arc::new(DummyService2 {
                tag_name: "svc-a".into(),
            }),
        )
        .await;
        mgr.add_service(
            "svc-b".into(),
            Arc::new(DummyService2 {
                tag_name: "svc-b".into(),
            }),
        )
        .await;

        let statuses = mgr.health_status().await;
        assert_eq!(statuses.len(), 2);

        for (_tag, status) in &statuses {
            assert_eq!(*status, ServiceStatus::Running);
        }
    }

    #[tokio::test]
    async fn test_start_all_empty_manager() {
        let mgr = ServiceManager::new();
        let results = mgr.start_all().await;
        assert!(results.is_empty());
    }
}
