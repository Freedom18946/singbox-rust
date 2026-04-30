//! Background service management (Resolved, DERP, SSM, etc.)
//!
//! Services provide background functionality like DNS resolution,
//! DERP relay, and Shadowsocks Manager API.

use sb_config::ir::{ServiceIR, ServiceType};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

// Re-export canonical definitions from sb-types.
// These were previously defined here; now sb-types is the single source of truth.
pub use sb_types::ports::service::{Lifecycle, Service, StartStage};

/// Context for building services.
#[derive(Default)]
pub struct ServiceContext {
    /// Optional DNS resolver for services that need routing.
    pub dns_resolver: Option<Arc<dyn crate::dns::DnsResolver>>,
    /// Optional DNS router (Go parity: adapter.DNSRouter) for service handlers (e.g., DERP bootstrap-dns).
    pub dns_router: Option<Arc<dyn crate::dns::dns_router::DnsRouter>>,
    /// Optional outbounds registry for detour-capable dialing (Go parity: Dial Fields detour).
    pub outbounds: Option<Arc<crate::outbound::OutboundRegistryHandle>>,
    /// Optional endpoints map (tag -> endpoint) for services that reference endpoint tags (e.g., DERP verify_client_endpoint).
    pub endpoints:
        Option<Arc<std::collections::HashMap<String, Arc<dyn crate::endpoint::Endpoint>>>>,
    /// Optional network monitor for tracking network changes.
    #[cfg(feature = "network_monitor")]
    pub network_monitor: Option<Arc<sb_platform::NetworkMonitor>>,
}

impl ServiceContext {
    /// Create a new empty context.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a context with a DNS resolver.
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
    #[must_use]
    pub fn with_outbounds(
        mut self,
        outbounds: Arc<crate::outbound::OutboundRegistryHandle>,
    ) -> Self {
        self.outbounds = Some(outbounds);
        self
    }

    /// Attach an endpoints map (tag -> endpoint).
    #[must_use]
    pub fn with_endpoints(
        mut self,
        endpoints: Arc<std::collections::HashMap<String, Arc<dyn crate::endpoint::Endpoint>>>,
    ) -> Self {
        self.endpoints = Some(endpoints);
        self
    }

    /// Set the network monitor.
    #[cfg(feature = "network_monitor")]
    #[must_use]
    pub fn with_network_monitor(mut self, monitor: Arc<sb_platform::NetworkMonitor>) -> Self {
        self.network_monitor = Some(monitor);
        self
    }
}

/// Builder function signature for creating services.
pub type ServiceBuilder = fn(&ServiceIR, &ServiceContext) -> Option<Arc<dyn Service>>;

/// Registry for service builders.
pub struct ServiceRegistry {
    builders: parking_lot::RwLock<std::collections::HashMap<ServiceType, ServiceBuilder>>,
}

impl ServiceRegistry {
    /// Create a new empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self {
            builders: parking_lot::RwLock::new(std::collections::HashMap::new()),
        }
    }

    /// Register a service builder for a specific service type.
    ///
    /// Returns `false` if a builder for this type already exists.
    pub fn register(&self, ty: ServiceType, builder: ServiceBuilder) -> bool {
        let mut g = self.builders.write();
        g.insert(ty, builder).is_none()
    }

    /// Look up a service builder by type.
    pub fn get(&self, ty: ServiceType) -> Option<ServiceBuilder> {
        let g = self.builders.read();
        g.get(&ty).copied()
    }

    /// Build a service from configuration.
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
static SERVICE_REGISTRY: once_cell::sync::Lazy<ServiceRegistry> =
    once_cell::sync::Lazy::new(ServiceRegistry::new);

/// Register a service builder globally.
///
/// Returns `false` if a builder for this type already exists.
pub fn register_service(ty: ServiceType, builder: ServiceBuilder) -> bool {
    SERVICE_REGISTRY.register(ty, builder)
}

/// Get the global service registry.
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
    statuses: Arc<RwLock<HashMap<String, ServiceStatus>>>,
}

impl std::fmt::Debug for ServiceManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServiceManager")
            .field("services", &"<dyn Service>")
            .field("statuses", &"<service status>")
            .finish()
    }
}

impl ServiceManager {
    /// Create a new empty service manager.
    pub fn new() -> Self {
        Self {
            services: Arc::new(RwLock::new(HashMap::new())),
            statuses: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Add a service with the given tag.
    pub async fn add_service(&self, tag: String, service: Arc<dyn Service>) {
        {
            let mut guard = self.services.write().await;
            guard.insert(tag.clone(), service);
        }
        let mut statuses = self.statuses.write().await;
        statuses.remove(&tag);
    }

    /// Fetch a service by tag.
    pub async fn get(&self, tag: &str) -> Option<Arc<dyn Service>> {
        let guard = self.services.read().await;
        guard.get(tag).cloned()
    }

    /// Remove a service by tag.
    pub async fn remove(&self, tag: &str) -> Option<Arc<dyn Service>> {
        let removed = {
            let mut guard = self.services.write().await;
            guard.remove(tag)
        };
        let mut statuses = self.statuses.write().await;
        statuses.remove(tag);
        removed
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
        {
            let mut guard = self.services.write().await;
            guard.clear();
        }
        let mut statuses = self.statuses.write().await;
        statuses.clear();
    }

    /// Start all registered services with fault isolation.
    /// Failed services are logged but don't prevent others from starting.
    pub async fn start_all(&self) -> Vec<(String, ServiceStatus)> {
        let services: Vec<(String, Arc<dyn Service>)> = {
            let guard = self.services.read().await;
            guard
                .iter()
                .map(|(tag, service)| (tag.clone(), service.clone()))
                .collect()
        };
        {
            let mut statuses = self.statuses.write().await;
            statuses.clear();
        }

        let mut results = Vec::new();

        for (tag, service) in services {
            {
                let mut statuses = self.statuses.write().await;
                statuses.insert(tag.clone(), ServiceStatus::Starting);
            }
            let status = match Self::start_service(&service, &tag) {
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
            {
                let mut statuses = self.statuses.write().await;
                statuses.insert(tag.clone(), status.clone());
            }
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
        let tags: Vec<String> = {
            let guard = self.services.read().await;
            guard.keys().cloned().collect()
        };
        let statuses = self.statuses.read().await;
        tags.into_iter()
            // Registered services without a start result have not run yet.
            .map(|tag| {
                (
                    tag.clone(),
                    statuses
                        .get(&tag)
                        .cloned()
                        .unwrap_or(ServiceStatus::Stopped),
                )
            })
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
        assert_eq!(
            failed,
            ServiceStatus::Failed("connection refused".to_string())
        );
        assert_eq!(stopped, ServiceStatus::Stopped);

        // Verify Debug derives work
        assert!(format!("{:?}", starting).contains("Starting"));
        assert!(format!("{:?}", running).contains("Running"));
        assert!(format!("{:?}", failed).contains("connection refused"));
        assert!(format!("{:?}", stopped).contains("Stopped"));

        // Verify Clone
        let cloned = failed.clone();
        assert_eq!(
            cloned,
            ServiceStatus::Failed("connection refused".to_string())
        );
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
                    assert!(matches!(status, ServiceStatus::Failed(_)));
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
    async fn service_manager_persists_failed_start_status() {
        struct OkService;
        impl Service for OkService {
            fn service_type(&self) -> &str {
                "ok"
            }
            fn tag(&self) -> &str {
                "ok-svc"
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

        struct FailService;
        impl Service for FailService {
            fn service_type(&self) -> &str {
                "fail"
            }
            fn tag(&self) -> &str {
                "fail-svc"
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
        mgr.add_service("ok-svc".into(), Arc::new(OkService)).await;
        mgr.add_service("fail-svc".into(), Arc::new(FailService))
            .await;

        let start_results = mgr.start_all().await;
        let health_statuses = mgr.health_status().await;
        let start_by_tag: std::collections::HashMap<_, _> = start_results.into_iter().collect();
        let health_by_tag: std::collections::HashMap<_, _> = health_statuses.into_iter().collect();

        assert_eq!(health_by_tag, start_by_tag);
        assert_eq!(health_by_tag.get("ok-svc"), Some(&ServiceStatus::Running));
        assert!(matches!(
            health_by_tag.get("fail-svc"),
            Some(ServiceStatus::Failed(message)) if message == "intentional failure"
        ));
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

        let before_start = mgr.health_status().await;
        assert_eq!(before_start.len(), 2);
        for (_tag, status) in &before_start {
            assert_eq!(*status, ServiceStatus::Stopped);
        }

        let start_results = mgr.start_all().await;
        assert_eq!(start_results.len(), 2);

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
