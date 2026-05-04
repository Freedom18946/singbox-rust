//! Background service management (Resolved, DERP, SSM, etc.)
//!
//! Services provide background functionality like DNS resolution,
//! DERP relay, and Shadowsocks Manager API.

use parking_lot::RwLock;
use sb_config::ir::{ServiceIR, ServiceType};
use std::collections::HashMap;
use std::sync::Arc;

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
    builders: RwLock<std::collections::HashMap<ServiceType, ServiceBuilder>>,
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
            let mut guard = self.services.write();
            guard.insert(tag.clone(), service);
        }
        let mut statuses = self.statuses.write();
        statuses.remove(&tag);
    }

    /// Fetch a service by tag.
    pub async fn get(&self, tag: &str) -> Option<Arc<dyn Service>> {
        let guard = self.services.read();
        guard.get(tag).cloned()
    }

    /// Remove a service by tag.
    pub async fn remove(&self, tag: &str) -> Option<Arc<dyn Service>> {
        let removed = {
            let mut guard = self.services.write();
            guard.remove(tag)
        };
        let mut statuses = self.statuses.write();
        statuses.remove(tag);
        removed
    }

    /// List all registered service tags.
    pub async fn list_tags(&self) -> Vec<String> {
        let guard = self.services.read();
        guard.keys().cloned().collect()
    }

    /// Number of registered services.
    pub async fn len(&self) -> usize {
        let guard = self.services.read();
        guard.len()
    }

    /// Returns true when no services are registered.
    pub async fn is_empty(&self) -> bool {
        self.len().await == 0
    }

    /// Clear all services.
    pub async fn clear(&self) {
        {
            let mut guard = self.services.write();
            guard.clear();
        }
        let mut statuses = self.statuses.write();
        statuses.clear();
    }

    /// Start all registered services with fault isolation.
    /// Failed services are logged but don't prevent others from starting.
    pub async fn start_all(&self) -> Vec<(String, ServiceStatus)> {
        for stage in [
            StartStage::Initialize,
            StartStage::Start,
            StartStage::PostStart,
            StartStage::Started,
        ] {
            self.start_stage(stage);
        }

        self.health_status().await
    }

    pub(crate) fn start_stage(&self, stage: StartStage) {
        let services: Vec<(String, Arc<dyn Service>)> = {
            let guard = self.services.read();
            guard
                .iter()
                .map(|(tag, service)| (tag.clone(), service.clone()))
                .collect()
        };

        if stage == StartStage::Initialize {
            let mut statuses = self.statuses.write();
            statuses.clear();
        }

        for (tag, service) in services {
            {
                let statuses = self.statuses.read();
                if matches!(statuses.get(&tag), Some(ServiceStatus::Failed(_))) {
                    tracing::debug!(
                        service = %tag,
                        ?stage,
                        "Skipping failed service in later startup stage"
                    );
                    continue;
                }
            }
            {
                let mut statuses = self.statuses.write();
                statuses.insert(tag.clone(), ServiceStatus::Starting);
            }
            let status = match service.start(stage) {
                Ok(()) if stage == StartStage::Started => ServiceStatus::Running,
                Ok(()) => ServiceStatus::Starting,
                Err(e) => {
                    tracing::error!(
                        service = %tag,
                        ?stage,
                        error = %e,
                        "Service startup stage failed (isolated)"
                    );
                    ServiceStatus::Failed(e.to_string())
                }
            };
            {
                let mut statuses = self.statuses.write();
                statuses.insert(tag.clone(), status.clone());
            }
        }
    }

    /// Get the health status of all services.
    pub async fn health_status(&self) -> Vec<(String, ServiceStatus)> {
        let tags: Vec<String> = {
            let guard = self.services.read();
            guard.keys().cloned().collect()
        };
        let statuses = self.statuses.read();
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

    /// LC-003 regression: supervisor-style sequence drives stages individually
    /// and registers services AFTER `Initialize` already ran on an empty
    /// manager. The fix in `runtime::supervisor` moves
    /// `populate_bridge_managers` before `run_context_stage(Start)` so that
    /// `ServiceManager.start_stage(Start)` observes the registered services.
    /// This test pins that contract: even when Initialize runs on an empty
    /// manager, a subsequent Start stage on a now-populated manager must
    /// detect bind failures and surface them via `health_status`.
    #[tokio::test]
    async fn service_manager_late_registration_after_initialize_persists_failed() {
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

        struct FailOnStartService;
        impl Service for FailOnStartService {
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
                    return Err("simulated bind failure".into());
                }
                Ok(())
            }
            fn close(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
                Ok(())
            }
        }

        let mgr = ServiceManager::new();
        // Mirror supervisor: Initialize runs on empty manager (no services yet).
        mgr.start_stage(StartStage::Initialize);

        // populate_bridge_managers happens here in the real flow.
        mgr.add_service("ok-svc".into(), Arc::new(OkService)).await;
        mgr.add_service("fail-svc".into(), Arc::new(FailOnStartService))
            .await;

        // Drive remaining stages, exactly like run_context_stage does in
        // supervisor after the populate step.
        mgr.start_stage(StartStage::Start);
        mgr.start_stage(StartStage::PostStart);
        mgr.start_stage(StartStage::Started);

        let health: std::collections::HashMap<_, _> =
            mgr.health_status().await.into_iter().collect();

        assert_eq!(
            health.get("ok-svc"),
            Some(&ServiceStatus::Running),
            "successful service must reach Running after late registration"
        );
        assert!(
            matches!(
                health.get("fail-svc"),
                Some(ServiceStatus::Failed(message)) if message == "simulated bind failure"
            ),
            "failed service must end as Failed, not Running. got: {:?}",
            health.get("fail-svc")
        );
    }

    #[tokio::test]
    async fn service_manager_start_stage_fault_isolation() {
        use crate::context::Startable;
        use std::sync::Mutex;

        struct RecordingService {
            stages: Mutex<Vec<StartStage>>,
        }
        impl Service for RecordingService {
            fn service_type(&self) -> &str {
                "ok"
            }
            fn tag(&self) -> &str {
                "ok-svc"
            }
            fn start(
                &self,
                stage: StartStage,
            ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
                self.stages.lock().unwrap().push(stage);
                Ok(())
            }
            fn close(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
                Ok(())
            }
        }

        struct FailOnStartService {
            stages: Mutex<Vec<StartStage>>,
        }
        impl Service for FailOnStartService {
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
                self.stages.lock().unwrap().push(stage);
                if stage == StartStage::Start {
                    return Err("start stage failed intentionally".into());
                }
                Ok(())
            }
            fn close(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
                Ok(())
            }
        }

        let mgr = ServiceManager::new();
        let ok = Arc::new(RecordingService {
            stages: Mutex::new(Vec::new()),
        });
        let fail = Arc::new(FailOnStartService {
            stages: Mutex::new(Vec::new()),
        });

        mgr.add_service("ok-svc".into(), ok.clone()).await;
        mgr.add_service("fail-svc".into(), fail.clone()).await;

        for stage in [
            StartStage::Initialize,
            StartStage::Start,
            StartStage::PostStart,
            StartStage::Started,
        ] {
            assert!(Startable::start(&mgr, stage).is_ok());
        }

        let health_by_tag: std::collections::HashMap<_, _> =
            mgr.health_status().await.into_iter().collect();
        assert_eq!(health_by_tag.get("ok-svc"), Some(&ServiceStatus::Running));
        assert!(matches!(
            health_by_tag.get("fail-svc"),
            Some(ServiceStatus::Failed(message)) if message == "start stage failed intentionally"
        ));

        assert_eq!(
            *ok.stages.lock().unwrap(),
            vec![
                StartStage::Initialize,
                StartStage::Start,
                StartStage::PostStart,
                StartStage::Started,
            ]
        );
        assert_eq!(
            *fail.stages.lock().unwrap(),
            vec![StartStage::Initialize, StartStage::Start]
        );
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
