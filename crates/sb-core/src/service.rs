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

/// Lifecycle stages for service initialization.
/// 服务初始化的生命周期阶段。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StartStage {
    /// Initialize resources.
    /// 初始化资源。
    Initialize,
    /// Start the service.
    /// 启动服务。
    Start,
    /// Post-start configuration.
    /// 启动后配置。
    PostStart,
    /// Finalize startup.
    /// 完成启动。
    Started,
}

/// Service trait for background services.
/// 后台服务的 Service trait。
///
/// Services (like Resolved/DERP/SSM) implement this trait to provide
/// background functionality with lifecycle management.
/// 服务（如 Resolved/DERP/SSM）实现此 trait 以提供具有生命周期管理的后台功能。
pub trait Service: Send + Sync {
    /// Return the service type (e.g., "resolved", "derp", "ssmapi").
    /// 返回服务类型（例如 "resolved", "derp", "ssmapi"）。
    fn service_type(&self) -> &str;

    /// Return the service tag/identifier.
    /// 返回服务标签/标识符。
    fn tag(&self) -> &str;

    /// Start the service at a specific lifecycle stage.
    /// 在特定的生命周期阶段启动服务。
    ///
    /// # Errors
    /// Returns an error if the service fails to start.
    /// 如果服务启动失败，则返回错误。
    fn start(&self, stage: StartStage) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;

    /// Stop and clean up the service.
    /// 停止并清理服务。
    ///
    /// # Errors
    /// Returns an error if cleanup fails.
    /// 如果清理失败，则返回错误。
    fn close(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;
}

/// Context for building services.
/// 构建服务的上下文。
#[derive(Default)]
pub struct ServiceContext {
    // Placeholder for future integration
    // pub logger: Arc<Logger>,
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
}
