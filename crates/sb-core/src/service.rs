//! Background service management (Resolved, DERP, SSM, etc.)
//!
//! Services provide background functionality like DNS resolution,
//! DERP relay, and Shadowsocks Manager API.

use sb_config::ir::{ServiceIR, ServiceType};
use std::sync::Arc;

/// Lifecycle stages for service initialization.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StartStage {
    /// Initialize resources.
    Initialize,
    /// Start the service.
    Start,
    /// Post-start configuration.
    PostStart,
    /// Finalize startup.
    Started,
}

/// Service trait for background services.
///
/// Services (like Resolved/DERP/SSM) implement this trait to provide
/// background functionality with lifecycle management.
pub trait Service: Send + Sync {
    /// Return the service type (e.g., "resolved", "derp", "ssmapi").
    fn service_type(&self) -> &str;

    /// Return the service tag/identifier.
    fn tag(&self) -> &str;

    /// Start the service at a specific lifecycle stage.
    ///
    /// # Errors
    /// Returns an error if the service fails to start.
    fn start(&self, stage: StartStage) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;

    /// Stop and clean up the service.
    ///
    /// # Errors
    /// Returns an error if cleanup fails.
    fn close(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;
}

/// Context for building services.
pub struct ServiceContext {
    // Placeholder for future integration
    // pub logger: Arc<Logger>,
}

impl Default for ServiceContext {
    fn default() -> Self {
        Self {}
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
}
