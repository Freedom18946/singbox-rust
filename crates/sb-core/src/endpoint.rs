//! VPN endpoint management (WireGuard, Tailscale, etc.)
//!
//! Endpoints provide VPN tunnel functionality similar to outbounds but with
//! dedicated lifecycle management and integration with the routing system.

use sb_config::ir::{EndpointIR, EndpointType};
use std::sync::Arc;

/// Lifecycle stages for endpoint initialization.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StartStage {
    /// Initialize resources.
    Initialize,
    /// Start the endpoint.
    Start,
    /// Post-start configuration.
    PostStart,
    /// Finalize startup.
    Started,
}

/// Endpoint trait for VPN tunnel management.
///
/// Endpoints (like WireGuard/Tailscale) implement this trait to provide
/// VPN functionality with lifecycle management.
pub trait Endpoint: Send + Sync {
    /// Return the endpoint type (e.g., "wireguard", "tailscale").
    fn endpoint_type(&self) -> &str;

    /// Return the endpoint tag/identifier.
    fn tag(&self) -> &str;

    /// Start the endpoint at a specific lifecycle stage.
    ///
    /// # Errors
    /// Returns an error if the endpoint fails to start.
    fn start(&self, stage: StartStage) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;

    /// Stop and clean up the endpoint.
    ///
    /// # Errors
    /// Returns an error if cleanup fails.
    fn close(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;
}

/// Context for building endpoints.
#[derive(Default)]
pub struct EndpointContext {
    // Placeholder for future router/bridge integration
    // pub router: Arc<RouterHandle>,
    // pub bridge: Arc<Bridge>,
}


/// Builder function signature for creating endpoints.
pub type EndpointBuilder = fn(&EndpointIR, &EndpointContext) -> Option<Arc<dyn Endpoint>>;

/// Registry for endpoint builders.
pub struct EndpointRegistry {
    builders: parking_lot::RwLock<std::collections::HashMap<EndpointType, EndpointBuilder>>,
}

impl EndpointRegistry {
    /// Create a new empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self {
            builders: parking_lot::RwLock::new(std::collections::HashMap::new()),
        }
    }

    /// Register an endpoint builder for a specific endpoint type.
    ///
    /// Returns `false` if a builder for this type already exists.
    pub fn register(&self, ty: EndpointType, builder: EndpointBuilder) -> bool {
        let mut g = self.builders.write();
        g.insert(ty, builder).is_none()
    }

    /// Look up an endpoint builder by type.
    pub fn get(&self, ty: EndpointType) -> Option<EndpointBuilder> {
        let g = self.builders.read();
        g.get(&ty).copied()
    }

    /// Build an endpoint from configuration.
    pub fn build(&self, ir: &EndpointIR, ctx: &EndpointContext) -> Option<Arc<dyn Endpoint>> {
        let builder = self.get(ir.ty)?;
        builder(ir, ctx)
    }
}

impl Default for EndpointRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Global endpoint registry instance.
static ENDPOINT_REGISTRY: once_cell::sync::Lazy<EndpointRegistry> =
    once_cell::sync::Lazy::new(EndpointRegistry::new);

/// Register an endpoint builder globally.
///
/// Returns `false` if a builder for this type already exists.
pub fn register_endpoint(ty: EndpointType, builder: EndpointBuilder) -> bool {
    ENDPOINT_REGISTRY.register(ty, builder)
}

/// Get the global endpoint registry.
#[must_use]
pub fn endpoint_registry() -> &'static EndpointRegistry {
    &ENDPOINT_REGISTRY
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_endpoint_registry() {
        let registry = EndpointRegistry::new();

        // Test empty registry
        assert!(registry.get(EndpointType::Wireguard).is_none());

        // Test registration
        fn stub_builder(_ir: &EndpointIR, _ctx: &EndpointContext) -> Option<Arc<dyn Endpoint>> {
            None
        }

        assert!(registry.register(EndpointType::Wireguard, stub_builder));
        assert!(!registry.register(EndpointType::Wireguard, stub_builder)); // duplicate

        // Test retrieval
        assert!(registry.get(EndpointType::Wireguard).is_some());
    }
}
