//! VPN endpoint management (WireGuard, Tailscale, etc.)
//!
//! Endpoints provide VPN tunnel functionality similar to outbounds but with
//! dedicated lifecycle management and integration with the routing system.

use sb_config::ir::{EndpointIR, EndpointType};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

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
        if g.contains_key(&ty) {
            return false;
        }
        g.insert(ty, builder);
        true
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

pub mod tailscale;
pub mod wireguard;

/// Register built-in endpoints.
pub fn register_builtins() {
    #[cfg(feature = "out_wireguard")]
    register_endpoint(
        sb_config::ir::EndpointType::Wireguard,
        wireguard::build_wireguard_endpoint,
    );
    #[cfg(feature = "out_tailscale")]
    register_endpoint(
        sb_config::ir::EndpointType::Tailscale,
        tailscale::build_tailscale_endpoint,
    );
}

/// Thread-safe manager for runtime endpoints.
#[derive(Clone)]
pub struct EndpointManager {
    endpoints: Arc<RwLock<HashMap<String, Arc<dyn Endpoint>>>>,
}

impl std::fmt::Debug for EndpointManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EndpointManager")
            .field("endpoints", &"<dyn Endpoint>")
            .finish()
    }
}

impl EndpointManager {
    /// Create a new empty endpoint manager.
    pub fn new() -> Self {
        Self {
            endpoints: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Register an endpoint by tag.
    pub async fn add_endpoint(&self, tag: String, endpoint: Arc<dyn Endpoint>) {
        let mut guard = self.endpoints.write().await;
        guard.insert(tag, endpoint);
    }

    /// Fetch an endpoint by tag.
    pub async fn get(&self, tag: &str) -> Option<Arc<dyn Endpoint>> {
        let guard = self.endpoints.read().await;
        guard.get(tag).cloned()
    }

    /// Remove an endpoint by tag.
    pub async fn remove(&self, tag: &str) -> Option<Arc<dyn Endpoint>> {
        let mut guard = self.endpoints.write().await;
        guard.remove(tag)
    }

    /// List all registered endpoint tags.
    pub async fn list_tags(&self) -> Vec<String> {
        let guard = self.endpoints.read().await;
        guard.keys().cloned().collect()
    }

    /// Number of registered endpoints.
    pub async fn len(&self) -> usize {
        let guard = self.endpoints.read().await;
        guard.len()
    }

    /// Returns true when no endpoints are registered.
    pub async fn is_empty(&self) -> bool {
        self.len().await == 0
    }

    /// Clear all endpoints.
    pub async fn clear(&self) {
        let mut guard = self.endpoints.write().await;
        guard.clear();
    }
}

impl Default for EndpointManager {
    fn default() -> Self {
        Self::new()
    }
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

    #[tokio::test]
    async fn endpoint_manager_tracks_entries() {
        let mgr = EndpointManager::new();
        assert!(mgr.is_empty().await);

        struct DummyEndpoint;
        impl Endpoint for DummyEndpoint {
            fn endpoint_type(&self) -> &str {
                "dummy"
            }
            fn tag(&self) -> &str {
                "ep"
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

        let ep = Arc::new(DummyEndpoint);
        mgr.add_endpoint("ep".into(), ep.clone()).await;
        assert_eq!(mgr.len().await, 1);
        assert!(mgr.get("ep").await.is_some());

        mgr.remove("ep").await;
        assert!(mgr.is_empty().await);
    }
}
