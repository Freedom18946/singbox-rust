//! Outbound switchboard: registry and selection of outbound connectors
//!
//! This module provides the central registry for outbound adapters/connectors,
//! mapping routing decisions to actual connector implementations.

use crate::error::SbResult;

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tracing::{info, warn};

/// Adapter error types
#[derive(Debug, thiserror::Error)]
pub enum AdapterError {
    #[error("Connection timeout after {0:?}")]
    Timeout(Duration),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Unsupported protocol: {0}")]
    UnsupportedProtocol(String),
    #[error("Not implemented: {0}")]
    NotImplemented(String),
    #[error("Invalid config: {0}")]
    InvalidConfig(&'static str),
    #[error("Other error: {0}")]
    Other(#[from] anyhow::Error),
}

pub type AdapterResult<T> = Result<T, AdapterError>;

/// Outbound switchboard for managing and selecting connectors
#[derive(Debug)]
pub struct OutboundSwitchboard {
    /// Registry mapping outbound names to connector instances
    registry: HashMap<String, Arc<dyn sb_types::Outbound>>,
    /// Default connector when no routing match is found
    default_connector: Option<Arc<dyn sb_types::Outbound>>,
}

impl OutboundSwitchboard {
    /// Create a new empty switchboard
    pub fn new() -> Self {
        Self {
            registry: HashMap::new(),
            default_connector: None,
        }
    }

    /// Register an outbound connector with a given name
    pub fn register<C>(&mut self, name: String, connector: C) -> SbResult<()>
    where
        C: sb_types::Outbound + 'static,
    {
        let connector = Arc::new(connector);

        self.registry.insert(name.clone(), connector);
        info!("Registered outbound connector: '{}'", name);
        Ok(())
    }

    /// Register an already-built canonical connector.
    pub fn register_arc(
        &mut self,
        name: String,
        connector: Arc<dyn sb_types::Outbound>,
    ) -> SbResult<()> {
        self.registry.insert(name.clone(), connector);
        info!("Registered outbound connector: '{}'", name);
        Ok(())
    }

    /// Set the default connector to use when no routing match is found
    pub fn set_default<C>(&mut self, connector: C) -> SbResult<()>
    where
        C: sb_types::Outbound + 'static,
    {
        let connector = Arc::new(connector);

        self.default_connector = Some(connector);
        info!("Set default outbound connector");
        Ok(())
    }

    /// Get a connector by name.
    ///
    /// No implicit fallback is performed for unknown names.
    pub fn get_connector(&self, name: &str) -> Option<Arc<dyn sb_types::Outbound>> {
        if let Some(connector) = self.registry.get(name) {
            return Some(connector.clone());
        }

        if name == "default" {
            return self.default_connector.clone();
        }

        let mut available = self.list_connectors();
        if self.default_connector.is_some() {
            available.push("default".to_string());
            available.sort();
        }
        warn!(
            requested = %name,
            available = ?available,
            "Outbound connector not found; no fallback connector is applied"
        );
        None
    }

    /// List all registered connector names
    pub fn list_connectors(&self) -> Vec<String> {
        let mut names: Vec<_> = self.registry.keys().cloned().collect();
        names.sort();
        names
    }

    /// Get the number of registered connectors
    pub fn len(&self) -> usize {
        self.registry.len()
    }

    /// Check if the switchboard is empty
    pub fn is_empty(&self) -> bool {
        self.registry.is_empty() && self.default_connector.is_none()
    }
}

impl Default for OutboundSwitchboard {
    fn default() -> Self {
        Self::new()
    }
}

/// Builder for constructing outbound switchboard from configuration
pub struct SwitchboardBuilder {
    switchboard: OutboundSwitchboard,
}

impl SwitchboardBuilder {
    /// Create a new builder.
    pub fn new() -> Self {
        Self {
            switchboard: OutboundSwitchboard::new(),
        }
    }

    /// Build switchboard from canonical connectors already assembled by adapter registry.
    pub fn from_bridge(bridge: &crate::adapter::Bridge) -> SbResult<OutboundSwitchboard> {
        let mut builder = Self::new();
        for (name, _kind, connector) in &bridge.outbounds {
            builder
                .switchboard
                .register_arc(name.clone(), connector.clone())?;
        }
        Ok(builder.switchboard)
    }

    /// Legacy IR protocol construction is removed. Use adapter bridge first.
    pub fn from_config_ir(_ir: &sb_config::ir::ConfigIR) -> SbResult<OutboundSwitchboard> {
        Err(crate::error::SbError::config(
            sb_types::IssueCode::SchemaInvalid,
            "switchboard_registry_required",
            "switchboard protocol construction requires adapter::bridge::build_bridge",
        ))
    }

    /// Consume builder and return switchboard.
    pub fn build(self) -> OutboundSwitchboard {
        self.switchboard
    }
}

impl Default for SwitchboardBuilder {
    fn default() -> Self {
        Self::new()
    }
}

// -----------------------------------------------------------------------------
// IR -> Config mapping helpers (for reuse and contract tests)
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    #[allow(unused_imports)]
    use super::*;

    #[test]
    fn ir_construction_requires_adapter_bridge() {
        let ir = sb_config::ir::ConfigIR {
            outbounds: vec![
                sb_config::ir::OutboundIR {
                    ty: sb_config::ir::OutboundType::Http,
                    name: Some("h1".into()),
                    server: Some("127.0.0.1".into()),
                    port: Some(8080),
                    ..Default::default()
                },
                sb_config::ir::OutboundIR {
                    ty: sb_config::ir::OutboundType::Socks,
                    name: Some("s1".into()),
                    server: Some("127.0.0.1".into()),
                    port: Some(1080),
                    ..Default::default()
                },
            ],
            ..Default::default()
        };
        let error = SwitchboardBuilder::from_config_ir(&ir).expect_err("legacy path must fail");
        assert!(error.to_string().contains("adapter::bridge::build_bridge"));
    }
}
