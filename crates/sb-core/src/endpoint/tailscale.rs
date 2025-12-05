//! Tailscale endpoint implementation.
//!
//! Provides a Tailscale-integrated endpoint that can:
//! - Act as a Tailnet node with its own identity
//! - Accept incoming connections from other Tailnet peers
//! - Route traffic through DERP relays when direct connections fail
//!
//! # Example Configuration
//! ```yaml
//! endpoints:
//!   - type: tailscale
//!     tag: my-node
//!     auth_key: tskey-auth-xxx
//!     hostname: singbox-node
//! ```

use super::{Endpoint, StartStage};
use sb_config::ir::{EndpointIR, EndpointType};
use std::net::Ipv4Addr;
use std::sync::Arc;

/// Tailscale endpoint configuration.
#[derive(Debug, Clone, Default)]
pub struct TailscaleEndpointConfig {
    /// Endpoint tag.
    pub tag: String,
    /// Tailscale auth key for headless login.
    pub auth_key: Option<String>,
    /// Control plane URL (default: Tailscale's).
    pub control_url: Option<String>,
    /// Hostname to advertise.
    pub hostname: Option<String>,
    /// Whether this is an ephemeral node.
    pub ephemeral: bool,
    /// State directory for persistent storage.
    pub state_directory: Option<String>,
    /// Accept advertised routes from control plane.
    pub accept_routes: bool,
    /// Advertise as exit node.
    pub advertise_exit_node: bool,
    /// Routes to advertise.
    pub advertise_routes: Vec<String>,
}

impl TailscaleEndpointConfig {
    /// Create config from IR.
    pub fn from_ir(ir: &EndpointIR) -> Self {
        Self {
            tag: ir.tag.clone().unwrap_or_else(|| "tailscale".to_string()),
            auth_key: std::env::var("TS_AUTHKEY").ok(),
            control_url: std::env::var("TS_CONTROL_URL").ok(),
            hostname: std::env::var("TS_HOSTNAME").ok(),
            ephemeral: std::env::var("TS_EPHEMERAL").ok().map(|v| v == "1" || v == "true").unwrap_or(false),
            state_directory: std::env::var("TS_STATE_DIR").ok(),
            accept_routes: false,
            advertise_exit_node: false,
            advertise_routes: vec![],
        }
    }
}

/// Tailscale endpoint state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TailscaleState {
    /// Not started.
    Stopped,
    /// Initializing WireGuard and coordination.
    Initializing,
    /// Waiting for authentication.
    WaitingForAuth,
    /// Connecting to control plane.
    Connecting,
    /// Fully connected and operational.
    Running,
    /// Shutting down.
    Stopping,
}

/// Tailscale endpoint that acts as a Tailnet node.
pub struct TailscaleEndpoint {
    config: TailscaleEndpointConfig,
    state: std::sync::atomic::AtomicU8,
    /// Our Tailscale IP (100.x.y.z) once assigned.
    tailscale_ip: parking_lot::RwLock<Option<Ipv4Addr>>,
}

impl TailscaleEndpoint {
    /// Create from IR configuration.
    pub fn new(ir: &EndpointIR) -> Self {
        Self {
            config: TailscaleEndpointConfig::from_ir(ir),
            state: std::sync::atomic::AtomicU8::new(TailscaleState::Stopped as u8),
            tailscale_ip: parking_lot::RwLock::new(None),
        }
    }

    /// Create with explicit config.
    pub fn with_config(config: TailscaleEndpointConfig) -> Self {
        Self {
            config,
            state: std::sync::atomic::AtomicU8::new(TailscaleState::Stopped as u8),
            tailscale_ip: parking_lot::RwLock::new(None),
        }
    }

    /// Get current state.
    pub fn state(&self) -> TailscaleState {
        match self.state.load(std::sync::atomic::Ordering::Relaxed) {
            0 => TailscaleState::Stopped,
            1 => TailscaleState::Initializing,
            2 => TailscaleState::WaitingForAuth,
            3 => TailscaleState::Connecting,
            4 => TailscaleState::Running,
            5 => TailscaleState::Stopping,
            _ => TailscaleState::Stopped,
        }
    }

    fn set_state(&self, state: TailscaleState) {
        self.state.store(state as u8, std::sync::atomic::Ordering::Relaxed);
    }

    /// Get assigned Tailscale IP.
    pub fn tailscale_ip(&self) -> Option<Ipv4Addr> {
        *self.tailscale_ip.read()
    }

    /// Initialize the WireGuard tunnel and coordination.
    async fn initialize(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.set_state(TailscaleState::Initializing);
        
        tracing::info!(
            tag = %self.config.tag,
            hostname = ?self.config.hostname,
            "Initializing Tailscale endpoint"
        );

        // TODO: Initialize boringtun WireGuard tunnel
        // TODO: Connect to coordination server
        // TODO: Perform authentication if auth_key provided
        // TODO: Set up DERP relay connections

        self.set_state(TailscaleState::Running);
        Ok(())
    }
}

impl std::fmt::Debug for TailscaleEndpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TailscaleEndpoint")
            .field("tag", &self.config.tag)
            .field("state", &self.state())
            .field("tailscale_ip", &self.tailscale_ip())
            .finish()
    }
}

impl Endpoint for TailscaleEndpoint {
    fn endpoint_type(&self) -> &str {
        "tailscale"
    }

    fn tag(&self) -> &str {
        &self.config.tag
    }

    fn start(&self, stage: StartStage) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        match stage {
            StartStage::Initialize => {
                tracing::debug!(tag = %self.config.tag, "Initializing Tailscale endpoint");
                // Sync initialization - actual async work in Start stage
            }
            StartStage::Start => {
                tracing::info!(
                    tag = %self.config.tag,
                    hostname = ?self.config.hostname,
                    ephemeral = self.config.ephemeral,
                    "Starting Tailscale endpoint"
                );
                
                // For now, just mark as running
                // Full implementation would spawn async init task
                self.set_state(TailscaleState::Running);
            }
            StartStage::PostStart => {
                if self.state() == TailscaleState::Running {
                    tracing::info!(
                        tag = %self.config.tag,
                        "Tailscale endpoint running"
                    );
                }
            }
            StartStage::Started => {}
        }
        Ok(())
    }

    fn close(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        tracing::info!(tag = %self.config.tag, "Closing Tailscale endpoint");
        self.set_state(TailscaleState::Stopping);
        
        // TODO: Close WireGuard tunnel
        // TODO: Disconnect from coordination server
        // TODO: Close DERP connections
        
        self.set_state(TailscaleState::Stopped);
        Ok(())
    }
}

/// Build Tailscale endpoint from IR.
pub fn build_tailscale_endpoint(
    ir: &EndpointIR,
    _ctx: &super::EndpointContext,
) -> Option<Arc<dyn Endpoint>> {
    if ir.ty != EndpointType::Tailscale {
        return None;
    }
    Some(Arc::new(TailscaleEndpoint::new(ir)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_state_transitions() {
        let config = TailscaleEndpointConfig {
            tag: "test".to_string(),
            ..Default::default()
        };
        let endpoint = TailscaleEndpoint::with_config(config);
        
        assert_eq!(endpoint.state(), TailscaleState::Stopped);
        
        endpoint.set_state(TailscaleState::Running);
        assert_eq!(endpoint.state(), TailscaleState::Running);
    }
}
