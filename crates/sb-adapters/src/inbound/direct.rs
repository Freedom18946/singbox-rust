//! Direct inbound adapter: wraps `sb_core::inbound::direct::DirectForward`.
//!
//! This adapter provides a simple TCP/UDP forwarder that listens on a local address
//! and forwards all connections to a fixed override destination.

use std::net::SocketAddr;
use std::sync::Arc;

use sb_core::adapter::{InboundParam, InboundService};
use sb_core::inbound::direct::DirectForward;

/// Direct inbound adapter that wraps the core DirectForward implementation.
#[derive(Debug)]
pub struct DirectInboundAdapter {
    inner: Arc<DirectForward>,
}

impl DirectInboundAdapter {
    /// Create a new Direct inbound adapter from parameters.
    ///
    /// # Arguments
    /// * `param` - Inbound parameters containing listen address, override host/port, and UDP flag.
    ///
    /// # Returns
    /// A boxed InboundService or an error if parameters are invalid.
    pub fn create(param: &InboundParam) -> std::io::Result<Box<dyn InboundService>> {
        // Parse listen address
        let listen_str = format!("{}:{}", param.listen, param.port);
        let listen: SocketAddr = listen_str.parse().map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("invalid listen address '{}': {}", listen_str, e),
            )
        })?;

        // Get override destination (required for Direct inbound)
        let dst_host = param
            .override_host
            .as_ref()
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "direct inbound requires override_host",
                )
            })?
            .clone();

        let dst_port = param.override_port.ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "direct inbound requires override_port",
            )
        })?;

        // Check network mode (tcp, udp, or both)
        // Default to both if not specified
        let udp_enabled = if let Some(network) = &param.network {
            let network_lower = network.to_lowercase();
            network_lower.contains("udp")
        } else {
            true // Default: support both TCP and UDP
        };

        let forward = DirectForward::new(listen, dst_host, dst_port, udp_enabled);

        Ok(Box::new(DirectInboundAdapter {
            inner: Arc::new(forward),
        }))
    }
}

impl InboundService for DirectInboundAdapter {
    fn serve(&self) -> std::io::Result<()> {
        self.inner.serve()
    }

    fn request_shutdown(&self) {
        self.inner.request_shutdown()
    }

    fn active_connections(&self) -> Option<u64> {
        self.inner.active_connections()
    }

    fn udp_sessions_estimate(&self) -> Option<u64> {
        self.inner.udp_sessions_estimate()
    }
}
