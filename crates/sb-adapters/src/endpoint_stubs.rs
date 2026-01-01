//! Endpoint stub implementations for WireGuard and Tailscale.
//!
//! These are placeholder implementations that return helpful errors
//! when the actual endpoint implementations are not available.

use sb_config::ir::{EndpointIR, EndpointType};
use sb_core::endpoint::{Endpoint, EndpointContext, StartStage};
use std::sync::Arc;

/// Stub endpoint that returns "not implemented" errors.
struct StubEndpoint {
    ty_str: &'static str,
    tag: String,
}

impl Endpoint for StubEndpoint {
    fn endpoint_type(&self) -> &str {
        self.ty_str
    }

    fn tag(&self) -> &str {
        &self.tag
    }

    fn start(&self, _stage: StartStage) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        Err(format!(
            "endpoint '{}' ({}) is not implemented in this build",
            self.tag, self.ty_str
        )
        .into())
    }

    fn close(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        Ok(()) // Stub cleanup is no-op
    }
}

/// Build a WireGuard endpoint stub.
///
/// Returns `None` and logs a warning that WireGuard is not implemented.
pub fn build_wireguard_endpoint(
    ir: &EndpointIR,
    _ctx: &EndpointContext,
) -> Option<Arc<dyn Endpoint>> {
    let tag = ir.tag.as_deref().unwrap_or("wireguard");
    tracing::warn!(
        endpoint_type = "wireguard",
        tag = tag,
        "WireGuard endpoint is not implemented; requires boringtun or kernel integration"
    );

    // Return stub that will error when start() is called
    Some(Arc::new(StubEndpoint {
        ty_str: "wireguard",
        tag: tag.to_string(),
    }))
}

/// Build a Tailscale endpoint stub.
///
/// Returns `None` and logs a warning that Tailscale is not implemented.
pub fn build_tailscale_endpoint(
    ir: &EndpointIR,
    _ctx: &EndpointContext,
) -> Option<Arc<dyn Endpoint>> {
    let tag = ir.tag.as_deref().unwrap_or("tailscale");
    tracing::warn!(
        endpoint_type = "tailscale",
        tag = tag,
        "Tailscale endpoint is not implemented; requires tailscale-go bindings or tsnet integration"
    );

    // Return stub that will error when start() is called
    Some(Arc::new(StubEndpoint {
        ty_str: "tailscale",
        tag: tag.to_string(),
    }))
}

/// Register all endpoint stubs.
///
/// This should be called during adapter initialization to register
/// WireGuard and Tailscale endpoint stubs.
pub fn register_endpoint_stubs() {
    #[cfg(feature = "adapter-wireguard-endpoint")]
    sb_core::endpoint::register_endpoint(
        EndpointType::Wireguard,
        crate::endpoint::wireguard::build_wireguard_endpoint,
    );

    #[cfg(not(feature = "adapter-wireguard-endpoint"))]
    sb_core::endpoint::register_endpoint(EndpointType::Wireguard, build_wireguard_endpoint);

    #[cfg(feature = "adapter-tailscale-endpoint")]
    sb_core::endpoint::register_endpoint(
        EndpointType::Tailscale,
        crate::endpoint::tailscale::build_tailscale_endpoint,
    );

    #[cfg(not(feature = "adapter-tailscale-endpoint"))]
    sb_core::endpoint::register_endpoint(EndpointType::Tailscale, build_tailscale_endpoint);
}

#[cfg(test)]
mod tests {
    use super::*;
    use sb_config::ir::EndpointType;

    #[test]
    fn test_wireguard_stub_registration() {
        let registry = sb_core::endpoint::EndpointRegistry::new();
        assert!(registry.register(EndpointType::Wireguard, build_wireguard_endpoint));

        let ctx = EndpointContext::default();
        let ir = EndpointIR {
            ty: EndpointType::Wireguard,
            tag: Some("wg0".to_string()),
            network: None,
            wireguard_system: None,
            wireguard_name: None,
            wireguard_mtu: None,
            wireguard_address: None,
            wireguard_private_key: None,
            wireguard_listen_port: None,
            wireguard_peers: None,
            wireguard_udp_timeout: None,
            wireguard_workers: None,
            tailscale_state_directory: None,
            tailscale_auth_key: None,
            tailscale_control_url: None,
            tailscale_ephemeral: None,
            tailscale_hostname: None,
            tailscale_accept_routes: None,
            tailscale_exit_node: None,
            tailscale_exit_node_allow_lan_access: None,
            tailscale_advertise_routes: None,
            tailscale_advertise_exit_node: None,
            tailscale_udp_timeout: None,
        };

        let endpoint = registry.build(&ir, &ctx);
        assert!(endpoint.is_some());

        let endpoint = endpoint.unwrap();
        assert_eq!(endpoint.endpoint_type(), "wireguard");
        assert_eq!(endpoint.tag(), "wg0");

        // Starting should fail with helpful error
        let result = endpoint.start(StartStage::Initialize);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not implemented"));
    }

    #[test]
    fn test_tailscale_stub_registration() {
        let registry = sb_core::endpoint::EndpointRegistry::new();
        assert!(registry.register(EndpointType::Tailscale, build_tailscale_endpoint));

        let ctx = EndpointContext::default();
        let ir = EndpointIR {
            ty: EndpointType::Tailscale,
            tag: Some("ts0".to_string()),
            network: None,
            wireguard_system: None,
            wireguard_name: None,
            wireguard_mtu: None,
            wireguard_address: None,
            wireguard_private_key: None,
            wireguard_listen_port: None,
            wireguard_peers: None,
            wireguard_udp_timeout: None,
            wireguard_workers: None,
            tailscale_state_directory: Some("/var/lib/tailscale".to_string()),
            tailscale_auth_key: None,
            tailscale_control_url: None,
            tailscale_ephemeral: None,
            tailscale_hostname: None,
            tailscale_accept_routes: None,
            tailscale_exit_node: None,
            tailscale_exit_node_allow_lan_access: None,
            tailscale_advertise_routes: None,
            tailscale_advertise_exit_node: None,
            tailscale_udp_timeout: None,
        };

        let endpoint = registry.build(&ir, &ctx);
        assert!(endpoint.is_some());

        let endpoint = endpoint.unwrap();
        assert_eq!(endpoint.endpoint_type(), "tailscale");
        assert_eq!(endpoint.tag(), "ts0");

        // Starting should fail with helpful error if stub, or succeed if real
        let result = endpoint.start(StartStage::Initialize);

        #[cfg(not(feature = "adapter-tailscale-endpoint"))]
        {
            assert!(result.is_err());
            assert!(result.unwrap_err().to_string().contains("not implemented"));
        }

        #[cfg(feature = "adapter-tailscale-endpoint")]
        {
            if let Err(e) = &result {
                assert!(!e.to_string().contains("not implemented"));
            }
        }
    }
}
