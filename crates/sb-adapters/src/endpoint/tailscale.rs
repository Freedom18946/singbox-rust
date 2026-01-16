//! Tailscale endpoint builder.
//!
//! This provides a thin wrapper around the sb-core TailscaleEndpoint so that
//! configs using `type: "tailscale"` can be instantiated without relying on
//! the stub fallback.

use std::sync::Arc;

use sb_config::ir::{EndpointIR, EndpointType};
use sb_core::endpoint::{tailscale::TailscaleEndpoint, Endpoint, EndpointContext};

pub fn build_tailscale_endpoint(
    ir: &EndpointIR,
    ctx: &EndpointContext,
) -> Option<Arc<dyn Endpoint>> {
    if ir.ty != EndpointType::Tailscale {
        return None;
    }

    #[cfg(feature = "router")]
    {
        Some(Arc::new(TailscaleEndpoint::new(ir, ctx.router.clone())))
    }
    #[cfg(not(feature = "router"))]
    {
        let _ = ctx;
        Some(Arc::new(TailscaleEndpoint::new(ir)))
    }
}
