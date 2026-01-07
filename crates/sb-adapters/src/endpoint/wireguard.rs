//! WireGuard endpoint builder.
//!
//! This is a thin wrapper around the sb-core WireGuard endpoint implementation
//! so the adapter registry can instantiate it directly.

use std::sync::Arc;

use sb_config::ir::{EndpointIR, EndpointType};
use sb_core::endpoint::{Endpoint, EndpointContext};

pub fn build_wireguard_endpoint(
    ir: &EndpointIR,
    ctx: &EndpointContext,
) -> Option<Arc<dyn Endpoint>> {
    if ir.ty != EndpointType::Wireguard {
        return None;
    }

    sb_core::endpoint::wireguard::build_wireguard_endpoint(ir, ctx)
}
