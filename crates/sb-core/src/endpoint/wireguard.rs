use super::{Endpoint, StartStage};
use sb_config::ir::{EndpointIR, EndpointType};
use std::sync::Arc;

pub struct WireGuardEndpoint {
    tag: String,
}

impl WireGuardEndpoint {
    pub fn new(ir: &EndpointIR) -> Self {
        Self {
            tag: ir.tag.clone().unwrap_or_else(|| "wireguard".to_string()),
        }
    }
}

impl Endpoint for WireGuardEndpoint {
    fn endpoint_type(&self) -> &str {
        "wireguard"
    }

    fn tag(&self) -> &str {
        &self.tag
    }

    fn start(&self, stage: StartStage) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        match stage {
            StartStage::Initialize => {
                tracing::debug!(tag = self.tag, "Initializing WireGuard endpoint");
            }
            StartStage::Start => {
                tracing::info!(tag = self.tag, "Starting WireGuard endpoint");
                // Note: WireGuard data plane is currently handled by WireGuardOutbound.
                // This endpoint implementation manages lifecycle and future control plane integration.
            }
            StartStage::PostStart => {}
            StartStage::Started => {}
        }
        Ok(())
    }

    fn close(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        tracing::info!(tag = self.tag, "Closing WireGuard endpoint");
        Ok(())
    }
}

pub fn build_wireguard_endpoint(
    ir: &EndpointIR,
    _ctx: &super::EndpointContext,
) -> Option<Arc<dyn Endpoint>> {
    if ir.ty != EndpointType::Wireguard {
        return None;
    }
    Some(Arc::new(WireGuardEndpoint::new(ir)))
}
