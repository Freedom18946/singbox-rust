use super::{Endpoint, StartStage};
use sb_config::ir::{EndpointIR, EndpointType};
use std::sync::Arc;

pub struct TailscaleEndpoint {
    tag: String,
}

impl TailscaleEndpoint {
    pub fn new(ir: &EndpointIR) -> Self {
        Self {
            tag: ir.tag.clone().unwrap_or_else(|| "tailscale".to_string()),
        }
    }
}

impl Endpoint for TailscaleEndpoint {
    fn endpoint_type(&self) -> &str {
        "tailscale"
    }

    fn tag(&self) -> &str {
        &self.tag
    }

    fn start(&self, stage: StartStage) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        match stage {
            StartStage::Initialize => {
                tracing::debug!(tag = self.tag, "Initializing Tailscale endpoint");
            }
            StartStage::Start => {
                tracing::info!(tag = self.tag, "Starting Tailscale endpoint");
            }
            StartStage::PostStart => {}
            StartStage::Started => {}
        }
        Ok(())
    }

    fn close(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        tracing::info!(tag = self.tag, "Closing Tailscale endpoint");
        Ok(())
    }
}

pub fn build_tailscale_endpoint(
    ir: &EndpointIR,
    _ctx: &super::EndpointContext,
) -> Option<Arc<dyn Endpoint>> {
    if ir.ty != EndpointType::Tailscale {
        return None;
    }
    Some(Arc::new(TailscaleEndpoint::new(ir)))
}
