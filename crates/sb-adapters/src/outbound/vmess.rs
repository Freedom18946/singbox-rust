//! VMess outbound connector implementation
//!
//! This module provides VMess protocol support for outbound connections.
//! VMess is a stateless protocol used by V2Ray.

use crate::outbound::prelude::*;

/// VMess outbound connector
#[derive(Debug, Clone)]
pub struct VmessConnector {
    _config: Option<()>, // Placeholder
}

impl Default for VmessConnector {
    fn default() -> Self {
        Self { _config: None }
    }
}

#[async_trait]
impl OutboundConnector for VmessConnector {
    fn name(&self) -> &'static str {
        "vmess"
    }

    async fn start(&self) -> Result<()> {
        Err(AdapterError::NotImplemented { what: "adapter-vmess" })
    }

    async fn dial(&self, _target: Target, _opts: DialOpts) -> Result<BoxedStream> {
        Err(AdapterError::NotImplemented { what: "VMess dial" })
    }
}