//! VLESS outbound connector implementation
//!
//! VLESS is a stateless, lightweight protocol that reduces overhead compared to VMess.
//! It supports multiple flow control modes and encryption options.

use crate::outbound::prelude::*;

/// VLESS outbound connector
#[derive(Debug, Clone)]
pub struct VlessConnector {
    _config: Option<()>, // Placeholder
}

impl Default for VlessConnector {
    fn default() -> Self {
        Self { _config: None }
    }
}

#[async_trait]
impl OutboundConnector for VlessConnector {
    fn name(&self) -> &'static str {
        "vless"
    }

    async fn start(&self) -> Result<()> {
        Err(AdapterError::NotImplemented { what: "adapter-vless" })
    }

    async fn dial(&self, _target: Target, _opts: DialOpts) -> Result<BoxedStream> {
        Err(AdapterError::NotImplemented { what: "VLESS dial" })
    }
}