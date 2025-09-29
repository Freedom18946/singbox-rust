//! TUIC protocol outbound connector implementation
//!
//! TUIC (The Ultimate Internet Connector) is a QUIC-based proxy protocol
//! that provides UDP relay and multiplexing features with authentication
//! and session management.

use crate::outbound::prelude::*;

/// TUIC outbound connector
#[derive(Debug, Clone)]
pub struct TuicConnector {
    _config: Option<()>, // Placeholder
}

impl Default for TuicConnector {
    fn default() -> Self {
        Self { _config: None }
    }
}

#[async_trait]
impl OutboundConnector for TuicConnector {
    fn name(&self) -> &'static str {
        "tuic"
    }

    async fn start(&self) -> Result<()> {
        Err(AdapterError::NotImplemented {
            what: "adapter-tuic",
        })
    }

    async fn dial(&self, _target: Target, _opts: DialOpts) -> Result<BoxedStream> {
        Err(AdapterError::NotImplemented { what: "TUIC dial" })
    }
}
