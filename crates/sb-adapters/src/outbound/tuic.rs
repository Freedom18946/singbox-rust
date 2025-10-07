//! TUIC outbound adapter
//!
//! Wraps the sb-core TUIC implementation to provide the OutboundConnector interface.

use crate::outbound::prelude::*;

/// TUIC outbound connector adapter
#[derive(Debug, Clone, Default)]
pub struct TuicConnector {
    _config: Option<()>,
}

impl TuicConnector {
    /// Create new TUIC connector (stub - requires out_tuic feature in sb-core)
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl OutboundConnector for TuicConnector {
    fn name(&self) -> &'static str {
        "tuic"
    }

    async fn start(&self) -> Result<()> {
        Err(AdapterError::NotImplemented {
            what: "TUIC requires out_tuic feature in sb-core",
        })
    }

    async fn dial(&self, _target: Target, _opts: DialOpts) -> Result<BoxedStream> {
        Err(AdapterError::NotImplemented {
            what: "TUIC requires out_tuic feature in sb-core",
        })
    }
}
