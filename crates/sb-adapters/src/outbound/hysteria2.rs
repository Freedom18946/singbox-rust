//! Hysteria2 outbound connector implementation
//!
//! Hysteria2 is a QUIC-based proxy protocol designed for high performance
//! and congestion control optimization.

use crate::outbound::prelude::*;

/// Hysteria2 outbound connector
#[derive(Debug, Clone)]
#[derive(Default)]
pub struct Hysteria2Connector {
    _config: Option<()>, // Placeholder
}


#[async_trait]
impl OutboundConnector for Hysteria2Connector {
    fn name(&self) -> &'static str {
        "hysteria2"
    }

    async fn start(&self) -> Result<()> {
        Err(AdapterError::NotImplemented {
            what: "adapter-hysteria2",
        })
    }

    async fn dial(&self, _target: Target, _opts: DialOpts) -> Result<BoxedStream> {
        Err(AdapterError::NotImplemented {
            what: "Hysteria2 dial",
        })
    }
}
