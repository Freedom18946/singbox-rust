//! DNS outbound connector implementation
//!
//! Provides DNS resolution as an outbound service, allowing routing
//! DNS queries through specific servers or configurations.

use crate::outbound::prelude::*;

/// DNS outbound connector
#[derive(Debug, Clone)]
pub struct DnsConnector {
    _config: Option<()>, // Placeholder
}

impl Default for DnsConnector {
    fn default() -> Self {
        Self { _config: None }
    }
}

#[async_trait]
impl OutboundConnector for DnsConnector {
    fn name(&self) -> &'static str {
        "dns"
    }

    async fn start(&self) -> Result<()> {
        Err(AdapterError::NotImplemented { what: "adapter-dns" })
    }

    async fn dial(&self, _target: Target, _opts: DialOpts) -> Result<BoxedStream> {
        Err(AdapterError::NotImplemented { what: "DNS dial" })
    }
}