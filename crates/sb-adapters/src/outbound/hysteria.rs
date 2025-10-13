//! Hysteria v1 outbound connector implementation

use crate::outbound::prelude::*;

#[cfg(feature = "adapter-hysteria")]
use sb_core::outbound::hysteria::{HysteriaV1Config, HysteriaV1Outbound};
#[cfg(feature = "adapter-hysteria")]
use sb_core::outbound::types::{HostPort, OutboundTcp};

/// Hysteria v1 adapter configuration
#[derive(Debug, Clone)]
pub struct HysteriaAdapterConfig {
    pub server: String,
    pub port: u16,
    pub protocol: String,
    pub up_mbps: u32,
    pub down_mbps: u32,
    pub obfs: Option<String>,
    pub auth: Option<String>,
    pub alpn: Vec<String>,
    pub recv_window_conn: Option<u64>,
    pub recv_window: Option<u64>,
    pub skip_cert_verify: bool,
    pub sni: Option<String>,
}

impl Default for HysteriaAdapterConfig {
    fn default() -> Self {
        Self {
            server: "127.0.0.1".to_string(),
            port: 443,
            protocol: "udp".to_string(),
            up_mbps: 10,
            down_mbps: 50,
            obfs: None,
            auth: None,
            alpn: vec!["hysteria".to_string()],
            recv_window_conn: None,
            recv_window: None,
            skip_cert_verify: false,
            sni: None,
        }
    }
}

/// Hysteria v1 outbound connector
#[derive(Debug, Clone)]
pub struct HysteriaConnector {
    cfg: HysteriaAdapterConfig,
}

impl Default for HysteriaConnector {
    fn default() -> Self {
        Self {
            cfg: HysteriaAdapterConfig::default(),
        }
    }
}

impl HysteriaConnector {
    pub fn new(cfg: HysteriaAdapterConfig) -> Self {
        Self { cfg }
    }
}

#[async_trait]
impl OutboundConnector for HysteriaConnector {
    fn name(&self) -> &'static str {
        "hysteria"
    }

    async fn start(&self) -> Result<()> {
        #[cfg(not(feature = "adapter-hysteria"))]
        return Err(AdapterError::NotImplemented {
            what: "adapter-hysteria",
        });

        #[cfg(feature = "adapter-hysteria")]
        Ok(())
    }

    async fn dial(&self, target: Target, _opts: DialOpts) -> Result<BoxedStream> {
        #[cfg(not(feature = "adapter-hysteria"))]
        return Err(AdapterError::NotImplemented {
            what: "adapter-hysteria",
        });

        #[cfg(feature = "adapter-hysteria")]
        {
            if target.kind != TransportKind::Tcp {
                return Err(AdapterError::Protocol(
                    "Hysteria v1 outbound only supports TCP".to_string(),
                ));
            }

            let _span = crate::outbound::span_dial("hysteria", &target);

            // Bridge to sb-core implementation
            let core_cfg = HysteriaV1Config {
                server: self.cfg.server.clone(),
                port: self.cfg.port,
                protocol: self.cfg.protocol.clone(),
                up_mbps: self.cfg.up_mbps,
                down_mbps: self.cfg.down_mbps,
                obfs: self.cfg.obfs.clone(),
                auth: self.cfg.auth.clone(),
                alpn: self.cfg.alpn.clone(),
                recv_window_conn: self.cfg.recv_window_conn,
                recv_window: self.cfg.recv_window,
                skip_cert_verify: self.cfg.skip_cert_verify,
                sni: self.cfg.sni.clone(),
            };

            let core = HysteriaV1Outbound::new(core_cfg)
                .map_err(|e| AdapterError::Other(e.to_string()))?;

            let hp = HostPort::new(target.host.clone(), target.port);
            let stream = core.connect(&hp).await.map_err(AdapterError::Io)?;

            Ok(Box::new(stream) as BoxedStream)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hysteria_connector_name() {
        let c = HysteriaConnector::new(HysteriaAdapterConfig::default());
        assert_eq!(c.name(), "hysteria");
    }
}
