//! Hysteria2 outbound connector implementation
//!
//! Wraps the sb-core Hysteria2 outbound to expose a unified adapter interface.

use crate::outbound::prelude::*;
#[cfg(feature = "adapter-hysteria2")]
use sb_core::outbound::types::OutboundTcp;

/// Adapter configuration for Hysteria2 outbound
#[derive(Debug, Clone)]
pub struct Hysteria2AdapterConfig {
    pub server: String,
    pub port: u16,
    pub password: String,
    pub skip_cert_verify: bool,
    pub sni: Option<String>,
    pub alpn: Option<Vec<String>>,
    pub congestion_control: Option<String>,
    pub up_mbps: Option<u32>,
    pub down_mbps: Option<u32>,
    pub obfs: Option<String>,
    pub salamander: Option<String>,
}

impl Default for Hysteria2AdapterConfig {
    fn default() -> Self {
        Self {
            server: "127.0.0.1".to_string(),
            port: 443,
            password: "password".to_string(),
            skip_cert_verify: true,
            sni: Some("example.com".to_string()),
            alpn: Some(vec!["h3".to_string(), "hysteria2".to_string()]),
            congestion_control: Some("bbr".to_string()),
            up_mbps: None,
            down_mbps: None,
            obfs: None,
            salamander: None,
        }
    }
}

/// Hysteria2 outbound connector
#[derive(Debug, Clone)]
#[derive(Default)]
pub struct Hysteria2Connector {
    cfg: Hysteria2AdapterConfig,
}


impl Hysteria2Connector {
    pub fn new(cfg: Hysteria2AdapterConfig) -> Self {
        Self { cfg }
    }

    #[cfg(feature = "adapter-hysteria2")]
    /// Create a UDP session for UDP relay
    pub async fn create_udp_session(
        &self,
    ) -> Result<sb_core::outbound::hysteria2::Hysteria2UdpSession> {
        use sb_core::outbound::hysteria2::Hysteria2Config;
        use sb_core::outbound::hysteria2::Hysteria2Outbound;

        let core_cfg = Hysteria2Config {
            server: self.cfg.server.clone(),
            port: self.cfg.port,
            password: self.cfg.password.clone(),
            congestion_control: self.cfg.congestion_control.clone(),
            up_mbps: self.cfg.up_mbps,
            down_mbps: self.cfg.down_mbps,
            obfs: self.cfg.obfs.clone(),
            skip_cert_verify: self.cfg.skip_cert_verify,
            sni: self.cfg.sni.clone(),
            alpn: self.cfg.alpn.clone(),
            salamander: self.cfg.salamander.clone(),
            brutal: None,
            tls_ca_paths: Vec::new(),
            tls_ca_pem: Vec::new(),
            zero_rtt_handshake: false,
        };

        let core =
            Hysteria2Outbound::new(core_cfg).map_err(|e| AdapterError::Other(e.to_string()))?;

        // Get connection
        let connection = core.get_connection().await.map_err(AdapterError::Io)?;

        // Create UDP session
        core.create_udp_session(&connection)
            .await
            .map_err(AdapterError::Io)
    }
}

#[async_trait]
impl OutboundConnector for Hysteria2Connector {
    fn name(&self) -> &'static str {
        "hysteria2"
    }

    async fn start(&self) -> Result<()> {
        #[cfg(not(feature = "adapter-hysteria2"))]
        return Err(AdapterError::NotImplemented {
            what: "adapter-hysteria2",
        });

        #[cfg(feature = "adapter-hysteria2")]
        Ok(())
    }

    async fn dial(&self, target: Target, _opts: DialOpts) -> Result<BoxedStream> {
        #[cfg(not(feature = "adapter-hysteria2"))]
        return Err(AdapterError::NotImplemented {
            what: "adapter-hysteria2",
        });

        #[cfg(feature = "adapter-hysteria2")]
        {
            if target.kind != TransportKind::Tcp {
                return Err(AdapterError::Protocol(
                    "Hysteria2 outbound only supports TCP".to_string(),
                ));
            }

            let _span = crate::outbound::span_dial("hysteria2", &target);

            // Bridge to sb-core implementation
            let core_cfg = sb_core::outbound::hysteria2::Hysteria2Config {
                server: self.cfg.server.clone(),
                port: self.cfg.port,
                password: self.cfg.password.clone(),
                congestion_control: self.cfg.congestion_control.clone(),
                up_mbps: self.cfg.up_mbps,
                down_mbps: self.cfg.down_mbps,
                obfs: self.cfg.obfs.clone(),
                skip_cert_verify: self.cfg.skip_cert_verify,
                sni: self.cfg.sni.clone(),
                alpn: self.cfg.alpn.clone(),
                salamander: self.cfg.salamander.clone(),
                brutal: None,
                tls_ca_paths: Vec::new(),
                tls_ca_pem: Vec::new(),
                zero_rtt_handshake: false,
            };

            let core = sb_core::outbound::hysteria2::Hysteria2Outbound::new(core_cfg)
                .map_err(|e| AdapterError::Other(e.to_string()))?;

            let hp = sb_core::outbound::types::HostPort::new(target.host.clone(), target.port);
            let quic_stream = core.connect(&hp).await.map_err(AdapterError::Io)?;

            Ok(Box::new(quic_stream) as BoxedStream)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hysteria2_connector_name() {
        let c = Hysteria2Connector::new(Hysteria2AdapterConfig::default());
        assert_eq!(c.name(), "hysteria2");
    }
}
