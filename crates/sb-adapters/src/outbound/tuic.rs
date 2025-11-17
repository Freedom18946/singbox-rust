//! TUIC outbound adapter
//!
//! Wraps the sb-core TUIC implementation to provide the OutboundConnector interface.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

use crate::outbound::prelude::*;
#[cfg(feature = "adapter-tuic")]
use sb_core::outbound::types::OutboundTcp;

/// Adapter configuration for TUIC outbound
#[derive(Debug, Clone)]
pub struct TuicAdapterConfig {
    pub server: String,
    pub port: u16,
    pub uuid: uuid::Uuid,
    pub token: String,
    pub password: Option<String>,
    pub congestion_control: Option<String>,
    pub alpn: Option<String>,
    pub skip_cert_verify: bool,
    pub udp_relay_mode: TuicUdpRelayMode,
    pub udp_over_stream: bool,
}

/// UDP relay mode for TUIC
#[derive(Debug, Clone, Default)]
pub enum TuicUdpRelayMode {
    #[default]
    Native,
    Quic,
}

impl Default for TuicAdapterConfig {
    fn default() -> Self {
        Self {
            server: "127.0.0.1".to_string(),
            port: 443,
            uuid: uuid::Uuid::new_v4(),
            token: "password".to_string(),
            password: None,
            congestion_control: Some("cubic".to_string()),
            alpn: Some("tuic".to_string()),
            skip_cert_verify: false,
            udp_relay_mode: TuicUdpRelayMode::Native,
            udp_over_stream: false,
        }
    }
}

/// TUIC outbound connector adapter
#[derive(Debug, Clone, Default)]
pub struct TuicConnector {
    cfg: TuicAdapterConfig,
}

impl TuicConnector {
    /// Create new TUIC connector with configuration
    pub fn new(cfg: TuicAdapterConfig) -> Self {
        Self { cfg }
    }

    #[cfg(feature = "adapter-tuic")]
    /// Create a UDP transport for UDP relay
    pub async fn create_udp_transport(&self) -> Result<sb_core::outbound::tuic::TuicUdpTransport> {
        use sb_core::outbound::tuic::{TuicConfig, TuicOutbound, UdpRelayMode};

        let core_cfg = TuicConfig {
            server: self.cfg.server.clone(),
            port: self.cfg.port,
            uuid: self.cfg.uuid,
            token: self.cfg.token.clone(),
            password: self.cfg.password.clone(),
            congestion_control: self.cfg.congestion_control.clone(),
            alpn: self.cfg.alpn.as_ref().map(|s| {
                s.split(',')
                    .map(|x| x.trim().to_string())
                    .filter(|x| !x.is_empty())
                    .collect()
            }),
            skip_cert_verify: self.cfg.skip_cert_verify,
            sni: None,
            tls_ca_paths: Vec::new(),
            tls_ca_pem: Vec::new(),
            udp_relay_mode: match self.cfg.udp_relay_mode {
                TuicUdpRelayMode::Native => UdpRelayMode::Native,
                TuicUdpRelayMode::Quic => UdpRelayMode::Quic,
            },
            udp_over_stream: self.cfg.udp_over_stream,
            zero_rtt_handshake: false,
        };

        let core = TuicOutbound::new(core_cfg).map_err(|e| AdapterError::Other(e.to_string()))?;

        // Create UDP transport
        core.create_udp_transport().await.map_err(AdapterError::Io)
    }
}

#[async_trait]
impl OutboundConnector for TuicConnector {
    fn name(&self) -> &'static str {
        "tuic"
    }

    async fn start(&self) -> Result<()> {
        #[cfg(not(feature = "adapter-tuic"))]
        return Err(AdapterError::NotImplemented {
            what: "adapter-tuic feature not enabled",
        });

        #[cfg(feature = "adapter-tuic")]
        Ok(())
    }

    async fn dial(&self, target: Target, _opts: DialOpts) -> Result<BoxedStream> {
        #[cfg(not(feature = "adapter-tuic"))]
        return Err(AdapterError::NotImplemented {
            what: "adapter-tuic feature not enabled",
        });

        #[cfg(feature = "adapter-tuic")]
        {
            if target.kind != TransportKind::Tcp {
                return Err(AdapterError::Protocol(
                    "TUIC outbound only supports TCP (UDP support via create_udp_transport)"
                        .to_string(),
                ));
            }

            let _span = crate::outbound::span_dial("tuic", &target);

            // Bridge to sb-core implementation
            let core_cfg = sb_core::outbound::tuic::TuicConfig {
                server: self.cfg.server.clone(),
                port: self.cfg.port,
                uuid: self.cfg.uuid,
                token: self.cfg.token.clone(),
                password: self.cfg.password.clone(),
                congestion_control: self.cfg.congestion_control.clone(),
                alpn: self.cfg.alpn.as_ref().map(|s| {
                    s.split(',')
                        .map(|x| x.trim().to_string())
                        .filter(|x| !x.is_empty())
                        .collect()
                }),
                skip_cert_verify: self.cfg.skip_cert_verify,
                sni: None,
                tls_ca_paths: Vec::new(),
                tls_ca_pem: Vec::new(),
                udp_relay_mode: match self.cfg.udp_relay_mode {
                    TuicUdpRelayMode::Native => sb_core::outbound::tuic::UdpRelayMode::Native,
                    TuicUdpRelayMode::Quic => sb_core::outbound::tuic::UdpRelayMode::Quic,
                },
                udp_over_stream: self.cfg.udp_over_stream,
                zero_rtt_handshake: false,
            };

            let core = sb_core::outbound::tuic::TuicOutbound::new(core_cfg)
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
    fn test_tuic_connector_name() {
        let c = TuicConnector::new(TuicAdapterConfig::default());
        assert_eq!(c.name(), "tuic");
    }

    #[test]
    fn test_tuic_config_default() {
        let cfg = TuicAdapterConfig::default();
        assert_eq!(cfg.server, "127.0.0.1");
        assert_eq!(cfg.port, 443);
        assert_eq!(cfg.token, "password");
        assert!(!cfg.skip_cert_verify);
        assert!(!cfg.udp_over_stream);
    }

    #[test]
    fn test_tuic_config_with_custom_values() {
        let uuid = uuid::Uuid::new_v4();
        let cfg = TuicAdapterConfig {
            server: "example.com".to_string(),
            port: 8443,
            uuid,
            token: "custom-token".to_string(),
            password: Some("custom-password".to_string()),
            congestion_control: Some("bbr".to_string()),
            alpn: Some("h3".to_string()),
            skip_cert_verify: true,
            udp_relay_mode: TuicUdpRelayMode::Quic,
            udp_over_stream: true,
        };

        assert_eq!(cfg.server, "example.com");
        assert_eq!(cfg.port, 8443);
        assert_eq!(cfg.uuid, uuid);
        assert_eq!(cfg.token, "custom-token");
        assert_eq!(cfg.password, Some("custom-password".to_string()));
        assert_eq!(cfg.congestion_control, Some("bbr".to_string()));
        assert_eq!(cfg.alpn, Some("h3".to_string()));
        assert!(cfg.skip_cert_verify);
        assert!(matches!(cfg.udp_relay_mode, TuicUdpRelayMode::Quic));
        assert!(cfg.udp_over_stream);
    }

    #[test]
    fn test_tuic_udp_relay_mode_default() {
        let mode = TuicUdpRelayMode::default();
        assert!(matches!(mode, TuicUdpRelayMode::Native));
    }

    #[test]
    fn test_tuic_connector_creation() {
        let cfg = TuicAdapterConfig {
            server: "test.example.com".to_string(),
            port: 9443,
            uuid: uuid::Uuid::new_v4(),
            token: "test-token".to_string(),
            password: None,
            congestion_control: Some("cubic".to_string()),
            alpn: Some("tuic".to_string()),
            skip_cert_verify: false,
            udp_relay_mode: TuicUdpRelayMode::Native,
            udp_over_stream: false,
        };

        let connector = TuicConnector::new(cfg.clone());
        assert_eq!(connector.cfg.server, cfg.server);
        assert_eq!(connector.cfg.port, cfg.port);
        assert_eq!(connector.cfg.token, cfg.token);
    }

    #[test]
    fn test_tuic_connector_default() {
        let connector = TuicConnector::default();
        assert_eq!(connector.name(), "tuic");
        assert_eq!(connector.cfg.server, "127.0.0.1");
        assert_eq!(connector.cfg.port, 443);
    }

    #[cfg(feature = "adapter-tuic")]
    #[tokio::test]
    async fn test_tuic_connector_start_with_feature() {
        let connector = TuicConnector::default();
        let result = connector.start().await;
        assert!(result.is_ok());
    }

    #[cfg(not(feature = "adapter-tuic"))]
    #[tokio::test]
    async fn test_tuic_connector_start_without_feature() {
        let connector = TuicConnector::default();
        let result = connector.start().await;
        assert!(result.is_err());

        if let Err(AdapterError::NotImplemented { what }) = result {
            assert!(what.contains("adapter-tuic"));
        } else {
            panic!("Expected NotImplemented error");
        }
    }

    #[test]
    fn test_tuic_config_validation_server() {
        let cfg = TuicAdapterConfig {
            server: "".to_string(),
            ..TuicAdapterConfig::default()
        };

        // Empty server should still create config (validation happens at connection time)
        assert_eq!(cfg.server, "");
    }

    #[test]
    fn test_tuic_config_validation_port() {
        let cfg = TuicAdapterConfig {
            port: 0,
            ..TuicAdapterConfig::default()
        };

        // Port 0 should still create config (validation happens at connection time)
        assert_eq!(cfg.port, 0);
    }

    #[test]
    fn test_tuic_config_clone() {
        let cfg1 = TuicAdapterConfig::default();
        let cfg2 = cfg1.clone();

        assert_eq!(cfg1.server, cfg2.server);
        assert_eq!(cfg1.port, cfg2.port);
        assert_eq!(cfg1.token, cfg2.token);
    }

    #[test]
    fn test_tuic_connector_clone() {
        let connector1 = TuicConnector::default();
        let connector2 = connector1.clone();

        assert_eq!(connector1.name(), connector2.name());
        assert_eq!(connector1.cfg.server, connector2.cfg.server);
    }

    #[test]
    fn test_tuic_config_debug() {
        let cfg = TuicAdapterConfig::default();
        let debug_str = format!("{:?}", cfg);

        // Should contain key fields
        assert!(debug_str.contains("server"));
        assert!(debug_str.contains("port"));
        assert!(debug_str.contains("token"));
    }

    #[test]
    fn test_tuic_udp_relay_mode_variants() {
        let native = TuicUdpRelayMode::Native;
        let quic = TuicUdpRelayMode::Quic;

        // Test that variants are different
        assert!(matches!(native, TuicUdpRelayMode::Native));
        assert!(matches!(quic, TuicUdpRelayMode::Quic));
    }
}
