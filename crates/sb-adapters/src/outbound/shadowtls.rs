//! ShadowTLS outbound connector adapter
//!
//! This adapter wraps the sb-core ShadowTLS outbound implementation and exposes
//! a unified `OutboundConnector` interface for the adapters crate.

use crate::outbound::prelude::*;
#[cfg(feature = "adapter-shadowtls")]
use sb_core::outbound::types::OutboundTcp;

/// Configuration for ShadowTLS outbound adapter
#[derive(Debug, Clone)]
pub struct ShadowTlsAdapterConfig {
    /// Decoy TLS server hostname or IP
    pub server: String,
    /// Decoy TLS server port (usually 443)
    pub port: u16,
    /// SNI to present during TLS handshake
    pub sni: String,
    /// Optional ALPN protocol (e.g., "h2", "http/1.1")
    pub alpn: Option<String>,
    /// Skip certificate verification (INSECURE; for testing only)
    pub skip_cert_verify: bool,
}

impl Default for ShadowTlsAdapterConfig {
    fn default() -> Self {
        Self {
            server: "127.0.0.1".to_string(),
            port: 443,
            sni: "example.com".to_string(),
            alpn: Some("http/1.1".to_string()),
            skip_cert_verify: false,
        }
    }
}

/// ShadowTLS outbound adapter connector
#[derive(Debug, Clone)]
pub struct ShadowTlsConnector {
    cfg: ShadowTlsAdapterConfig,
}

impl ShadowTlsConnector {
    pub fn new(cfg: ShadowTlsAdapterConfig) -> Self {
        Self { cfg }
    }
}

#[async_trait]
impl OutboundConnector for ShadowTlsConnector {
    fn name(&self) -> &'static str {
        "shadowtls"
    }

    async fn start(&self) -> Result<()> {
        #[cfg(not(feature = "adapter-shadowtls"))]
        return Err(AdapterError::NotImplemented {
            what: "adapter-shadowtls",
        });

        #[cfg(feature = "adapter-shadowtls")]
        Ok(())
    }

    async fn dial(&self, target: Target, _opts: DialOpts) -> Result<BoxedStream> {
        #[cfg(not(feature = "adapter-shadowtls"))]
        return Err(AdapterError::NotImplemented {
            what: "adapter-shadowtls",
        });

        #[cfg(feature = "adapter-shadowtls")]
        {
            if target.kind != TransportKind::Tcp {
                return Err(AdapterError::Protocol(
                    "ShadowTLS outbound only supports TCP".to_string(),
                ));
            }

            let _span = crate::outbound::span_dial("shadowtls", &target);

            // Bridge to sb-core implementation
            let core_cfg = sb_core::outbound::shadowtls::ShadowTlsConfig {
                server: self.cfg.server.clone(),
                port: self.cfg.port,
                sni: self.cfg.sni.clone(),
                alpn: self.cfg.alpn.clone(),
                skip_cert_verify: self.cfg.skip_cert_verify,
            };

            let core = sb_core::outbound::shadowtls::ShadowTlsOutbound::new(core_cfg)
                .map_err(|e| AdapterError::Other(e.to_string()))?;

            let hp = sb_core::outbound::types::HostPort::new(target.host.clone(), target.port);
            let tls_stream = core.connect(&hp).await.map_err(AdapterError::Io)?;

            Ok(Box::new(tls_stream) as BoxedStream)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shadowtls_connector_name() {
        let c = ShadowTlsConnector::new(ShadowTlsAdapterConfig::default());
        assert_eq!(c.name(), "shadowtls");
    }
}
