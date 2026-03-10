//! ShadowTLS outbound connector adapter.
//!
//! IMPORTANT:
//! The previous implementation modeled ShadowTLS as a standalone "TLS + HTTP
//! CONNECT tunnel". That does not match sing-box ShadowTLS semantics, where
//! ShadowTLS acts as a transport wrapper/detour rather than a leaf protocol
//! that serializes the final destination itself.
//!
//! Until transport-wrapper chaining is implemented, this adapter remains
//! registrable but rejects standalone leaf dialing at runtime so parity
//! evidence is not contaminated by the legacy tunnel model.

use crate::outbound::prelude::*;

/// Configuration for ShadowTLS outbound adapter
#[derive(Debug, Clone)]
pub struct ShadowTlsAdapterConfig {
    /// Decoy TLS server hostname or IP
    pub server: String,
    /// Decoy TLS server port (usually 443)
    pub port: u16,
    /// ShadowTLS protocol version.
    pub version: u8,
    /// Shared password for ShadowTLS authentication.
    pub password: String,
    /// SNI to present during TLS handshake
    pub sni: String,
    /// Optional ALPN protocol (e.g., "h2", "http/1.1")
    pub alpn: Option<String>,
    /// Skip certificate verification (INSECURE; for testing only)
    pub skip_cert_verify: bool,
    /// Optional uTLS fingerprint name for outbound TLS layer.
    pub utls_fingerprint: Option<String>,
}

impl Default for ShadowTlsAdapterConfig {
    fn default() -> Self {
        Self {
            server: "127.0.0.1".to_string(),
            port: 443,
            version: 1,
            password: String::new(),
            sni: "example.com".to_string(),
            alpn: Some("http/1.1".to_string()),
            skip_cert_verify: false,
            utls_fingerprint: None,
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
            tracing::warn!(
                server = %self.cfg.server,
                port = self.cfg.port,
                version = self.cfg.version,
                sni = %self.cfg.sni,
                target = %format!("{}:{}", target.host, target.port),
                "shadowtls standalone leaf dial rejected; transport-wrapper remodel is required"
            );
            Err(AdapterError::Protocol(
                format!(
                    "ShadowTLS standalone leaf dialing is disabled for version {}: sing-box parity requires a transport-wrapper/detour model, not the legacy TLS+CONNECT tunnel",
                    self.cfg.version
                ),
            ))
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
