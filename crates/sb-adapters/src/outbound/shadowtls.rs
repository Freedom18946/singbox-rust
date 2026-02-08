//! ShadowTLS outbound connector adapter
//!
//! Fully self-contained ShadowTLS implementation using sb-tls for TLS configuration.
//! No dependency on sb-core's protocol stack.

use crate::outbound::prelude::*;

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
    /// Optional uTLS fingerprint name for outbound TLS layer.
    pub utls_fingerprint: Option<String>,
}

impl Default for ShadowTlsAdapterConfig {
    fn default() -> Self {
        Self {
            server: "127.0.0.1".to_string(),
            port: 443,
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
    #[cfg(feature = "adapter-shadowtls")]
    tls_config: std::sync::Arc<rustls::ClientConfig>,
}

impl ShadowTlsConnector {
    pub fn new(cfg: ShadowTlsAdapterConfig) -> Self {
        #[cfg(feature = "adapter-shadowtls")]
        {
            let tls_config = Self::build_tls_config(&cfg);
            Self { cfg, tls_config }
        }
        #[cfg(not(feature = "adapter-shadowtls"))]
        Self { cfg }
    }

    #[cfg(feature = "adapter-shadowtls")]
    fn build_tls_config(cfg: &ShadowTlsAdapterConfig) -> std::sync::Arc<rustls::ClientConfig> {
        use std::sync::Arc;

        sb_tls::ensure_crypto_provider();

        let insecure_env = std::env::var("SB_STL_ALLOW_INSECURE")
            .ok()
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
        let insecure = cfg.skip_cert_verify || insecure_env;

        let alpn_list: Option<Vec<String>> = cfg.alpn.as_ref().map(|s| {
            s.split(',')
                .map(|x| x.trim().to_string())
                .filter(|x| !x.is_empty())
                .collect()
        });

        #[cfg(feature = "tls_reality")]
        if let Some(fp_name) = cfg.utls_fingerprint.as_deref() {
            if let Ok(fp) = fp_name.parse::<sb_tls::UtlsFingerprint>() {
                let mut utls_cfg = sb_tls::UtlsConfig::new(cfg.sni.clone())
                    .with_fingerprint(fp)
                    .with_insecure(insecure);
                if let Some(alpn) = alpn_list.clone() {
                    utls_cfg = utls_cfg.with_alpn(alpn);
                }
                let roots = sb_tls::global::base_root_store();
                return utls_cfg.build_client_config_with_roots(roots);
            }
        }

        let roots = sb_tls::global::base_root_store();
        let mut tls_config = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();

        if insecure {
            tracing::warn!("ShadowTLS: insecure mode enabled, certificate verification disabled");
            let v = sb_tls::danger::NoVerify::new();
            tls_config
                .dangerous()
                .set_certificate_verifier(Arc::new(v));
        }

        if let Some(alpn) = &alpn_list {
            tls_config.alpn_protocols = alpn.iter().map(|p| p.as_bytes().to_vec()).collect();
        }

        Arc::new(tls_config)
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
            use tokio::io::AsyncWriteExt;
            use tokio::net::TcpStream;

            if target.kind != TransportKind::Tcp {
                return Err(AdapterError::Protocol(
                    "ShadowTLS outbound only supports TCP".to_string(),
                ));
            }

            let _span = crate::outbound::span_dial("shadowtls", &target);

            #[cfg(feature = "metrics")]
            let start_time = sb_metrics::start_adapter_timer();

            // Connect to the ShadowTLS server (decoy)
            let tcp_stream =
                TcpStream::connect((self.cfg.server.as_str(), self.cfg.port))
                    .await
                    .map_err(|e| AdapterError::Network(format!("ShadowTLS TCP connect failed: {}", e)))?;

            // Establish TLS connection with specified SNI
            let server_name =
                rustls::pki_types::ServerName::try_from(self.cfg.sni.clone()).map_err(|e| {
                    AdapterError::Protocol(format!("Invalid SNI: {}", e))
                })?;

            let connector = tokio_rustls::TlsConnector::from(self.tls_config.clone());
            let mut tls_stream = connector
                .connect(server_name, tcp_stream)
                .await
                .map_err(|e| AdapterError::Network(format!("ShadowTLS TLS handshake failed: {}", e)))?;

            // Tunneling header: CONNECT to target through the TLS channel
            let connect_line = format!(
                "CONNECT {}:{} HTTP/1.1\r\nHost: {}:{}\r\n\r\n",
                target.host, target.port, target.host, target.port
            );
            tls_stream
                .write_all(connect_line.as_bytes())
                .await
                .map_err(|e| AdapterError::Network(format!("tunnel header write failed: {}", e)))?;
            tls_stream
                .flush()
                .await
                .map_err(|e| AdapterError::Network(format!("tunnel header flush failed: {}", e)))?;

            #[cfg(feature = "metrics")]
            {
                sb_metrics::record_adapter_dial("shadowtls", start_time, Ok::<(), &dyn core::fmt::Display>(()));
            }

            tracing::debug!(
                server = %self.cfg.server,
                sni = %self.cfg.sni,
                target = %format!("{}:{}", target.host, target.port),
                "ShadowTLS tunnel established"
            );

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
