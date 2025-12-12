//! ShadowTLS (v2/v3) outbound implementation
//!
//! Provides TLS1.3 masquerading by establishing real TLS connections to decoy servers
//! while tunneling actual traffic through the encrypted channel.

#[cfg(feature = "out_shadowtls")]
use async_trait::async_trait;
#[cfg(feature = "out_shadowtls")]
use std::io;
#[cfg(feature = "out_shadowtls")]
use std::sync::Arc;
#[cfg(feature = "out_shadowtls")]
use tokio::net::TcpStream;
#[cfg(feature = "out_shadowtls")]
use tokio_rustls::client::TlsStream;
#[cfg(feature = "out_shadowtls")]
use tokio_rustls::{rustls, TlsConnector};
#[cfg(feature = "out_shadowtls")]
use sb_tls::{UtlsConfig, UtlsFingerprint};

#[cfg(feature = "out_shadowtls")]
use super::types::{HostPort, OutboundTcp};

#[cfg(feature = "out_shadowtls")]
#[derive(Clone, Debug)]
pub struct ShadowTlsConfig {
    pub server: String,
    pub port: u16,
    pub sni: String,
    pub alpn: Option<Vec<String>>,
    pub skip_cert_verify: bool,
    /// Optional uTLS fingerprint name for outbound TLS layer.
    pub utls_fingerprint: Option<String>,
}

#[cfg(feature = "out_shadowtls")]
pub struct ShadowTlsOutbound {
    config: ShadowTlsConfig,
    tls_config: Arc<rustls::ClientConfig>,
}

#[cfg(feature = "out_shadowtls")]
impl ShadowTlsOutbound {
    pub fn new(config: ShadowTlsConfig) -> anyhow::Result<Self> {
        // Ensure a CryptoProvider is installed for rustls 0.23
        #[allow(unused_must_use)]
        {
            use tokio_rustls::rustls::crypto::ring;
            let _ = ring::default_provider().install_default();
        }
        // Allow insecure verification when explicitly enabled
        let insecure_env = std::env::var("SB_STL_ALLOW_INSECURE")
            .ok()
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
        let insecure = config.skip_cert_verify || insecure_env;

        let tls_config: Arc<rustls::ClientConfig> = if let Some(fp_name) =
            config.utls_fingerprint.as_deref()
        {
            let fp = fp_name
                .parse::<UtlsFingerprint>()
                .map_err(|e| anyhow::anyhow!("invalid uTLS fingerprint: {e}"))?;
            let mut utls_cfg = UtlsConfig::new(config.sni.clone())
                .with_fingerprint(fp)
                .with_insecure(insecure);
            if let Some(alpn) = config.alpn.clone() {
                utls_cfg = utls_cfg.with_alpn(alpn);
            }
            let roots = crate::tls::global::base_root_store();
            utls_cfg.build_client_config_with_roots(roots)
        } else {
            let roots = crate::tls::global::base_root_store();
            let mut tls_config = rustls::ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth();

            if insecure {
                tracing::warn!(
                    "ShadowTLS: insecure mode enabled, certificate verification disabled"
                );
                let v = crate::tls::danger::NoVerify::new();
                tls_config.dangerous().set_certificate_verifier(Arc::new(v));
            }

            if let Some(alpn_list) = &config.alpn {
                tls_config.alpn_protocols = alpn_list
                    .iter()
                    .map(|proto| proto.as_bytes().to_vec())
                    .collect();
            }

            Arc::new(tls_config)
        };
        Ok(Self { config, tls_config })
    }
}

#[cfg(feature = "out_shadowtls")]
#[async_trait]
impl OutboundTcp for ShadowTlsOutbound {
    type IO = TlsStream<TcpStream>;

    async fn connect(&self, target: &HostPort) -> io::Result<Self::IO> {
        use crate::metrics::outbound::{record_connect_attempt, record_connect_success};
        use crate::metrics::record_outbound_error;

        record_connect_attempt(crate::outbound::OutboundKind::ShadowTls);

        #[cfg(feature = "metrics")]
        let start = std::time::Instant::now();

        // Connect to the ShadowTLS server (decoy)
        let tcp_stream =
            match TcpStream::connect((self.config.server.as_str(), self.config.port)).await {
                Ok(stream) => stream,
                Err(e) => {
                    record_outbound_error(crate::outbound::OutboundKind::Direct, &e);
                    return Err(e);
                }
            };

        // Establish TLS connection with specified SNI
        let server_name = match rustls::pki_types::ServerName::try_from(self.config.sni.clone()) {
            Ok(name) => name,
            Err(e) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("Invalid SNI: {}", e),
                ))
            }
        };

        let connector = TlsConnector::from(self.tls_config.clone());
        let mut tls_stream = match connector.connect(server_name, tcp_stream).await {
            Ok(stream) => stream,
            Err(e) => {
                record_outbound_error(crate::outbound::OutboundKind::Direct, &e);

                // Record specific ShadowTLS metrics
                #[cfg(feature = "metrics")]
                {
                    use metrics::counter;
                    counter!("shadowtls_connect_total", "result" => "tls_fail").increment(1);
                }

                return Err(io::Error::other(format!("TLS handshake failed: {}", e)));
            }
        };

        record_connect_success(crate::outbound::OutboundKind::Direct);

        // Record ShadowTLS-specific metrics
        #[cfg(feature = "metrics")]
        {
            use metrics::{counter, histogram};
            counter!("shadowtls_connect_total", "result" => "ok").increment(1);
            histogram!("shadowtls_handshake_ms").record(start.elapsed().as_millis() as f64);
        }

        // Minimal tunneling header: mimic HTTP CONNECT to improve cover traffic plausibility
        // CONNECT host:port HTTP/1.1\r\nHost: host:port\r\n\r\n
        use tokio::io::AsyncWriteExt;
        let connect_line = format!(
            "CONNECT {}:{} HTTP/1.1\r\nHost: {}:{}\r\n\r\n",
            target.host, target.port, target.host, target.port
        );
        if let Err(e) = tls_stream.write_all(connect_line.as_bytes()).await {
            #[cfg(feature = "metrics")]
            metrics::counter!("shadowtls_connect_total", "result" => "write_fail").increment(1);
            return Err(io::Error::other(format!(
                "tunnel header write failed: {}",
                e
            )));
        }
        if let Err(e) = tls_stream.flush().await {
            return Err(io::Error::other(format!(
                "tunnel header flush failed: {}",
                e
            )));
        }

        Ok(tls_stream)
    }

    fn protocol_name(&self) -> &'static str {
        "shadowtls"
    }
}

#[cfg(test)]
#[cfg(feature = "out_shadowtls")]
mod tests {
    use super::*;

    #[test]
    fn shadowtls_rejects_unknown_utls_fingerprint() {
        let cfg = ShadowTlsConfig {
            server: "example.com".to_string(),
            port: 443,
            sni: "example.com".to_string(),
            alpn: None,
            skip_cert_verify: false,
            utls_fingerprint: Some("invalid-fp".to_string()),
        };
        assert!(ShadowTlsOutbound::new(cfg).is_err());
    }

    #[test]
    fn shadowtls_accepts_chrome_utls_fingerprint() {
        let cfg = ShadowTlsConfig {
            server: "example.com".to_string(),
            port: 443,
            sni: "example.com".to_string(),
            alpn: None,
            skip_cert_verify: false,
            utls_fingerprint: Some("chrome".to_string()),
        };
        assert!(ShadowTlsOutbound::new(cfg).is_ok());
    }
}

#[cfg(not(feature = "out_shadowtls"))]
pub struct ShadowTlsConfig;

#[cfg(not(feature = "out_shadowtls"))]
impl ShadowTlsConfig {
    pub fn new() -> Self {
        Self
    }
}
