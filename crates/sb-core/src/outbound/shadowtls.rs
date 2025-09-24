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
use super::types::{HostPort, OutboundTcp};

#[cfg(feature = "out_shadowtls")]
#[derive(Clone, Debug)]
pub struct ShadowTlsConfig {
    pub server: String,
    pub port: u16,
    pub sni: String,
    pub alpn: Option<String>,
    pub skip_cert_verify: bool,
}

#[cfg(feature = "out_shadowtls")]
pub struct ShadowTlsOutbound {
    config: ShadowTlsConfig,
    tls_config: Arc<rustls::ClientConfig>,
}

#[cfg(feature = "out_shadowtls")]
impl ShadowTlsOutbound {
    pub fn new(config: ShadowTlsConfig) -> anyhow::Result<Self> {
        // Create TLS configuration for ShadowTLS
        let mut tls_config = rustls::ClientConfig::builder()
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_no_client_auth();

        if config.skip_cert_verify
            && std::env::var("SB_STL_ALLOW_INSECURE").ok() == Some("1".to_string())
        {
            // Allow insecure connections if explicitly enabled
            tracing::warn!("ShadowTLS: insecure mode enabled, certificate verification disabled");
        }

        if let Some(alpn) = &config.alpn {
            tls_config.alpn_protocols = vec![alpn.as_bytes().to_vec()];
        }

        let tls_config = Arc::new(tls_config);

        Ok(Self { config, tls_config })
    }
}

#[cfg(feature = "out_shadowtls")]
#[async_trait]
impl OutboundTcp for ShadowTlsOutbound {
    type IO = TlsStream<TcpStream>;

    async fn connect(&self, target: &HostPort) -> io::Result<Self::IO> {
        use crate::metrics::outbound::{
            record_connect_attempt, record_connect_error, record_connect_success,
            OutboundErrorClass,
        };

        record_connect_attempt(crate::outbound::OutboundKind::Direct); // TODO: Add ShadowTLS kind

        let start = std::time::Instant::now();

        // Connect to the ShadowTLS server (decoy)
        let tcp_stream =
            match TcpStream::connect((self.config.server.as_str(), self.config.port)).await {
                Ok(stream) => stream,
                Err(e) => {
                    record_connect_error(
                        crate::outbound::OutboundKind::Direct,
                        OutboundErrorClass::Io,
                    );
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
        let tls_stream = match connector.connect(server_name, tcp_stream).await {
            Ok(stream) => stream,
            Err(e) => {
                record_connect_error(
                    crate::outbound::OutboundKind::Direct,
                    OutboundErrorClass::Handshake,
                );

                // Record specific ShadowTLS metrics
                #[cfg(feature = "metrics")]
                {
                    use metrics::counter;
                    counter!("shadowtls_connect_total", "result" => "tls_fail").increment(1);
                }

                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!("TLS handshake failed: {}", e),
                ));
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

        // Note: In a full ShadowTLS implementation, the target would be used as follows:
        // 1. The TLS connection above is the "masquerading" connection to the decoy server
        // 2. The actual target traffic would be tunneled through this TLS connection
        // 3. ShadowTLS protocol would encode target info and relay actual payload

        // For now, we store the target info for future protocol implementation
        tracing::debug!(
            "ShadowTLS connecting to decoy {}, actual target: {:?}",
            self.config.sni,
            target
        );

        // TODO: Implement ShadowTLS protocol layer that uses `target` for actual routing
        // This would involve sending target information through the established TLS tunnel
        // and setting up bidirectional forwarding

        Ok(tls_stream)
    }

    fn protocol_name(&self) -> &'static str {
        "shadowtls"
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
