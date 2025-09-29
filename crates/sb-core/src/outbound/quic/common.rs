//! QUIC common utilities for TUIC and Hysteria2
//!
//! Provides unified QUIC endpoint configuration, connection establishment,
//! and ALPN handling for QUIC-based protocols.

#[cfg(feature = "out_quic")]
use quinn::Connection;

#[cfg(feature = "out_quic")]
#[derive(Clone, Debug)]
pub struct QuicConfig {
    pub server: String,
    pub port: u16,
    pub alpn: Vec<Vec<u8>>,
    pub allow_insecure: bool,
}

#[cfg(feature = "out_quic")]
impl QuicConfig {
    pub fn new(server: String, port: u16) -> Self {
        Self {
            server,
            port,
            alpn: Vec::new(),
            allow_insecure: false,
        }
    }

    pub fn with_alpn(mut self, alpn: Vec<Vec<u8>>) -> Self {
        self.alpn = alpn;
        self
    }

    pub fn with_allow_insecure(mut self, allow: bool) -> Self {
        self.allow_insecure = allow;
        self
    }
}

/// Establish QUIC connection with unified configuration
#[cfg(feature = "out_quic")]
pub async fn connect(cfg: &QuicConfig) -> anyhow::Result<Connection> {
    use rustls::{ClientConfig as RustlsConfig, RootCertStore};
    use std::sync::Arc;

    // 1) Build rustls client with roots and ALPN
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let mut tls = RustlsConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    if !cfg.alpn.is_empty() {
        tls.alpn_protocols = cfg.alpn.clone();
    }
    if cfg.allow_insecure {
        #[cfg(feature = "tls_rustls")]
        {
            use crate::tls::danger::NoVerify;
            tls.dangerous()
                .set_certificate_verifier(Arc::new(NoVerify::new()));
        }
    }
    // Use platform verifier for TLS roots; feature flags can extend this
    // with custom root stores or pinning.
    let client = quinn::ClientConfig::try_with_platform_verifier()
        .map_err(|e| anyhow::anyhow!("Failed to create QUIC client config: {}", e))?;

    // 2) Create client endpoint
    let mut ep = quinn::Endpoint::client("0.0.0.0:0".parse()?)?;
    ep.set_default_client_config(client);

    // 3) Resolve server and connect with appropriate SNI
    let server_name = if cfg.server.parse::<std::net::IpAddr>().is_ok() {
        if cfg.allow_insecure {
            "localhost"
        } else {
            cfg.server.as_str()
        }
    } else {
        cfg.server.as_str()
    };

    let mut last_err: Option<anyhow::Error> = None;
    let host_iter = tokio::net::lookup_host((&cfg.server[..], cfg.port)).await?;
    for sa in host_iter {
        #[cfg(feature = "metrics")]
        metrics::counter!("quic_connect_attempt_total").increment(1);
        match ep.connect(sa, server_name) {
            Ok(c) => match c.await {
                Ok(conn) => {
                    #[cfg(feature = "metrics")]
                    metrics::counter!("quic_connect_total", "result"=>"ok").increment(1);
                    return Ok(conn);
                }
                Err(e) => {
                    #[cfg(feature = "metrics")]
                    metrics::counter!("quic_connect_total", "result"=>"handshake_fail")
                        .increment(1);
                    last_err = Some(anyhow::anyhow!("QUIC handshake failed: {e}"));
                    continue;
                }
            },
            Err(e) => {
                #[cfg(feature = "metrics")]
                metrics::counter!("quic_connect_total", "result"=>"connect_fail").increment(1);
                last_err = Some(anyhow::anyhow!("QUIC connect setup failed: {e}"));
                continue;
            }
        }
    }
    if last_err.is_none() {
        #[cfg(feature = "metrics")]
        metrics::counter!("quic_connect_total", "result"=>"no_addresses").increment(1);
    }
    Err(last_err.unwrap_or_else(|| anyhow::anyhow!("QUIC connect: no addresses")))
}

/// Get ALPN protocols from environment variable
#[cfg(feature = "out_quic")]
pub fn alpn_from_env(env_var: &str) -> Vec<Vec<u8>> {
    std::env::var(env_var)
        .ok()
        .map(|alpn_str| {
            alpn_str
                .split(',')
                .map(|proto| proto.trim().as_bytes().to_vec())
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(not(feature = "out_quic"))]
pub struct QuicConfig;

#[cfg(not(feature = "out_quic"))]
impl QuicConfig {
    pub fn new(_server: String, _port: u16) -> Self {
        Self
    }
}

#[cfg(test)]
#[cfg(feature = "out_quic")]
mod tests {
    use super::*;

    #[test]
    fn test_quic_config() {
        let config = QuicConfig::new("example.com".to_string(), 443)
            .with_alpn(vec![b"h3".to_vec()])
            .with_allow_insecure(false);

        assert_eq!(config.server, "example.com");
        assert_eq!(config.port, 443);
        assert_eq!(config.alpn, vec![b"h3".to_vec()]);
        assert!(!config.allow_insecure);
    }

    #[test]
    fn test_alpn_from_env() {
        std::env::set_var("TEST_QUIC_ALPN", "h3,h2");
        let alpn = alpn_from_env("TEST_QUIC_ALPN");
        assert_eq!(alpn, vec![b"h3".to_vec(), b"h2".to_vec()]);
    }
}
