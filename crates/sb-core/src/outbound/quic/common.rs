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
    pub sni: Option<String>,
    pub extra_ca_paths: Vec<String>,
    pub extra_ca_pem: Vec<String>,
    pub enable_0rtt: bool,
}

#[cfg(feature = "out_quic")]
impl QuicConfig {
    pub fn new(server: String, port: u16) -> Self {
        Self {
            server,
            port,
            alpn: Vec::new(),
            allow_insecure: false,
            sni: None,
            extra_ca_paths: Vec::new(),
            extra_ca_pem: Vec::new(),
            enable_0rtt: false,
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

    pub fn with_sni(mut self, sni: Option<String>) -> Self {
        self.sni = sni;
        self
    }

    pub fn with_extra_ca_paths(mut self, paths: Vec<String>) -> Self {
        self.extra_ca_paths = paths;
        self
    }

    pub fn with_extra_ca_pem(mut self, pems: Vec<String>) -> Self {
        self.extra_ca_pem = pems;
        self
    }

    pub fn with_enable_0rtt(mut self, enable: bool) -> Self {
        self.enable_0rtt = enable;
        self
    }
}

/// Establish QUIC connection with unified configuration
#[cfg(feature = "out_quic")]
pub async fn connect(cfg: &QuicConfig) -> anyhow::Result<Connection> {
    use rustls::{ClientConfig as RustlsConfig, RootCertStore};
    use std::sync::Arc;

    // 1) Build rustls client with global roots + extra CAs and ALPN
    let mut roots: RootCertStore = crate::tls::global::base_root_store();
    // extra CA from paths
    for path in &cfg.extra_ca_paths {
        if let Ok(bytes) = std::fs::read(path) {
            let mut rd = std::io::BufReader::new(&bytes[..]);
            for der in rustls_pemfile::certs(&mut rd).flatten() {
                let _ = roots.add(der);
            }
        }
    }
    // extra CA from inline PEM
    for pem in &cfg.extra_ca_pem {
        let mut rd = std::io::BufReader::new(pem.as_bytes());
        for der in rustls_pemfile::certs(&mut rd).flatten() {
            let _ = roots.add(der);
        }
    }

    let mut tls = RustlsConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    if !cfg.alpn.is_empty() {
        tls.alpn_protocols = cfg.alpn.clone();
    }
    // Enable early data when requested (0-RTT)
    if cfg.enable_0rtt {
        tls.enable_early_data = true;
    }
    if cfg.allow_insecure {
        #[cfg(feature = "tls_rustls")]
        {
            use crate::tls::danger::NoVerify;
            tls.dangerous()
                .set_certificate_verifier(Arc::new(NoVerify::new()));
        }
    }
    #[cfg(feature = "metrics")]
    if cfg.enable_0rtt {
        metrics::counter!("quic_0rtt_enabled_total").increment(1);
    }
    // Build Quinn client config from rustls config
    let client = quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(tls)
            .map_err(|e| anyhow::anyhow!("Failed to build rustls QUIC config: {}", e))?,
    ));

    // 2) Create client endpoint
    let mut ep = quinn::Endpoint::client("0.0.0.0:0".parse()?)?;
    ep.set_default_client_config(client);

    // 3) Resolve server and connect with appropriate SNI
    let server_name = if let Some(sni) = cfg.sni.as_deref() {
        sni
    } else if cfg.server.parse::<std::net::IpAddr>().is_ok() {
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
