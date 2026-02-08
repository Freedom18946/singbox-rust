//! Shared QUIC utilities for TUIC and Hysteria protocols
//!
//! Provides unified QUIC endpoint configuration, connection establishment,
//! and bidirectional stream wrapper. Uses sb-tls for TLS infrastructure.

#![allow(unreachable_pub)]

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// QUIC connection configuration (builder pattern)
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

impl QuicConfig {
    #[allow(dead_code)]
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

    #[allow(dead_code)]
    pub fn with_alpn(mut self, alpn: Vec<Vec<u8>>) -> Self {
        self.alpn = alpn;
        self
    }

    #[allow(dead_code)]
    pub fn with_allow_insecure(mut self, allow: bool) -> Self {
        self.allow_insecure = allow;
        self
    }

    #[allow(dead_code)]
    pub fn with_sni(mut self, sni: Option<String>) -> Self {
        self.sni = sni;
        self
    }

    #[allow(dead_code)]
    pub fn with_extra_ca_paths(mut self, paths: Vec<String>) -> Self {
        self.extra_ca_paths = paths;
        self
    }

    #[allow(dead_code)]
    pub fn with_extra_ca_pem(mut self, pems: Vec<String>) -> Self {
        self.extra_ca_pem = pems;
        self
    }

    #[allow(dead_code)]
    pub fn with_enable_0rtt(mut self, enable: bool) -> Self {
        self.enable_0rtt = enable;
        self
    }
}

/// Establish QUIC connection with unified configuration.
///
/// Uses sb-tls for root certificate store and danger verifiers.
pub async fn quic_connect(cfg: &QuicConfig) -> anyhow::Result<quinn::Connection> {
    use rustls::ClientConfig as RustlsConfig;

    sb_tls::ensure_crypto_provider();

    // Start with the global root store (webpki-roots + configured extra CAs)
    let mut roots = sb_tls::global::base_root_store();

    // Add per-connection extra CAs from file paths
    for path in &cfg.extra_ca_paths {
        if let Ok(bytes) = std::fs::read(path) {
            let mut rd = std::io::BufReader::new(&bytes[..]);
            for der in rustls_pemfile::certs(&mut rd).flatten() {
                let _ = roots.add(der);
            }
        }
    }

    // Add per-connection extra CAs from inline PEM
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

    if cfg.enable_0rtt {
        tls.enable_early_data = true;
    }

    if cfg.allow_insecure {
        tls.dangerous()
            .set_certificate_verifier(Arc::new(sb_tls::danger::NoVerify::new()));
    }

    // Build Quinn client config from rustls config
    let client = quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(tls)
            .map_err(|e| anyhow::anyhow!("Failed to build rustls QUIC config: {}", e))?,
    ));

    // Create client endpoint
    let mut ep = quinn::Endpoint::client("0.0.0.0:0".parse()?)?;
    ep.set_default_client_config(client);

    // Resolve server and connect with appropriate SNI
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
        match ep.connect(sa, server_name) {
            Ok(c) => match c.await {
                Ok(conn) => return Ok(conn),
                Err(e) => {
                    last_err = Some(anyhow::anyhow!("QUIC handshake failed: {e}"));
                    continue;
                }
            },
            Err(e) => {
                last_err = Some(anyhow::anyhow!("QUIC connect setup failed: {e}"));
                continue;
            }
        }
    }
    Err(last_err.unwrap_or_else(|| anyhow::anyhow!("QUIC connect: no addresses")))
}

/// Wrapper for Quinn bidirectional stream that implements AsyncRead + AsyncWrite
pub(crate) struct QuicBidiStream {
    recv: quinn::RecvStream,
    send: quinn::SendStream,
}

impl QuicBidiStream {
    pub(crate) fn new(send: quinn::SendStream, recv: quinn::RecvStream) -> Self {
        Self { recv, send }
    }
}

impl AsyncRead for QuicBidiStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.recv).poll_read(cx, buf)
    }
}

impl AsyncWrite for QuicBidiStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match Pin::new(&mut self.send).poll_write(cx, buf) {
            Poll::Ready(Ok(n)) => Poll::Ready(Ok(n)),
            Poll::Ready(Err(e)) => Poll::Ready(Err(io::Error::other(e.to_string()))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match Pin::new(&mut self.send).poll_flush(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
            Poll::Ready(Err(e)) => Poll::Ready(Err(io::Error::other(e.to_string()))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match Pin::new(&mut self.send).poll_shutdown(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
            Poll::Ready(Err(e)) => Poll::Ready(Err(io::Error::other(e.to_string()))),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl Unpin for QuicBidiStream {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_quic_config_builder() {
        let config = QuicConfig::new("example.com".to_string(), 443)
            .with_alpn(vec![b"h3".to_vec()])
            .with_allow_insecure(false)
            .with_sni(Some("sni.example.com".to_string()))
            .with_enable_0rtt(true);

        assert_eq!(config.server, "example.com");
        assert_eq!(config.port, 443);
        assert_eq!(config.alpn, vec![b"h3".to_vec()]);
        assert!(!config.allow_insecure);
        assert_eq!(config.sni, Some("sni.example.com".to_string()));
        assert!(config.enable_0rtt);
    }
}
