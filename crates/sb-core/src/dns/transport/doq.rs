//! DNS-over-QUIC (`DoQ`) transport implementation (RFC 9250)
//!
//! Simplified client implementation using QUIC bidirectional streams:
//! - One query per stream, 2-byte length prefix framing (same as TCP/DoT)
//! - Establishes a QUIC connection per query for simplicity
//! - ALPN set to "doq"

use std::{io, net::SocketAddr, time::Duration};

use anyhow::Result;
use async_trait::async_trait;
use futures::io::AsyncReadExt;
use tokio_util::compat::TokioAsyncReadCompatExt;

use super::DnsTransport;

pub struct DoqTransport {
    server: SocketAddr,
    server_name: String,
    timeout: Duration,
    endpoint: quinn::Endpoint,
    conn: tokio::sync::Mutex<Option<quinn::Connection>>,
}

impl DoqTransport {
    pub fn new(server: SocketAddr, server_name: String) -> Result<Self> {
        Self::new_with_tls(server, server_name, Vec::new(), Vec::new(), false)
    }

    pub fn new_with_tls(
        server: SocketAddr,
        server_name: String,
        extra_ca_paths: Vec<String>,
        extra_ca_pem: Vec<String>,
        skip_verify: bool,
    ) -> Result<Self> {
        let timeout = Duration::from_millis(
            std::env::var("SB_DNS_DOQ_TIMEOUT_MS")
                .ok()
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(5000),
        );
        // Create client endpoint and config once with DoQ ALPN
        let mut endpoint =
            quinn::Endpoint::client("0.0.0.0:0".parse().unwrap()).map_err(io::Error::other)?;

        // Build rustls config with ALPN for DoQ using global trust (+ per-upstream additions)
        let mut roots = crate::tls::global::base_root_store();
        for p in extra_ca_paths {
            if let Ok(bytes) = std::fs::read(p) {
                let mut rd = std::io::BufReader::new(&bytes[..]);
                for it in rustls_pemfile::certs(&mut rd) {
                    if let Ok(der) = it {
                        let _ = roots.add(der);
                    }
                }
            }
        }
        for pem in extra_ca_pem {
            let mut rd = std::io::BufReader::new(pem.as_bytes());
            for it in rustls_pemfile::certs(&mut rd) {
                if let Ok(der) = it {
                    let _ = roots.add(der);
                }
            }
        }
        let mut crypto = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        crypto.alpn_protocols = vec![b"doq".to_vec()];
        if skip_verify {
            let v = crate::tls::danger::NoVerify::new();
            crypto
                .dangerous()
                .set_certificate_verifier(std::sync::Arc::new(v));
        }

        let client_cfg = quinn::ClientConfig::new(std::sync::Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(crypto).map_err(io::Error::other)?,
        ));

        // Set default client config once during construction
        endpoint.set_default_client_config(client_cfg);

        Ok(Self {
            server,
            server_name,
            timeout,
            endpoint,
            conn: tokio::sync::Mutex::new(None),
        })
    }

    async fn query_once(&self, packet: &[u8]) -> Result<Vec<u8>> {
        // Get or establish QUIC connection
        let conn = {
            let mut guard = self.conn.lock().await;
            if let Some(c) = guard.as_ref() {
                c.clone()
            } else {
                let connecting = self
                    .endpoint
                    .connect(self.server, &self.server_name)
                    .map_err(io::Error::other)?;
                let connected = tokio::time::timeout(self.timeout, connecting)
                    .await
                    .map_err(|_| {
                        io::Error::new(io::ErrorKind::TimedOut, "DoQ connect timeout")
                    })??;
                *guard = Some(connected.clone());
                connected
            }
        };

        // Open bidirectional stream
        let (mut send, recv) = tokio::time::timeout(self.timeout, conn.open_bi())
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "DoQ open_bi timeout"))??;

        // Send length-prefixed DNS query
        let len = packet.len() as u16;
        let len_be = len.to_be_bytes();
        tokio::time::timeout(self.timeout, send.write_all(&len_be))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "DoQ write len timeout"))??;
        tokio::time::timeout(self.timeout, send.write_all(packet))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "DoQ write pkt timeout"))??;
        let _ = send.finish();

        // Read response via tokio compat
        let mut recv = recv.compat();
        let mut len_buf = [0u8; 2];
        tokio::time::timeout(self.timeout, recv.read_exact(&mut len_buf))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "DoQ read len timeout"))??;
        let resp_len = u16::from_be_bytes(len_buf) as usize;
        let mut resp = vec![0u8; resp_len];
        tokio::time::timeout(self.timeout, recv.read_exact(&mut resp))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "DoQ read body timeout"))??;

        Ok(resp)
    }
}

#[async_trait]
impl DnsTransport for DoqTransport {
    async fn query(&self, packet: &[u8]) -> Result<Vec<u8>> {
        self.query_once(packet).await
    }
    fn name(&self) -> &'static str {
        "doq"
    }
}
