//! DNS-over-HTTP/3 (`DoH3`) transport implementation
//!
//! Provides DNS-over-HTTPS using HTTP/3 over QUIC:
//! - RFC 8484 compliant (DNS-over-HTTPS)
//! - HTTP/3 transport over QUIC
//! - ALPN set to "h3"
//! - Connection pooling and reuse
//! - 0-RTT support for reduced latency

use std::{io, net::SocketAddr, sync::Arc, time::Duration};

use anyhow::{Context, Result};
use async_trait::async_trait;
use bytes::Bytes;

use super::DnsTransport;

#[cfg(feature = "dns_doh3")]
pub struct Doh3Transport {
    server: SocketAddr,
    server_name: String,
    path: String,
    timeout: Duration,
    endpoint: quinn::Endpoint,
    conn: tokio::sync::Mutex<Option<quinn::Connection>>,
}

#[cfg(feature = "dns_doh3")]
impl Doh3Transport {
    pub fn new(server: SocketAddr, server_name: String, path: String) -> Result<Self> {
        Self::new_with_tls(server, server_name, path, Vec::new(), Vec::new(), false)
    }

    pub fn new_with_tls(
        server: SocketAddr,
        server_name: String,
        path: String,
        extra_ca_paths: Vec<String>,
        extra_ca_pem: Vec<String>,
        skip_verify: bool,
    ) -> Result<Self> {
        let timeout = Duration::from_millis(
            std::env::var("SB_DNS_DOH3_TIMEOUT_MS")
                .ok()
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(5000),
        );

        // Create client endpoint with HTTP/3 ALPN
        let mut endpoint =
            quinn::Endpoint::client("0.0.0.0:0".parse().unwrap()).map_err(io::Error::other)?;

        // Build rustls config with ALPN for HTTP/3
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

        // HTTP/3 requires "h3" ALPN
        crypto.alpn_protocols = vec![b"h3".to_vec()];

        if skip_verify {
            let v = crate::tls::danger::NoVerify::new();
            crypto.dangerous().set_certificate_verifier(Arc::new(v));
        }

        let client_cfg = quinn::ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(crypto).map_err(io::Error::other)?,
        ));

        endpoint.set_default_client_config(client_cfg);

        Ok(Self {
            server,
            server_name,
            path,
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
                if c.close_reason().is_none() {
                    c.clone()
                } else {
                    // Connection closed, re-establish
                    *guard = None;
                    let connecting = self
                        .endpoint
                        .connect(self.server, &self.server_name)
                        .map_err(io::Error::other)?;
                    let connected = tokio::time::timeout(self.timeout, connecting)
                        .await
                        .map_err(|_| {
                            io::Error::new(io::ErrorKind::TimedOut, "DoH3 connect timeout")
                        })??;
                    *guard = Some(connected.clone());
                    connected
                }
            } else {
                let connecting = self
                    .endpoint
                    .connect(self.server, &self.server_name)
                    .map_err(io::Error::other)?;
                let connected = tokio::time::timeout(self.timeout, connecting)
                    .await
                    .map_err(|_| {
                        io::Error::new(io::ErrorKind::TimedOut, "DoH3 connect timeout")
                    })??;
                *guard = Some(connected.clone());
                connected
            }
        };

        // Create HTTP/3 connection over QUIC
        let (mut driver, mut send_request) = h3::client::new(h3_quinn::Connection::new(conn))
            .await
            .map_err(|e| {
                io::Error::new(io::ErrorKind::Other, format!("H3 handshake failed: {}", e))
            })?;

        // Spawn driver task to run in background
        tokio::spawn(async move {
            let _ = futures::future::poll_fn(|cx| driver.poll_close(cx)).await;
        });

        // Send HTTP/3 POST request with DNS query
        let req = http::Request::builder()
            .method(http::Method::POST)
            .uri(&self.path)
            .header("content-type", "application/dns-message")
            .header("accept", "application/dns-message")
            .header("cache-control", "no-cache")
            .body(())
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;

        let mut stream = send_request.send_request(req).await.map_err(|e| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("H3 send_request failed: {}", e),
            )
        })?;

        // Send DNS query data
        stream
            .send_data(Bytes::copy_from_slice(packet))
            .await
            .map_err(|e| {
                io::Error::new(io::ErrorKind::Other, format!("H3 send_data failed: {}", e))
            })?;

        stream.finish().await.map_err(|e| {
            io::Error::new(io::ErrorKind::Other, format!("H3 finish failed: {}", e))
        })?;

        // Receive HTTP/3 response
        let resp = stream.recv_response().await.map_err(|e| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("H3 recv_response failed: {}", e),
            )
        })?;

        // Check HTTP status
        if !resp.status().is_success() {
            return Err(anyhow::anyhow!(
                "DoH3 server returned error status: {}",
                resp.status()
            ));
        }

        // Read response body
        let mut body = Vec::new();
        loop {
            match stream.recv_data().await {
                Ok(Some(chunk)) => {
                    // Convert Buf to bytes
                    use bytes::Buf;
                    let bytes = chunk.chunk();
                    body.extend_from_slice(bytes);
                }
                Ok(None) => break,
                Err(e) => {
                    return Err(anyhow::anyhow!("H3 recv_data failed: {}", e));
                }
            }
        }

        if body.is_empty() {
            return Err(anyhow::anyhow!("DoH3 server returned empty response"));
        }

        Ok(body)
    }
}

#[cfg(feature = "dns_doh3")]
#[async_trait]
impl DnsTransport for Doh3Transport {
    async fn query(&self, packet: &[u8]) -> Result<Vec<u8>> {
        tokio::time::timeout(self.timeout, self.query_once(packet))
            .await
            .context("DoH3 query timeout")?
    }

    fn name(&self) -> &'static str {
        "doh3"
    }
}

#[cfg(not(feature = "dns_doh3"))]
pub struct Doh3Transport;

#[cfg(not(feature = "dns_doh3"))]
impl Doh3Transport {
    pub fn new(_server: SocketAddr, _server_name: String, _path: String) -> Result<Self> {
        Err(anyhow::anyhow!(
            "DoH3 transport not available: compile with --features dns_doh3"
        ))
    }
}
