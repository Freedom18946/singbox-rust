//! Naive HTTP/2 CONNECT server inbound
//!
//! Implements Naive protocol server:
//! - TLS connection with HTTP/2 ALPN using sb-tls infrastructure
//! - HTTP/2 CONNECT proxy with optional Basic authentication
//! - Router-based upstream selection
//! - Bidirectional relay
//!
//! Sprint 20 Phase 1.1: Complete migration to sb-tls infrastructure

use anyhow::{anyhow, Result};
use base64::Engine;
use bytes::Bytes;
use h2::server::{Builder, SendResponse};
use http::StatusCode;
use sb_core::router;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Mutex};
use tracing::{debug, error, info, warn};

/// Naive server configuration
#[derive(Clone, Debug)]
pub struct NaiveInboundConfig {
    /// Listen address
    pub listen: SocketAddr,
    /// TLS configuration using sb-tls infrastructure (Standard TLS only - Naive doesn't support REALITY/ECH)
    pub tls: sb_transport::TlsConfig,
    /// Router for upstream selection
    pub router: Arc<router::RouterHandle>,
    /// Optional username for authentication
    pub username: Option<String>,
    /// Optional password for authentication
    pub password: Option<String>,
}

/// Main server loop
pub async fn serve(cfg: NaiveInboundConfig, mut stop_rx: mpsc::Receiver<()>) -> Result<()> {
    info!(
        addr=?cfg.listen,
        "naive: HTTP/2 server bound"
    );

    // Bind TCP listener
    let listener = TcpListener::bind(cfg.listen).await?;
    let actual = listener.local_addr().unwrap_or(cfg.listen);
    info!(
        listen=?cfg.listen,
        actual=?actual,
        "naive: HTTP/2 server listening"
    );

    // Create TLS transport using sb-tls infrastructure
    // Note: Naive requires HTTP/2 ALPN, which should be configured in TlsConfig
    // Note: TlsTransport is created inside each spawn to avoid clone issues

    let cfg = Arc::new(cfg);

    loop {
        tokio::select! {
            _ = stop_rx.recv() => {
                info!("naive: shutting down");
                break;
            }
            r = listener.accept() => {
                let (stream, peer) = match r {
                    Ok(v) => v,
                    Err(e) => {
                        error!(error=%e, "naive: accept error");
                        sb_core::metrics::http::record_error_display(&e);
                        sb_core::metrics::record_inbound_error_display("naive", &e);
                        continue;
                    }
                };

                let cfg_clone = cfg.clone();

                tokio::spawn(async move {
                    // Create TLS transport inside the spawn to avoid clone issues
                    let tls_transport = sb_transport::TlsTransport::new(cfg_clone.tls.clone());
                    match tls_transport.wrap_server(stream).await {
                        Ok(tls_stream) => {
                            if let Err(e) = handle_conn(cfg_clone, tls_stream, peer).await {
                                debug!(%peer, error=%e, "naive: connection error");
                            }
                        }
                        Err(e) => {
                            sb_core::metrics::http::record_error_display(&e);
                            sb_core::metrics::record_inbound_error_display("naive", &e);
                            warn!(%peer, error=%e, "naive: TLS handshake failed")
                        },
                    }
                });
            }
        }
    }

    Ok(())
}

/// Handle single connection
async fn handle_conn<S>(cfg: Arc<NaiveInboundConfig>, tls_stream: S, peer: SocketAddr) -> Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    debug!(%peer, "naive: new HTTP/2 connection");

    // HTTP/2 server handshake (TLS already handled by TlsTransport)
    let mut builder = Builder::new();
    builder
        .max_concurrent_streams(256)
        .initial_window_size(1024 * 1024)
        .initial_connection_window_size(1024 * 1024);

    let mut connection = builder
        .handshake(tls_stream)
        .await
        .map_err(|e| anyhow!("HTTP/2 handshake failed: {}", e))?;

    debug!(%peer, "naive: HTTP/2 handshake complete");

    // Accept and handle streams
    while let Some(result) = connection.accept().await {
        let (request, respond) = match result {
            Ok(v) => v,
            Err(e) => {
                warn!(error=%e, "naive: stream accept error");
                break;
            }
        };

        let cfg_clone = cfg.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_stream(cfg_clone, request, respond, peer).await {
                debug!(%peer, error=%e, "naive: stream error");
            }
        });
    }

    debug!(%peer, "naive: connection closed");
    Ok(())
}

/// Handle single HTTP/2 stream (CONNECT request)
async fn handle_stream(
    cfg: Arc<NaiveInboundConfig>,
    request: http::Request<h2::RecvStream>,
    mut respond: SendResponse<Bytes>,
    peer: SocketAddr,
) -> Result<()> {
    // Validate CONNECT method
    if request.method() != http::Method::CONNECT {
        error!(%peer, method=%request.method(), "naive: non-CONNECT request");
        let response = http::Response::builder()
            .status(StatusCode::METHOD_NOT_ALLOWED)
            .body(())
            .map_err(|e| anyhow!("Failed to build response: {}", e))?;
        let _ = respond.send_response(response, true);
        return Err(anyhow!("Method not allowed: {}", request.method()));
    }

    // Validate authentication (if configured)
    if let (Some(expected_user), Some(expected_pass)) = (&cfg.username, &cfg.password) {
        let auth_header = request
            .headers()
            .get("proxy-authorization")
            .and_then(|v| v.to_str().ok());

        if let Some(auth_value) = auth_header {
            // Parse "Basic <base64>" format
            if !auth_value.starts_with("Basic ") {
                let response = http::Response::builder()
                    .status(StatusCode::PROXY_AUTHENTICATION_REQUIRED)
                    .body(())
                    .map_err(|e| anyhow!("Failed to build response: {}", e))?;
                let _ = respond.send_response(response, true);
                return Err(anyhow!("Invalid authentication scheme"));
            }

            let encoded = &auth_value[6..]; // Skip "Basic "
            let decoded = base64::engine::general_purpose::STANDARD
                .decode(encoded)
                .map_err(|_| anyhow!("Invalid base64 in authentication"))?;

            let auth_str = String::from_utf8(decoded)
                .map_err(|_| anyhow!("Invalid UTF-8 in authentication"))?;

            let expected = format!("{}:{}", expected_user, expected_pass);

            // Constant-time comparison to prevent timing attacks
            use subtle::ConstantTimeEq;
            if auth_str.as_bytes().ct_eq(expected.as_bytes()).into() {
                debug!(%peer, "naive: authentication successful");
            } else {
                warn!(%peer, "naive: authentication failed");
                let response = http::Response::builder()
                    .status(StatusCode::PROXY_AUTHENTICATION_REQUIRED)
                    .body(())
                    .map_err(|e| anyhow!("Failed to build response: {}", e))?;
                let _ = respond.send_response(response, true);
                return Err(anyhow!("Authentication failed"));
            }
        } else {
            // Authentication required but not provided
            let response = http::Response::builder()
                .status(StatusCode::PROXY_AUTHENTICATION_REQUIRED)
                .header("Proxy-Authenticate", "Basic realm=\"Naive\"")
                .body(())
                .unwrap();
            let _ = respond.send_response(response, true);
            return Err(anyhow!("Authentication required"));
        }
    }

    // Parse target from URI (CONNECT host:port)
    let target_str = request.uri().to_string();
    let (host, port) = parse_target(&target_str)?;

    debug!(%peer, %host, port, "naive: CONNECT request");

    // Router integration (Sprint 20 Phase 1.2)
    // For now, use direct connection (router integration will be added next)
    // TODO: Add router decision logic (Direct/Proxy/Reject)
    let upstream = TcpStream::connect((host.as_str(), port))
        .await
        .map_err(|e| anyhow!("Failed to connect to target: {}", e))?;

    debug!(%host, port, "naive: connected to target");

    // Send 200 OK response
    let response = http::Response::builder()
        .status(StatusCode::OK)
        .body(())
        .map_err(|e| anyhow!("Failed to build response: {}", e))?;

    let send_stream = respond
        .send_response(response, false)
        .map_err(|e| anyhow!("Failed to send response: {}", e))?;

    // Get recv stream from request
    let recv_stream = request.into_body();

    // Bidirectional relay
    relay_h2_tcp(send_stream, recv_stream, upstream).await?;

    Ok(())
}

/// Parse CONNECT target (host:port)
fn parse_target(target: &str) -> Result<(String, u16)> {
    let (host, port_str) = target
        .rsplit_once(':')
        .ok_or_else(|| anyhow!("Invalid target format: {}", target))?;
    let port = port_str
        .parse::<u16>()
        .map_err(|_| anyhow!("Invalid port: {}", port_str))?;
    Ok((host.to_string(), port))
}

/// Relay data between HTTP/2 stream and TCP stream
async fn relay_h2_tcp(
    mut h2_send: h2::SendStream<Bytes>,
    mut h2_recv: h2::RecvStream,
    mut tcp: TcpStream,
) -> Result<()> {
    let (mut tcp_read, mut tcp_write) = tcp.split();

    let h2_to_tcp = async {
        // Read from HTTP/2 stream, write to TCP
        while let Some(result) = h2_recv.data().await {
            let data = result.map_err(|e| anyhow!("H2 recv error: {}", e))?;

            if data.is_empty() {
                break;
            }

            tcp_write
                .write_all(&data)
                .await
                .map_err(|e| anyhow!("TCP write error: {}", e))?;

            // Release flow control
            let _ = h2_recv.flow_control().release_capacity(data.len());
        }
        tcp_write.shutdown().await.ok();
        Ok::<_, anyhow::Error>(())
    };

    let tcp_to_h2 = async {
        // Read from TCP, write to HTTP/2 stream
        let mut buf = vec![0u8; 8192];
        loop {
            let n = tcp_read
                .read(&mut buf)
                .await
                .map_err(|e| anyhow!("TCP read error: {}", e))?;

            if n == 0 {
                break;
            }

            h2_send
                .send_data(Bytes::copy_from_slice(&buf[..n]), false)
                .map_err(|e| anyhow!("H2 send error: {}", e))?;
        }
        h2_send.send_data(Bytes::new(), true).ok();
        Ok::<_, anyhow::Error>(())
    };

    tokio::select! {
        r1 = h2_to_tcp => r1,
        r2 = tcp_to_h2 => r2,
    }
}

/// Naive inbound adapter that implements InboundService trait
#[derive(Debug)]
pub struct NaiveInboundAdapter {
    config: NaiveInboundConfig,
    shutdown_tx: Arc<Mutex<Option<mpsc::Sender<()>>>>,
}

impl NaiveInboundAdapter {
    /// Create a new Naive inbound adapter from parameters.
    ///
    /// # Arguments
    /// * `param` - Inbound parameters containing listen address, TLS cert/key, and credentials.
    ///
    /// # Returns
    /// A boxed InboundService or an error if parameters are invalid.
    pub fn new(
        param: &sb_core::adapter::InboundParam,
        router: Arc<router::RouterHandle>,
    ) -> Result<Box<dyn sb_core::adapter::InboundService>> {
        // Parse listen address
        let listen_str = format!("{}:{}", param.listen, param.port);
        let listen: SocketAddr = listen_str
            .parse()
            .map_err(|e| anyhow!("invalid listen address '{}': {}", listen_str, e))?;

        // Get TLS certificate and key (required for Naive)
        let (cert_pem, cert_path) = match (&param.tls_cert_pem, &param.tls_cert_path) {
            (Some(pem), _) => (Some(pem.clone()), None),
            (None, Some(path)) => (None, Some(path.clone())),
            (None, None) => {
                return Err(anyhow!(
                    "Naive inbound requires TLS certificate (tls_cert_pem or tls_cert_path)"
                ));
            }
        };

        let (key_pem, key_path) = match (&param.tls_key_pem, &param.tls_key_path) {
            (Some(pem), _) => (Some(pem.clone()), None),
            (None, Some(path)) => (None, Some(path.clone())),
            (None, None) => {
                return Err(anyhow!(
                    "Naive inbound requires TLS private key (tls_key_pem or tls_key_path)"
                ));
            }
        };

        // Create TLS configuration using sb-transport infrastructure
        // Naive requires HTTP/2 ALPN
        let alpn = param
            .tls_alpn
            .clone()
            .unwrap_or_else(|| vec!["h2".to_string()]);

        let standard_tls = sb_transport::tls::StandardTlsConfig {
            server_name: param.tls_server_name.clone(),
            alpn,
            insecure: false,
            cert_path,
            key_path,
            cert_pem,
            key_pem,
        };

        let tls = sb_transport::TlsConfig::Standard(standard_tls);

        // Get optional authentication credentials
        let username = param.basic_auth.as_ref().and_then(|a| a.username.clone());
        let password = param.basic_auth.as_ref().and_then(|a| a.password.clone());

        let config = NaiveInboundConfig {
            listen,
            tls,
            router,
            username,
            password,
        };

        Ok(Box::new(NaiveInboundAdapter {
            config,
            shutdown_tx: Arc::new(Mutex::new(None)),
        }))
    }
}

impl sb_core::adapter::InboundService for NaiveInboundAdapter {
    fn serve(&self) -> std::io::Result<()> {
        let config = self.config.clone();
        let (stop_tx, stop_rx) = mpsc::channel(1);

        // Store shutdown channel
        {
            let mut tx = self.shutdown_tx.blocking_lock();
            *tx = Some(stop_tx);
        }

        // Use current tokio runtime or create new one
        match tokio::runtime::Handle::try_current() {
            Ok(handle) => {
                // Already in a tokio runtime, spawn the server task
                handle.spawn(async move {
                    if let Err(e) = serve(config, stop_rx).await {
                        error!(error=%e, "Naive inbound server error");
                    }
                });
                Ok(())
            }
            Err(_) => {
                // No tokio runtime, create one and block on it
                let runtime = tokio::runtime::Runtime::new().map_err(std::io::Error::other)?;
                runtime
                    .block_on(serve(config, stop_rx))
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
            }
        }
    }

    fn request_shutdown(&self) {
        if let Some(tx) = self.shutdown_tx.blocking_lock().take() {
            let _ = tx.blocking_send(());
        }
    }

    fn active_connections(&self) -> Option<u64> {
        // TODO: Add connection tracking in the future
        None
    }

    fn udp_sessions_estimate(&self) -> Option<u64> {
        // Naive doesn't support UDP
        None
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_parse_target() {
        assert_eq!(
            parse_target("example.com:443").unwrap(),
            ("example.com".to_string(), 443)
        );

        assert_eq!(
            parse_target("192.168.1.1:8080").unwrap(),
            ("192.168.1.1".to_string(), 8080)
        );

        assert!(parse_target("invalid").is_err());
        assert!(parse_target("example.com:99999").is_err());
    }
}
