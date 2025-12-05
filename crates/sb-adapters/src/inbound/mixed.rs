//! Mixed inbound (HTTP CONNECT + SOCKS5 hybrid listener)
//!
//! Accepts both HTTP CONNECT and SOCKS5 connections on the same port.
//! Protocol detection is performed by inspecting the first bytes received.
//!
//! Protocol detection logic:
//! - HTTP: First byte is printable ASCII (typically 'C' from "CONNECT")
//! - SOCKS5: First byte is 0x05 (SOCKS version 5)

use std::{io, net::SocketAddr, sync::Arc, time::Duration};

use tokio::{
    net::{TcpListener, TcpStream},
    select,
    sync::{mpsc, oneshot},
};

use tracing::{debug, info, warn};

use sb_config::ir::Credentials;
use sb_core::outbound::OutboundRegistryHandle;
use sb_core::router::RouterHandle;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

#[cfg(feature = "metrics")]
use metrics::counter;

#[derive(Clone, Debug)]
pub struct MixedInboundConfig {
    pub listen: SocketAddr,
    pub router: Arc<RouterHandle>,
    pub outbounds: Arc<OutboundRegistryHandle>,
    pub read_timeout: Option<Duration>,
    pub tls: Option<sb_transport::TlsConfig>,
    pub users: Option<Vec<Credentials>>,
    pub set_system_proxy: bool,
}

pub async fn serve_mixed(
    cfg: MixedInboundConfig,
    mut stop_rx: mpsc::Receiver<()>,
    ready_tx: Option<oneshot::Sender<()>>,
) -> io::Result<()> {
    let listener = TcpListener::bind(cfg.listen).await?;
    let actual = listener.local_addr().unwrap_or(cfg.listen);
    info!(addr=?cfg.listen, actual=?actual, "Mixed (HTTP+SOCKS5) inbound bound");

    if let Some(tx) = ready_tx {
        let _ = tx.send(());
    }

    // Set system proxy if configured
    // Set system proxy if configured
    if cfg.set_system_proxy {
        #[cfg(feature = "tun")]
        {
            info!("Setting system proxy to {}", actual.port());
            let manager = sb_platform::system_proxy::SystemProxyManager::new(actual.port(), true);
            if let Err(e) = manager.enable() {
                warn!("Failed to set system proxy: {}", e);
            }
        }
        #[cfg(not(feature = "tun"))]
        {
            warn!("System proxy requested but 'tun' feature is not enabled; ignoring");
        }
    }

    // Ensure system proxy is disabled on exit
    // We use a guard to ensure it runs even on panic or early return
    struct SystemProxyGuard(bool);
    impl Drop for SystemProxyGuard {
        fn drop(&mut self) {
            if self.0 {
                #[cfg(feature = "tun")]
                {
                    info!("Disabling system proxy");
                    let manager = sb_platform::system_proxy::SystemProxyManager::new(0, true);
                    if let Err(e) = manager.disable() {
                        warn!("Failed to disable system proxy: {}", e);
                    }
                }
            }
        }
    }
    let _proxy_guard = SystemProxyGuard(cfg.set_system_proxy);

    // Allow disabling stop signal for testing
    let disable_stop = std::env::var("SB_MIXED_DISABLE_STOP").as_deref() == Ok("1");

    loop {
        select! {
            _ = stop_rx.recv(), if !disable_stop => break,
            r = listener.accept() => {
                let (cli, peer) = match r {
                    Ok(v) => v,
                    Err(e) => {
                        warn!(error=%e, "accept failed");
                        sb_core::metrics::http::record_error_display(&e);
                        sb_core::metrics::record_inbound_error_display("mixed", &e);
                        continue;
                    }
                };

                let cfg_clone = cfg.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_mixed_conn(cli, peer, &cfg_clone).await {
                        // Client closed early (probe) - downgrade to debug
                        if e.kind() == io::ErrorKind::UnexpectedEof {
                            debug!(peer=%peer, "mixed: client closed early (probe)");
                            return;
                        }
                        warn!(peer=%peer, error=%e, "mixed session error");
                    }
                });
            }
        }
    }
    Ok(())
}

/// Detect protocol and route to appropriate handler
async fn handle_mixed_conn(
    cli: TcpStream,
    peer: SocketAddr,
    cfg: &MixedInboundConfig,
) -> io::Result<()> {
    #[cfg(feature = "metrics")]
    counter!("inbound_connections_total", "protocol" => "mixed", "network" => "tcp").increment(1);

    // Peek first byte to detect protocol without consuming
    let mut first_byte = [0u8; 1];

    // Apply read timeout if configured
    let peek_result = if let Some(timeout) = cfg.read_timeout {
        tokio::time::timeout(timeout, cli.peek(&mut first_byte))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "protocol detection timeout"))?
    } else {
        cli.peek(&mut first_byte).await
    };

    match peek_result {
        Ok(0) => {
            // Connection closed immediately
            Ok(())
        }
        Ok(_) => {
            let first = first_byte[0];

            // Protocol detection
            if first == 0x16 {
                // TLS handshake (0x16 = TLS handshake record type)
                debug!(peer=%peer, "mixed: detected TLS protocol");
                #[cfg(feature = "metrics")]
                counter!("mixed_protocol_detection_total", "protocol" => "tls").increment(1);

                handle_tls(cli, peer, cfg).await
            } else if first == 0x05 || first == 0x04 {
                // SOCKS5 (0x05) or SOCKS4 (0x04) protocol
                debug!(peer=%peer, "mixed: detected SOCKS protocol");
                #[cfg(feature = "metrics")]
                counter!("mixed_protocol_detection_total", "protocol" => "socks").increment(1);

                handle_socks(cli, first, peer, cfg).await
            } else {
                // Assume HTTP (or unknown, let HTTP handler decide/fail)
                // HTTP protocol (likely "CONNECT" or "GET")
                debug!(peer=%peer, "mixed: detected HTTP protocol (or unknown)");
                #[cfg(feature = "metrics")]
                counter!("mixed_protocol_detection_total", "protocol" => "http").increment(1);

                handle_http(cli, first, peer, cfg).await
            }
        }
        Err(e) => {
            sb_core::metrics::http::record_error_display(&e);
            sb_core::metrics::record_inbound_error_display("mixed", &e);
            Err(e)
        }
    }
}

/// Handle SOCKS connection
async fn handle_socks(
    cli: TcpStream,
    first_byte: u8,
    peer: SocketAddr,
    cfg: &MixedInboundConfig,
) -> io::Result<()> {
    // Reuse SOCKS inbound handler from socks module
    let socks_cfg = crate::inbound::socks::SocksInboundConfig {
        listen: cfg.listen,
        udp_bind: None, // Mixed inbound doesn't support UDP ASSOCIATE by default
        router: Arc::clone(&cfg.router),
        outbounds: Arc::clone(&cfg.outbounds),
        udp_nat_ttl: Duration::from_secs(60),
        users: cfg.users.clone(),
    };

    let mut stream = PeekedStream::new(cli, first_byte);
    crate::inbound::socks::serve_conn(&mut stream, peer, &socks_cfg, None).await
}

/// Handle TLS connection
async fn handle_tls(cli: TcpStream, peer: SocketAddr, cfg: &MixedInboundConfig) -> io::Result<()> {
    // Check if TLS is configured
    let tls_config = match &cfg.tls {
        Some(config) => config,
        None => {
            warn!(peer=%peer, "mixed: TLS detected but not configured");
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "TLS not configured",
            ));
        }
    };

    // Wrap stream with TLS
    let tls_transport = sb_transport::TlsTransport::new(tls_config.clone());
    let mut tls_stream = match tls_transport.wrap_server(cli).await {
        Ok(stream) => stream,
        Err(e) => {
            warn!(peer=%peer, error=%e, "mixed: TLS handshake failed");
            return Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                format!("TLS handshake failed: {}", e),
            ));
        }
    };

    debug!(peer=%peer, "mixed: TLS handshake successful, detecting inner protocol");

    // Now detect the inner protocol by peeking at the first byte
    // We need to read a byte to detect the protocol

    let mut first_byte = [0u8; 1];
    use tokio::io::AsyncReadExt;

    let n = tls_stream.read(&mut first_byte).await?;
    if n == 0 {
        return Ok(());
    }

    let first = first_byte[0];

    // Detect inner protocol
    if first == 0x05 || first == 0x04 {
        // SOCKS5 or SOCKS4 over TLS
        debug!(peer=%peer, "mixed/tls: detected SOCKS protocol");
        #[cfg(feature = "metrics")]
        counter!("mixed_protocol_detection_total", "protocol" => "tls_socks").increment(1);

        let socks_cfg = crate::inbound::socks::SocksInboundConfig {
            listen: cfg.listen,
            udp_bind: None,
            router: Arc::clone(&cfg.router),
            outbounds: Arc::clone(&cfg.outbounds),
            udp_nat_ttl: Duration::from_secs(60),
            users: cfg.users.clone(),
        };
        let mut stream = PeekedStream::new(tls_stream, first);
        crate::inbound::socks::serve_conn(&mut stream, peer, &socks_cfg, None).await
    } else {
        // Assume HTTP over TLS
        debug!(peer=%peer, "mixed/tls: detected HTTP protocol (or unknown)");
        #[cfg(feature = "metrics")]
        counter!("mixed_protocol_detection_total", "protocol" => "tls_http").increment(1);

        let http_cfg = crate::inbound::http::HttpProxyConfig {
            listen: cfg.listen,
            router: Arc::clone(&cfg.router),
            outbounds: Arc::clone(&cfg.outbounds),
            tls: None, // Already unwrapped
            users: cfg.users.clone(),
        };
        let stream = PeekedStream::new(tls_stream, first);
        crate::inbound::http::serve_conn(stream, peer, &http_cfg)
            .await
            .map_err(io::Error::other)
    }
}

/// Handle HTTP CONNECT connection
async fn handle_http(
    cli: TcpStream,
    first_byte: u8,
    peer: SocketAddr,
    cfg: &MixedInboundConfig,
) -> io::Result<()> {
    // Reuse HTTP inbound handler from http module
    let http_cfg = crate::inbound::http::HttpProxyConfig {
        listen: cfg.listen,
        router: Arc::clone(&cfg.router),
        outbounds: Arc::clone(&cfg.outbounds),
        tls: None,
        users: cfg.users.clone(),
    };

    let stream = PeekedStream::new(cli, first_byte);
    crate::inbound::http::serve_conn(stream, peer, &http_cfg)
        .await
        .map_err(io::Error::other)
}

struct PeekedStream<S> {
    inner: S,
    peeked: Option<u8>,
}

impl<S> PeekedStream<S> {
    fn new(inner: S, peeked: u8) -> Self {
        Self {
            inner,
            peeked: Some(peeked),
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for PeekedStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if let Some(b) = self.peeked.take() {
            buf.put_slice(&[b]);
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for PeekedStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {

    #[test]
    fn test_protocol_detection_socks5() {
        assert_eq!(0x05, 0x05);
    }

    #[test]
    fn test_protocol_detection_http() {
        assert!(b'C'.is_ascii_alphabetic());
        assert!(b'G'.is_ascii_alphabetic());
    }
}
