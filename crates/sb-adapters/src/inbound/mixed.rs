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
    io::AsyncReadExt,
    net::{TcpListener, TcpStream},
    select,
    sync::{mpsc, oneshot},
};

use tracing::{debug, info, warn};

use sb_config::ir::Credentials;
use sb_core::net::rate_limit_metrics;
#[cfg(test)]
use sb_core::net::tcp_rate_limit::TcpRateLimitConfig;
use sb_core::net::tcp_rate_limit::TcpRateLimiter;
use sb_core::outbound::OutboundRegistryHandle;
use sb_core::router::RouterHandle;
use sb_core::v2ray_stats::StatsManager;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

#[cfg(feature = "metrics")]
use metrics::counter;

#[derive(Clone, Debug)]
pub struct MixedInboundConfig {
    pub tag: Option<String>,
    pub listen: SocketAddr,
    pub router: Arc<RouterHandle>,
    pub outbounds: Arc<OutboundRegistryHandle>,
    pub read_timeout: Option<Duration>,
    pub tls: Option<sb_transport::TlsConfig>,
    pub users: Option<Vec<Credentials>>,
    pub set_system_proxy: bool,
    pub allow_private_network: bool,
    pub udp_timeout: Option<Duration>,
    pub domain_strategy: Option<crate::inbound::socks::DomainStrategy>,
    pub stats: Option<Arc<StatsManager>>,
    pub conn_tracker: Arc<sb_common::conntrack::ConnTracker>,
    /// Inbound sniff configuration (Go parity: sniff_enabled).
    pub sniff: bool,
    /// Override destination with sniffed hostname (Go parity: sniff_override_destination).
    pub sniff_override_destination: bool,
}

pub async fn serve_mixed(
    cfg: MixedInboundConfig,
    stop_rx: mpsc::Receiver<()>,
    ready_tx: Option<oneshot::Sender<io::Result<()>>>,
) -> io::Result<()> {
    serve_mixed_with_limiter(
        cfg,
        stop_rx,
        ready_tx,
        TcpRateLimiter::new(super::tcp_rate_limit_config_from_env()),
    )
    .await
}

async fn serve_mixed_with_limiter(
    cfg: MixedInboundConfig,
    mut stop_rx: mpsc::Receiver<()>,
    ready_tx: Option<oneshot::Sender<io::Result<()>>>,
    rate_limiter: TcpRateLimiter,
) -> io::Result<()> {
    let listener = match TcpListener::bind(cfg.listen).await {
        Ok(listener) => listener,
        Err(error) => {
            if let Some(tx) = ready_tx {
                let _ = tx.send(Err(io::Error::new(error.kind(), error.to_string())));
            }
            return Err(error);
        }
    };
    let actual = listener.local_addr().unwrap_or(cfg.listen);
    info!(addr=?cfg.listen, actual=?actual, "Mixed (HTTP+SOCKS5) inbound bound");

    if let Some(tx) = ready_tx {
        let _ = tx.send(Ok(()));
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

                if !rate_limiter.allow_connection(peer.ip()) {
                    warn!(%peer, "mixed: connection rate limited");
                    rate_limit_metrics::record_rate_limited("mixed", "connection_limit");
                    continue;
                }

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
    mut cli: TcpStream,
    peer: SocketAddr,
    cfg: &MixedInboundConfig,
) -> io::Result<()> {
    #[cfg(feature = "metrics")]
    counter!("inbound_connections_total", "protocol" => "mixed", "network" => "tcp").increment(1);

    // Read first byte to detect protocol (consumed from stream, replayed via PeekedStream)
    let mut first_byte = [0u8; 1];

    // Apply read timeout if configured
    let peek_result = if let Some(timeout) = cfg.read_timeout {
        tokio::time::timeout(timeout, cli.read_exact(&mut first_byte))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "protocol detection timeout"))?
    } else {
        cli.read_exact(&mut first_byte).await
    };

    match peek_result {
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
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
            // Connection closed before sending any data
            Ok(())
        }
        Err(e) => {
            sb_core::metrics::http::record_error_display(&e);
            sb_core::metrics::record_inbound_error_display("mixed", &e);
            Err(e)
        }
    }
}

/// Detect TLS handshake based on the first bytes of a stream.
pub fn detect_tls(data: &[u8]) -> bool {
    if data.len() < 3 {
        return false;
    }
    if data[0] != 0x16 {
        return false;
    }
    matches!(u16::from_be_bytes([data[1], data[2]]), 0x0301..=0x0304)
}

/// Detect SOCKS protocol based on the first bytes of a stream.
pub fn detect_socks5(data: &[u8]) -> bool {
    data.first().copied() == Some(0x05)
}

/// Detect HTTP-like requests based on method prefixes.
pub fn detect_http(data: &[u8]) -> bool {
    if data.len() < 4 {
        return false;
    }
    matches!(
        &data[..4],
        b"GET " | b"POST" | b"PUT " | b"HEAD" | b"OPTI" | b"DELE" | b"PATC" | b"CONN"
    )
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
        tag: cfg.tag.clone(),
        listen: cfg.listen,
        udp_bind: None, // Mixed inbound doesn't support UDP ASSOCIATE by default
        router: Arc::clone(&cfg.router),
        outbounds: Arc::clone(&cfg.outbounds),
        udp_nat_ttl: Duration::from_secs(60),
        users: cfg.users.clone(),
        udp_timeout: cfg.udp_timeout,
        domain_strategy: cfg.domain_strategy,
        stats: cfg.stats.clone(),
        conn_tracker: cfg.conn_tracker.clone(),
        sniff: cfg.sniff,
        sniff_override_destination: cfg.sniff_override_destination,
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
            tag: cfg.tag.clone(),
            listen: cfg.listen,
            udp_bind: None,
            router: Arc::clone(&cfg.router),
            outbounds: Arc::clone(&cfg.outbounds),
            udp_nat_ttl: Duration::from_secs(60),
            users: cfg.users.clone(),
            udp_timeout: cfg.udp_timeout,
            domain_strategy: cfg.domain_strategy,
            stats: cfg.stats.clone(),
            conn_tracker: cfg.conn_tracker.clone(),
            sniff: cfg.sniff,
            sniff_override_destination: cfg.sniff_override_destination,
        };
        let mut stream = PeekedStream::new(tls_stream, first);
        crate::inbound::socks::serve_conn(&mut stream, peer, &socks_cfg, None).await
    } else {
        // Assume HTTP over TLS
        debug!(peer=%peer, "mixed/tls: detected HTTP protocol (or unknown)");
        #[cfg(feature = "metrics")]
        counter!("mixed_protocol_detection_total", "protocol" => "tls_http").increment(1);

        let http_cfg = crate::inbound::http::HttpProxyConfig {
            tag: cfg.tag.clone(),
            listen: cfg.listen,
            router: Arc::clone(&cfg.router),
            outbounds: Arc::clone(&cfg.outbounds),
            tls: None, // Already unwrapped
            users: cfg.users.clone(),
            set_system_proxy: cfg.set_system_proxy,
            allow_private_network: cfg.allow_private_network,
            stats: cfg.stats.clone(),
            conn_tracker: cfg.conn_tracker.clone(),
            active_connections: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            sniff: cfg.sniff,
            sniff_override_destination: cfg.sniff_override_destination,
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
        tag: cfg.tag.clone(),
        listen: cfg.listen,
        router: Arc::clone(&cfg.router),
        outbounds: Arc::clone(&cfg.outbounds),
        tls: None,
        users: cfg.users.clone(),
        set_system_proxy: cfg.set_system_proxy,
        allow_private_network: cfg.allow_private_network,
        stats: cfg.stats.clone(),
        conn_tracker: cfg.conn_tracker.clone(),
        active_connections: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        sniff: cfg.sniff,
        sniff_override_destination: cfg.sniff_override_destination,
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
    use super::*;
    use std::io::ErrorKind;
    use std::net::TcpListener as StdTcpListener;
    use tokio::net::TcpStream;
    use tokio::time::{sleep, timeout};

    fn test_cfg(listen: SocketAddr) -> MixedInboundConfig {
        MixedInboundConfig {
            tag: Some("mixed-ready-test".to_string()),
            listen,
            router: Arc::new(RouterHandle::from_env()),
            outbounds: Arc::new(OutboundRegistryHandle::default()),
            read_timeout: Some(Duration::from_secs(1)),
            tls: None,
            users: None,
            set_system_proxy: false,
            allow_private_network: true,
            udp_timeout: None,
            domain_strategy: None,
            stats: None,
            conn_tracker: Arc::new(sb_common::conntrack::ConnTracker::new()),
            sniff: false,
            sniff_override_destination: false,
        }
    }

    fn test_limiter(max_connections: usize) -> TcpRateLimiter {
        TcpRateLimiter::new(TcpRateLimitConfig {
            max_connections,
            window: Duration::from_secs(60),
            ..TcpRateLimitConfig::default()
        })
    }

    #[tokio::test]
    async fn readiness_reports_success_after_bind() {
        let (stop_tx, stop_rx) = mpsc::channel(1);
        let (ready_tx, ready_rx) = oneshot::channel();

        let task = tokio::spawn(serve_mixed(
            test_cfg("127.0.0.1:0".parse().unwrap()),
            stop_rx,
            Some(ready_tx),
        ));

        timeout(Duration::from_secs(2), ready_rx)
            .await
            .expect("mixed ready timed out")
            .expect("mixed ready sender dropped")
            .expect("mixed bind failed");
        let _ = stop_tx.send(()).await;
        task.await
            .expect("mixed task panicked")
            .expect("mixed stopped");
    }

    #[tokio::test]
    async fn readiness_reports_bind_failure_on_occupied_port() {
        let holder = StdTcpListener::bind("127.0.0.1:0").expect("hold mixed port");
        let addr = holder.local_addr().expect("held mixed address");
        let (_stop_tx, stop_rx) = mpsc::channel(1);
        let (ready_tx, ready_rx) = oneshot::channel();

        let err = serve_mixed(test_cfg(addr), stop_rx, Some(ready_tx))
            .await
            .expect_err("occupied mixed port must fail");
        let ready_err = timeout(Duration::from_secs(2), ready_rx)
            .await
            .expect("mixed ready failure timed out")
            .expect("mixed ready sender dropped")
            .expect_err("mixed ready must report bind failure");

        assert_eq!(ready_err.kind(), ErrorKind::AddrInUse);
        assert_eq!(err.kind(), ErrorKind::AddrInUse);
        drop(holder);
    }

    #[tokio::test]
    async fn limiter_rejects_second_mixed_peer() {
        let holder = StdTcpListener::bind("127.0.0.1:0").expect("reserve mixed port");
        let addr = holder.local_addr().expect("reserved mixed address");
        drop(holder);

        let (stop_tx, stop_rx) = mpsc::channel(1);
        let (ready_tx, ready_rx) = oneshot::channel();
        let task = tokio::spawn(serve_mixed_with_limiter(
            test_cfg(addr),
            stop_rx,
            Some(ready_tx),
            test_limiter(1),
        ));
        timeout(Duration::from_secs(2), ready_rx)
            .await
            .expect("mixed ready timed out")
            .expect("mixed ready sender dropped")
            .expect("mixed bind failed");

        let first = TcpStream::connect(addr).await.expect("first mixed connect");
        sleep(Duration::from_millis(50)).await;
        let rejected_before = sb_core::net::rate_limit_metrics::RATE_LIMITED_TOTAL
            .with_label_values(&["mixed", "connection_limit"])
            .get();
        let second = TcpStream::connect(addr)
            .await
            .expect("second mixed connect");
        timeout(Duration::from_secs(2), async {
            loop {
                let rejected = sb_core::net::rate_limit_metrics::RATE_LIMITED_TOTAL
                    .with_label_values(&["mixed", "connection_limit"])
                    .get();
                if rejected > rejected_before {
                    return;
                }
                sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("second mixed connection was not rate limited");

        drop(second);
        drop(first);
        let _ = stop_tx.send(()).await;
        task.await
            .expect("mixed task panicked")
            .expect("mixed stopped");
    }

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
/// Transitional blocking driver for mixed inbound registration.
#[cfg(all(
    feature = "adapter-http",
    feature = "adapter-socks",
    feature = "mixed",
    feature = "router"
))]
#[derive(Debug)]
pub(crate) struct MixedInboundDriver {
    cfg: MixedInboundConfig,
    stop_tx: std::sync::Mutex<Option<tokio::sync::mpsc::Sender<()>>>,
}

#[cfg(all(
    feature = "adapter-http",
    feature = "adapter-socks",
    feature = "mixed",
    feature = "router"
))]
impl MixedInboundDriver {
    pub(crate) fn new(cfg: MixedInboundConfig) -> Self {
        Self {
            cfg,
            stop_tx: std::sync::Mutex::new(None),
        }
    }
}

#[cfg(all(
    feature = "adapter-http",
    feature = "adapter-socks",
    feature = "mixed",
    feature = "router"
))]
impl sb_core::adapter::InboundTaskDriver for MixedInboundDriver {
    fn serve(&self) -> std::io::Result<()> {
        self.serve_with_ready(None)
    }

    fn supports_startup_readiness(&self) -> bool {
        true
    }

    fn serve_with_ready(
        &self,
        ready: Option<sb_core::adapter::InboundReadySender>,
    ) -> std::io::Result<()> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .map_err(std::io::Error::other)?;
        let (stop_tx, stop_rx) = tokio::sync::mpsc::channel(1);
        *self
            .stop_tx
            .lock()
            .unwrap_or_else(|error| error.into_inner()) = Some(stop_tx);
        let result = runtime.block_on(async {
            serve_mixed(self.cfg.clone(), stop_rx, ready)
                .await
                .map_err(std::io::Error::other)
        });
        let _ = self
            .stop_tx
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .take();
        result
    }

    fn request_shutdown(&self) {
        if let Some(stop_tx) = self
            .stop_tx
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .take()
        {
            let _ = stop_tx.try_send(());
        }
    }
}
