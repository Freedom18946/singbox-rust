//! DERP service implementation.

use super::client_registry::ClientRegistry;
use super::protocol::{DerpFrame, FrameType, PublicKey};
use crate::service::{Service, ServiceContext, StartStage};
use httparse::{Request, Status};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::ServerConfig;
use rustls_pemfile;
use sb_config::ir::ServiceIR;
use sb_metrics;
use std::collections::HashMap;
use std::fs;
use std::io::{self, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener as StdTcpListener, UdpSocket as StdUdpSocket};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{mpsc, Notify};
use tokio::task::JoinHandle;
use tokio::time::timeout;
use tokio_rustls::TlsAcceptor;

/// DERP service implementation.
///
/// Provides:
/// - STUN server (UDP) for connectivity checks
/// - HTTP server stub (returns 200 OK for root/health, 404 for others)
/// - DERP protocol server (real frame-based client-to-client relay)
/// - TCP mock relay (legacy, for backward compatibility)
use futures::FutureExt;

trait AsyncReadWrite: AsyncRead + AsyncWrite {}
impl<T: AsyncRead + AsyncWrite> AsyncReadWrite for T {}

type RelayStream = Pin<Box<dyn AsyncReadWrite + Send + Unpin>>;

/// Simple per-IP sliding window rate limiter to protect DERP accept paths.
struct RateLimiter {
    window: Duration,
    max: usize,
    slots: parking_lot::Mutex<HashMap<IpAddr, (Instant, usize)>>,
}

impl RateLimiter {
    fn new(window: Duration, max: usize) -> Self {
        Self {
            window,
            max,
            slots: parking_lot::Mutex::new(HashMap::new()),
        }
    }

    /// Returns true if the caller is within the limit.
    fn allow(&self, ip: IpAddr) -> bool {
        let now = Instant::now();
        let mut map = self.slots.lock();

        // Opportunistically trim stale entries when the map grows.
        if map.len() > 1024 {
            map.retain(|_, (ts, _)| now.saturating_duration_since(*ts) <= self.window);
        }

        let entry = map.entry(ip).or_insert((now, 0));
        if now.saturating_duration_since(entry.0) > self.window {
            entry.0 = now;
            entry.1 = 0;
        }
        entry.1 += 1;
        entry.1 <= self.max
    }
}

pub struct DerpService {
    tag: Arc<str>,
    listen_addr: SocketAddr,
    stun_addr: SocketAddr,
    stun_enabled: bool,
    mesh_psk: Option<String>,
    server_key: PublicKey,
    tls_acceptor: Option<Arc<TlsAcceptor>>,
    client_registry: Arc<ClientRegistry>,
    rate_limiter: Arc<RateLimiter>,
    // Legacy mock relay support (backward compatibility)
    pending_relays: Arc<parking_lot::Mutex<HashMap<String, RelayStream>>>,
    running: AtomicBool,
    shutdown_notify: Arc<Notify>,
    stun_task: parking_lot::Mutex<Option<JoinHandle<()>>>,
    http_task: parking_lot::Mutex<Option<JoinHandle<()>>>,
    mesh_with: Vec<String>,
    mesh_tasks: parking_lot::Mutex<Vec<JoinHandle<()>>>,
}

/// How long to keep a half-open relay connection while waiting for a peer.
const RELAY_IDLE_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug, Clone)]
struct RelayHandshake {
    session: String,
    token: Option<String>,
}

impl DerpService {
    /// Create a new DERP service from IR configuration.
    pub fn from_ir(
        ir: &ServiceIR,
        _ctx: &ServiceContext,
    ) -> Result<Arc<Self>, Box<dyn std::error::Error + Send + Sync>> {
        let tag: Arc<str> = Arc::from(
            ir.tag
                .as_deref()
                .unwrap_or("derp")
                .to_string()
                .into_boxed_str(),
        );

        // Parse listen address
        let listen_ip = ir
            .derp_listen
            .as_deref()
            .unwrap_or("127.0.0.1")
            .parse()
            .map_err(|e| format!("invalid listen address: {}", e))?;
        let listen_port = ir.derp_listen_port.unwrap_or(3478);
        let listen_addr = SocketAddr::new(listen_ip, listen_port);

        // STUN port usually matches the DERP port for Tailscale.
        let stun_port = ir.derp_stun_listen_port.unwrap_or(listen_port);
        let stun_enabled = ir.derp_stun_enabled.unwrap_or(true);
        let stun_addr = SocketAddr::new(listen_ip, stun_port);

        let mesh_psk = load_mesh_psk(ir)?;

        // Load or generate server key (persistent if path configured)
        let server_key = load_or_generate_server_key(ir.derp_server_key_path.as_deref())?;

        // Create TLS acceptor if configured
        let tls_acceptor = create_tls_acceptor(
            ir.derp_tls_cert_path.as_deref(),
            ir.derp_tls_key_path.as_deref(),
        )?;

        let mesh_with = ir.derp_mesh_with.clone().unwrap_or_default();

        if tls_acceptor.is_some() {
            tracing::info!(
                service = "derp",
                tag = tag.as_ref(),
                "TLS enabled for DERP connections"
            );
        }

        tracing::info!(
            service = "derp",
            tag = tag.as_ref(),
            listen = %listen_addr,
            stun_port = stun_port,
            stun_enabled,
            tls_enabled = tls_acceptor.is_some(),
            mesh_psk = mesh_psk.as_deref().map(|_| "<redacted>"),
            mesh_peers = mesh_with.len(),
            server_key = ?server_key,
            "DERP service initialized (HTTP + STUN + DERP protocol + legacy mock relay)"
        );

        Ok(Arc::new(Self {
            tag: tag.clone(),
            listen_addr,
            stun_addr,
            stun_enabled,
            mesh_psk,
            server_key,
            tls_acceptor,
            client_registry: Arc::new(ClientRegistry::new(tag.clone())),
            rate_limiter: Arc::new(RateLimiter::new(Duration::from_secs(10), 120)),
            pending_relays: Arc::new(parking_lot::Mutex::new(HashMap::new())),
            running: AtomicBool::new(false),
            shutdown_notify: Arc::new(Notify::new()),
            stun_task: parking_lot::Mutex::new(None),
            http_task: parking_lot::Mutex::new(None),
            mesh_with,
            mesh_tasks: parking_lot::Mutex::new(Vec::new()),
        }))
    }

    /// Run the STUN server loop.
    async fn run_stun_server(
        socket: UdpSocket,
        shutdown: Arc<Notify>,
        tag: Arc<str>,
    ) -> io::Result<()> {
        let addr = socket.local_addr()?;
        tracing::info!(service = "derp", listen = %addr, "STUN server started");

        let mut buf = vec![0u8; 65535];

        loop {
            tokio::select! {
                _ = shutdown.notified() => {
                    tracing::info!(service = "derp", "STUN server shutting down");
                    break;
                }
                result = socket.recv_from(&mut buf) => {
                    match result {
                        Ok((len, peer)) => {
                            if let Some(response) = Self::handle_stun_packet(&buf[..len], peer) {
                                if let Err(e) = socket.send_to(&response, peer).await {
                                    tracing::debug!(service = "derp", error = %e, "Failed to send STUN response");
                                    sb_metrics::inc_derp_stun(&tag, "send_fail");
                                } else {
                                    sb_metrics::inc_derp_stun(&tag, "ok");
                                }
                            }
                        }
                        Err(e) => {
                            tracing::error!(service = "derp", error = %e, "STUN recv error");
                            sb_metrics::inc_derp_stun(&tag, "recv_error");
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Minimal HTTP server stub (200 for "/"  or "/health", 404 otherwise).
    #[allow(clippy::too_many_arguments)]
    async fn run_http_server(
        listener: TcpListener,
        shutdown: Arc<Notify>,
        tag: Arc<str>,
        rate_limiter: Arc<RateLimiter>,
        client_registry: Arc<ClientRegistry>,
        server_key: PublicKey,
        pending_relays: Arc<parking_lot::Mutex<HashMap<String, RelayStream>>>,
        mesh_psk: Option<String>,
        tls_acceptor: Option<Arc<TlsAcceptor>>,
    ) -> io::Result<()> {
        let addr = listener.local_addr()?;
        tracing::info!(service = "derp", listen = %addr, tls_enabled = tls_acceptor.is_some(), "HTTP/DERP server started");

        loop {
            tokio::select! {
                _ = shutdown.notified() => {
                    tracing::info!(service = "derp", "HTTP/DERP server shutting down");
                    break;
                }
                result = listener.accept() => {
                    let (stream, peer_addr) = result?;

                    if !rate_limiter.allow(peer_addr.ip()) {
                        sb_metrics::inc_derp_connection(&tag, "rate_limited");
                        tracing::warn!(service = "derp", peer = %peer_addr, "DERP connection rate-limited");
                        continue;
                    }

                    let client_registry = client_registry.clone();
                    let pending_relays = pending_relays.clone();
                    let mesh_psk = mesh_psk.clone();
                    let tls_acceptor = tls_acceptor.clone();
                    let tag = tag.clone();

                    tokio::spawn(async move {
                        let result = match tls_acceptor {
                            Some(acceptor) => {
                                match acceptor.accept(stream).await {
                                    Ok(tls_stream) => {
                                        tracing::debug!(service = "derp", peer = %peer_addr, "Accepted DERP TLS connection");
                                        Self::handle_http_connection(
                                            tls_stream,
                                            peer_addr,
                                            tag,
                                            client_registry,
                                            server_key,
                                            pending_relays,
                                            mesh_psk,
                                        ).await
                                    }
                                    Err(e) => {
                                        client_registry.metrics().connect_failed("tls_error");
                                        tracing::warn!(service = "derp", peer = %peer_addr, error = %e, "TLS handshake failed for DERP connection");
                                        return;
                                    }
                                }
                            }
                            None => {
                                Self::handle_http_connection(
                                    stream,
                                    peer_addr,
                                    tag,
                                    client_registry,
                                    server_key,
                                    pending_relays,
                                    mesh_psk,
                                ).await
                            }
                        };

                        if let Err(e) = result {
                            tracing::error!(service = "derp", peer = %peer_addr, error = %e, "Connection closed with error");
                        }
                    });
                }
            }
        }

        Ok(())
    }

    async fn handle_http_connection<S>(
        mut stream: S,
        peer: SocketAddr,
        tag: Arc<str>,
        client_registry: Arc<ClientRegistry>,
        server_key: PublicKey,
        pending_relays: Arc<parking_lot::Mutex<HashMap<String, RelayStream>>>,
        mesh_psk: Option<String>,
    ) -> io::Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        // Read a small prefix to decide HTTP vs DERP protocol vs legacy mock relay.
        let mut buf = vec![0u8; 1024];
        let read = match timeout(Duration::from_millis(200), stream.read(&mut buf)).await {
            Ok(result) => result?,
            Err(_) => 0,
        };

        if read == 0 {
            tracing::debug!(service = "derp", peer = %peer, "No initial bytes; assuming DERP protocol");
            return Self::handle_derp_client(
                stream,
                peer,
                tag.clone(),
                client_registry,
                server_key,
                false, // is_mesh_peer
            )
            .await;
        }

        let prefix = &buf[..read];
        let initial_data = prefix.to_vec();

        // Check for HTTP
        if Self::looks_like_http(prefix) {
            if let Some(upgraded_stream) =
                Self::handle_http_request(stream, prefix, peer, tag.clone(), mesh_psk).await?
            {
                tracing::info!(service = "derp", peer = %peer, "Upgraded to DERP mesh connection");
                return Self::handle_derp_client(
                    upgraded_stream,
                    peer,
                    tag,
                    client_registry,
                    server_key,
                    true, // is_mesh_peer
                )
                .await;
            }
            return Ok(());
        }

        // Check for DERP protocol (starts with frame type byte)
        if Self::looks_like_derp_protocol(prefix) {
            tracing::debug!(service = "derp", peer = %peer, "Detected DERP protocol connection");
            let prefixed = PrefixedStream::new(stream, initial_data);
            return Self::handle_derp_client(
                prefixed,
                peer,
                tag,
                client_registry,
                server_key,
                false, // is_mesh_peer
            )
            .await;
        }

        // Fallback to legacy mock relay (for backward compatibility)
        tracing::debug!(service = "derp", peer = %peer, "Using legacy mock relay");
        let handshake = match Self::parse_relay_session(prefix) {
            Some(s) => s,
            None => {
                let _ = stream
                    .write_all(b"ERR derp handshake (expected \"DERP <session>\\n\")\n")
                    .await;
                let _ = stream.shutdown().await;
                client_registry.metrics().connect_failed("bad_handshake");
                tracing::debug!(service = "derp", peer = %peer, "closing TCP connection due to bad handshake");
                return Ok(());
            }
        };

        // Consume the handshake line so it's not echoed to the peer
        let handshake_len = prefix
            .iter()
            .position(|&b| b == b'\n')
            .map(|i| i + 1)
            .unwrap_or(prefix.len());

        let remaining_data = if handshake_len < prefix.len() {
            prefix[handshake_len..].to_vec()
        } else {
            Vec::new()
        };

        let mut prefixed_stream = PrefixedStream::new(stream, remaining_data);

        if let Err(e) = Self::validate_token(&handshake, mesh_psk.as_deref()) {
            let _ = prefixed_stream
                .write_all(b"ERR unauthorized (invalid DERP token)\n")
                .await;
            let _ = prefixed_stream.shutdown().await;
            client_registry.metrics().connect_failed("unauthorized");
            tracing::warn!(service = "derp", peer = %peer, error = %e, "Rejecting DERP mock relay connection");
            return Ok(());
        }

        Self::handle_relay_session(
            handshake.session,
            Box::pin(prefixed_stream),
            pending_relays,
            peer,
        )
        .await
    }

    fn looks_like_http(prefix: &[u8]) -> bool {
        const HTTP_PREFIXES: &[&[u8]] = &[
            b"GET ",
            b"HEAD ",
            b"POST ",
            b"PUT ",
            b"DELETE ",
            b"OPTIONS ",
        ];
        HTTP_PREFIXES.iter().any(|p| prefix.starts_with(p))
    }

    fn looks_like_derp_protocol(prefix: &[u8]) -> bool {
        if prefix.is_empty() {
            return false;
        }
        // Check if first byte is a valid DERP frame type
        matches!(
            FrameType::from_u8(prefix[0]),
            Ok(FrameType::ServerKey)
                | Ok(FrameType::ClientInfo)
                | Ok(FrameType::SendPacket)
                | Ok(FrameType::RecvPacket)
                | Ok(FrameType::KeepAlive)
                | Ok(FrameType::Ping)
                | Ok(FrameType::Pong)
                | Ok(FrameType::PeerGone)
                | Ok(FrameType::PeerPresent)
        )
    }

    fn parse_relay_session(prefix: &[u8]) -> Option<RelayHandshake> {
        let line = String::from_utf8_lossy(prefix);
        let first_line = line.lines().next()?.trim();
        let mut parts = first_line.split_whitespace();
        let first = parts.next()?;
        if first != "DERP" {
            return None;
        }

        let mut session = parts.next()?.to_string();
        if session == "session" {
            session = parts.next()?.to_string();
        }

        if session.is_empty() {
            return None;
        }

        let mut token = None;
        for part in parts {
            if let Some(val) = part.strip_prefix("token=") {
                if !val.is_empty() {
                    token = Some(val.to_string());
                }
            }
        }

        Some(RelayHandshake { session, token })
    }

    async fn handle_http_request<S>(
        mut stream: S,
        prefix: &[u8],
        peer: SocketAddr,
        tag: Arc<str>,
        mesh_psk: Option<String>,
    ) -> io::Result<Option<S>>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        // Re-parse HTTP request from already-read prefix.
        let buffer = prefix.to_vec();
        let mut headers = [httparse::EMPTY_HEADER; 32];
        let mut req = Request::new(&mut headers);
        let status = req
            .parse(&buffer)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        if status == Status::Partial {
            let res = Self::write_response(
                &mut stream,
                "400 Bad Request",
                "incomplete request\n",
                false,
            )
            .await;
            sb_metrics::inc_derp_http(&tag, "400");
            res?;
            return Ok(None);
        }

        let method = req.method.unwrap_or("");
        let path = req.path.unwrap_or("/");

        if let Some(expected) = mesh_psk.as_deref() {
            let provided = req
                .headers
                .iter()
                .find(|h| h.name.eq_ignore_ascii_case("x-derp-mesh-psk"))
                .and_then(|h| std::str::from_utf8(h.value).ok())
                .map(str::trim);
            if provided != Some(expected) {
                sb_metrics::inc_derp_http(&tag, "401");
                tracing::warn!(service = "derp", peer = %peer, "HTTP request rejected (mesh PSK)");
                Self::write_response(
                    &mut stream,
                    "401 Unauthorized",
                    "mesh psk required\n",
                    method.eq_ignore_ascii_case("HEAD"),
                )
                .await?;
                return Ok(None);
            }

            // Check for mesh upgrade
            if path == "/derp/mesh" {
                Self::write_response(&mut stream, "101 Switching Protocols", "", false).await?;
                return Ok(Some(stream));
            }
        }

        let (status_line, body) = match (method, path) {
            ("GET", "/") | ("GET", "/health") => ("200 OK", "OK\n"),
            ("HEAD", "/") | ("HEAD", "/health") => ("200 OK", ""),
            _ => ("404 Not Found", "not found\n"),
        };

        Self::write_response(
            &mut stream,
            status_line,
            body,
            method.eq_ignore_ascii_case("HEAD"),
        )
        .await?;
        if let Some(code) = status_line.split_whitespace().next() {
            sb_metrics::inc_derp_http(&tag, code);
        }
        tracing::debug!(service = "derp", peer = %peer, path, status = status_line);
        Ok(None)
    }

    fn validate_token(
        handshake: &RelayHandshake,
        mesh_psk: Option<&str>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if let Some(expected) = mesh_psk {
            if handshake.token.as_deref() != Some(expected) {
                return Err(
                    io::Error::new(io::ErrorKind::PermissionDenied, "invalid DERP token").into(),
                );
            }
        }
        Ok(())
    }

    /// Handle a DERP protocol client connection.
    async fn handle_derp_client<S>(
        stream: S,
        peer: SocketAddr,
        tag: Arc<str>,
        client_registry: Arc<ClientRegistry>,
        server_key: PublicKey,
        is_mesh_peer: bool,
    ) -> io::Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        tracing::info!(service = "derp", tag = %tag, peer = %peer, "DERP client connected");

        let (mut read_half, mut write_half) = tokio::io::split(stream);

        // Send ServerKey frame
        let server_key_frame = DerpFrame::ServerKey { key: server_key };
        server_key_frame
            .write_to_async(&mut write_half)
            .await
            .map_err(|e| io::Error::other(format!("Failed to send ServerKey: {}", e)))?;

        // Read ClientInfo frame (or ServerKey if mesh peer)
        let client_key = match DerpFrame::read_from_async(&mut read_half).await {
            Ok(DerpFrame::ClientInfo { key }) => key,
            Ok(DerpFrame::ServerKey { key }) if is_mesh_peer => key,
            Ok(other) => {
                tracing::warn!(service = "derp", peer = %peer, frame = ?other.frame_type(), "Expected ClientInfo");
                client_registry.metrics().connect_failed("handshake");
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Expected ClientInfo",
                ));
            }
            Err(e) => {
                client_registry.metrics().connect_failed("handshake");
                return Err(io::Error::other(format!(
                    "Failed to read ClientInfo: {}",
                    e
                )));
            }
        };

        tracing::info!(service = "derp", peer = %peer, client_key = ?client_key, "Client registered");

        // Create channel for sending frames to this client
        let (tx, mut rx) = mpsc::unbounded_channel();

        // Register client or mesh peer
        if is_mesh_peer {
            if let Err(e) = client_registry.register_mesh_peer(client_key, tx) {
                tracing::error!(service = "derp", peer = %peer, error = %e, "Failed to register mesh peer");
                return Err(io::Error::other(e));
            }
            tracing::info!(service = "derp", peer = %peer, key = ?client_key, "Mesh peer registered");
        } else if let Err(e) = client_registry.register_client(client_key, peer, tx) {
            tracing::error!(service = "derp", peer = %peer, error = %e, "Failed to register client");
            return Err(io::Error::other(e));
        }

        // Broadcast peer presence to other clients
        client_registry.broadcast_peer_present(&client_key);

        // Spawn task to write outgoing frames
        let client_key_for_writer = client_key;
        let write_task = tokio::spawn(async move {
            while let Some(frame) = rx.recv().await {
                if let Err(e) = frame.write_to_async(&mut write_half).await {
                    tracing::debug!(service = "derp", client = ?client_key_for_writer, error = %e, "Failed to write frame");
                    break;
                }
            }
        });

        // Read and process incoming frames
        loop {
            let frame = match DerpFrame::read_from_async(&mut read_half).await {
                Ok(f) => f,
                Err(e) => {
                    tracing::debug!(service = "derp", peer = %peer, client = ?client_key, error = %e, "Connection closed or error reading frame");
                    break;
                }
            };

            match frame {
                DerpFrame::SendPacket { dst_key, packet } => {
                    // Relay packet to destination client
                    if let Err(e) = client_registry.relay_packet(&client_key, &dst_key, packet) {
                        tracing::debug!(service = "derp", src = ?client_key, dst = ?dst_key, error = %e, "Failed to relay packet");
                    }
                }
                DerpFrame::ForwardPacket {
                    src_key,
                    dst_key,
                    packet,
                } => {
                    if is_mesh_peer {
                        if let Err(e) =
                            client_registry.handle_forward_packet(&src_key, &dst_key, packet)
                        {
                            tracing::debug!(service = "derp", src = ?src_key, dst = ?dst_key, error = %e, "Failed to handle forwarded packet");
                        }
                    } else {
                        tracing::warn!(service = "derp", client = ?client_key, "Received ForwardPacket from non-mesh peer");
                    }
                }
                DerpFrame::PeerPresent { key } => {
                    if is_mesh_peer {
                        client_registry.register_remote_client(key, client_key);
                    }
                }
                DerpFrame::PeerGone { key } => {
                    if is_mesh_peer {
                        client_registry.unregister_remote_client(&key);
                    }
                }
                DerpFrame::KeepAlive => {
                    // Update last seen
                    client_registry.touch_client(&client_key);
                }
                DerpFrame::Ping { data } => {
                    // Respond with Pong
                    let pong = DerpFrame::Pong { data };
                    if let Err(e) = client_registry.send_to_client(&client_key, pong) {
                        tracing::debug!(service = "derp", client = ?client_key, error = %e, "Failed to send Pong");
                    }
                }
                _ => {
                    tracing::warn!(service = "derp", client = ?client_key, frame_type = ?frame.frame_type(), "Unexpected frame from client");
                }
            }
        }

        // Cleanup: unregister client and notify peers
        if is_mesh_peer {
            client_registry.unregister_mesh_peer(&client_key);
        } else {
            client_registry.unregister_client(&client_key);
            client_registry.broadcast_peer_gone(&client_key);
        }

        // Cancel write task
        write_task.abort();

        tracing::info!(service = "derp", peer = %peer, client = ?client_key, "Client disconnected");
        Ok(())
    }

    async fn run_mesh_client(
        peer_addr_str: String,
        psk: String,
        tag: Arc<str>,
        client_registry: Arc<ClientRegistry>,
        server_key: PublicKey,
        shutdown: Arc<Notify>,
    ) {
        loop {
            if shutdown.notified().now_or_never().is_some() {
                break;
            }

            tracing::info!(service = "derp", peer = %peer_addr_str, "Connecting to mesh peer");

            match TcpStream::connect(&peer_addr_str).await {
                Ok(mut stream) => {
                    // Send HTTP upgrade request
                    let req = format!(
                        "GET /derp/mesh HTTP/1.1\r\n\
                         Host: {}\r\n\
                         Connection: Upgrade\r\n\
                         Upgrade: derp\r\n\
                         x-derp-mesh-psk: {}\r\n\
                         \r\n",
                        peer_addr_str, psk
                    );

                    if let Err(e) = stream.write_all(req.as_bytes()).await {
                        tracing::error!(service = "derp", peer = %peer_addr_str, error = %e, "Failed to send mesh handshake");
                        tokio::time::sleep(Duration::from_secs(5)).await;
                        continue;
                    }

                    // Read response
                    let mut buf = vec![0u8; 1024];
                    let mut filled = 0;
                    let mut handshake_done = false;

                    loop {
                        match stream.read(&mut buf[filled..]).await {
                            Ok(n) if n > 0 => {
                                filled += n;
                                let response = String::from_utf8_lossy(&buf[..filled]);
                                if let Some(idx) = response.find("\r\n\r\n") {
                                    if response.contains("101 Switching Protocols") {
                                        tracing::info!(service = "derp", peer = %peer_addr_str, "Mesh handshake successful");

                                        let peer_addr = stream
                                            .peer_addr()
                                            .unwrap_or_else(|_| "0.0.0.0:0".parse().unwrap());

                                        let prefix = buf[idx + 4..filled].to_vec();
                                        let prefixed_stream = PrefixedStream::new(stream, prefix);

                                        if let Err(e) = Self::handle_derp_client(
                                            prefixed_stream,
                                            peer_addr,
                                            tag.clone(),
                                            client_registry.clone(),
                                            server_key,
                                            true,
                                        )
                                        .await
                                        {
                                            tracing::error!(service = "derp", peer = %peer_addr_str, error = %e, "Mesh client error");
                                            tokio::time::sleep(Duration::from_secs(1)).await;
                                        }
                                        handshake_done = true;
                                        break;
                                    } else {
                                        tracing::warn!(service = "derp", peer = %peer_addr_str, response = %response, "Mesh handshake failed - expected 101");
                                        handshake_done = true;
                                        break;
                                    }
                                }
                                if filled == buf.len() {
                                    tracing::error!(service = "derp", peer = %peer_addr_str, "Mesh handshake buffer overflow");
                                    break;
                                }
                            }
                            Ok(_) => {
                                tracing::warn!(service = "derp", peer = %peer_addr_str, "Mesh handshake closed");
                                break;
                            }
                            Err(e) => {
                                tracing::error!(service = "derp", peer = %peer_addr_str, error = %e, "Mesh handshake read error");
                                break;
                            }
                        }
                    }

                    if !handshake_done {
                        tokio::time::sleep(Duration::from_secs(1)).await;
                    }
                }
                Err(e) => {
                    tracing::error!(service = "derp", peer = %peer_addr_str, error = %e, "Failed to connect to mesh peer");
                }
            }

            tokio::select! {
                _ = tokio::time::sleep(Duration::from_secs(5)) => {}
                _ = shutdown.notified() => { break; }
            }
        }
    }

    async fn handle_relay_session(
        session: String,
        mut stream: RelayStream,
        pending_relays: Arc<parking_lot::Mutex<HashMap<String, RelayStream>>>,
        peer: SocketAddr,
    ) -> io::Result<()> {
        // Try to find a waiting peer without holding the lock across await points.
        let mut maybe_other = {
            let mut map = pending_relays.lock();
            map.remove(&session)
        };
        if let Some(mut other) = maybe_other.take() {
            tracing::info!(service = "derp", peer = %peer, session = %session, "Pairing DERP mock relay connections");
            let _ = tokio::io::copy_bidirectional(&mut stream, &mut other).await;
            return Ok(());
        }

        // Otherwise store and wait for a partner.
        tracing::info!(service = "derp", peer = %peer, session = %session, "Waiting for DERP mock relay peer");
        pending_relays.lock().insert(session.clone(), stream);
        let pending_relays = pending_relays.clone();
        tokio::spawn(async move {
            tokio::time::sleep(RELAY_IDLE_TIMEOUT).await;
            let mut stale = {
                let mut map = pending_relays.lock();
                map.remove(&session)
            };
            if let Some(mut stale_stream) = stale.take() {
                let _ = stale_stream.shutdown().await;
                tracing::debug!(service = "derp", session = %session, "Dropped idle DERP mock relay half-connection");
            }
        });
        Ok(())
    }

    async fn write_response<S>(
        stream: &mut S,
        status: &str,
        body: &str,
        head_only: bool,
    ) -> io::Result<()>
    where
        S: AsyncWrite + Unpin,
    {
        let body_bytes = body.as_bytes();
        let response = format!(
            "HTTP/1.1 {status}\r\nContent-Length: {}\r\nContent-Type: text/plain; charset=utf-8\r\nConnection: close\r\n\r\n",
            body_bytes.len()
        );

        stream.write_all(response.as_bytes()).await?;
        if !head_only && !body_bytes.is_empty() {
            stream.write_all(body_bytes).await?;
        }
        stream.shutdown().await?;
        Ok(())
    }

    /// Handle a potential STUN packet and return a response if applicable.
    ///
    /// Implements a minimal STUN Binding Request handler.
    fn handle_stun_packet(packet: &[u8], peer: SocketAddr) -> Option<Vec<u8>> {
        // STUN header is 20 bytes
        if packet.len() < 20 {
            return None;
        }

        // Check for Binding Request (0x0001)
        // First 2 bits must be 0
        if packet[0] & 0xC0 != 0 {
            return None;
        }

        let msg_type = u16::from_be_bytes([packet[0], packet[1]]);
        let _msg_len = u16::from_be_bytes([packet[2], packet[3]]);
        let magic_cookie = &packet[4..8];
        let transaction_id = &packet[8..20];

        // Binding Request = 0x0001
        if msg_type != 0x0001 {
            return None;
        }

        // Validate magic cookie (0x2112A442) for RFC 5389
        if magic_cookie != [0x21, 0x12, 0xA4, 0x42] {
            // Legacy STUN (RFC 3489) doesn't require magic cookie check,
            // but we primarily support modern STUN for Tailscale.
            // Tailscale uses RFC 5389.
        }

        // Construct Binding Response (0x0101)
        let mut response = Vec::with_capacity(32);

        // Header
        response.extend_from_slice(&0x0101u16.to_be_bytes()); // Binding Response
                                                              // Length will be filled later
        response.extend_from_slice(&0u16.to_be_bytes());
        response.extend_from_slice(magic_cookie);
        response.extend_from_slice(transaction_id);

        // Add XOR-MAPPED-ADDRESS attribute (0x0020)
        response.extend_from_slice(&0x0020u16.to_be_bytes()); // Attribute Type
        response.extend_from_slice(&8u16.to_be_bytes()); // Attribute Length (8 bytes for IPv4)

        // Reserved (1 byte) + Family (1 byte)
        response.push(0);
        match peer {
            SocketAddr::V4(addr) => {
                response.push(0x01); // IPv4

                // X-Port
                let port = peer.port();
                let xor_port = port ^ 0x2112; // Magic cookie high 16 bits
                response.extend_from_slice(&xor_port.to_be_bytes());

                // X-Address
                let ip_octets = addr.ip().octets();
                let cookie_octets = [0x21, 0x12, 0xA4, 0x42];
                for i in 0..4 {
                    response.push(ip_octets[i] ^ cookie_octets[i]);
                }
            }
            SocketAddr::V6(addr) => {
                // Adjust length for IPv6 (20 bytes total value)
                let len_pos = 22; // Position of attribute length
                response[len_pos] = 0;
                response[len_pos + 1] = 20;

                response.push(0x02); // IPv6

                // X-Port
                let port = peer.port();
                let xor_port = port ^ 0x2112;
                response.extend_from_slice(&xor_port.to_be_bytes());

                // X-Address
                let ip_octets = addr.ip().octets();
                let cookie_octets = [0x21, 0x12, 0xA4, 0x42];
                let transaction_id_octets = transaction_id;

                // First 4 bytes XOR with magic cookie
                for i in 0..4 {
                    response.push(ip_octets[i] ^ cookie_octets[i]);
                }
                // Remaining 12 bytes XOR with transaction ID
                for i in 0..12 {
                    response.push(ip_octets[i + 4] ^ transaction_id_octets[i]);
                }
            }
        }

        // Update message length (total length - 20 bytes header)
        let total_len = response.len() as u16 - 20;
        response[2] = (total_len >> 8) as u8;
        response[3] = (total_len & 0xFF) as u8;

        Some(response)
    }
}

/// A stream adapter that replays already-read prefix bytes before delegating to the inner stream.
struct PrefixedStream<S> {
    prefix: Vec<u8>,
    offset: usize,
    inner: S,
}

impl<S> PrefixedStream<S> {
    fn new(inner: S, prefix: Vec<u8>) -> Self {
        Self {
            prefix,
            offset: 0,
            inner,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for PrefixedStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.offset < self.prefix.len() {
            let remaining = self.prefix.len() - self.offset;
            let to_copy = remaining.min(buf.remaining());
            let start = self.offset;
            let end = start + to_copy;
            buf.put_slice(&self.prefix[start..end]);
            self.offset += to_copy;
            return Poll::Ready(Ok(()));
        }

        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for PrefixedStream<S> {
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

impl Service for DerpService {
    fn service_type(&self) -> &str {
        "derp"
    }

    fn tag(&self) -> &str {
        &self.tag
    }

    fn start(&self, stage: StartStage) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        match stage {
            StartStage::Initialize => {
                tracing::debug!(
                    service = "derp",
                    tag = self.tag.as_ref(),
                    "Initialize stage"
                );
                Ok(())
            }
            StartStage::Start => {
                if self.running.swap(true, Ordering::SeqCst) {
                    return Ok(());
                }

                let listen_addr = self.listen_addr;
                let shutdown = self.shutdown_notify.clone();
                let mesh_psk = self.mesh_psk.clone();
                let client_registry = self.client_registry.clone();
                let server_key = self.server_key;
                let tag = self.tag.clone();

                // Pre-bind sockets so failures surface synchronously.
                let std_http_listener = StdTcpListener::bind(listen_addr)?;
                std_http_listener.set_nonblocking(true)?;
                let http_listener = TcpListener::from_std(std_http_listener)?;

                let _http_addr = http_listener.local_addr()?;

                // HTTP stub server (TCP)
                let http_shutdown = shutdown.clone();
                let pending_relays = self.pending_relays.clone();
                let tls_acceptor = self.tls_acceptor.clone();
                let rate_limiter = self.rate_limiter.clone();
                let mesh_psk_http = mesh_psk.clone();
                let http_handle = tokio::spawn(async move {
                    if let Err(e) = Self::run_http_server(
                        http_listener,
                        http_shutdown,
                        tag,
                        rate_limiter,
                        client_registry,
                        server_key,
                        pending_relays,
                        mesh_psk_http,
                        tls_acceptor,
                    )
                    .await
                    {
                        tracing::error!(service = "derp", error = %e, "HTTP stub server failed");
                    }
                });
                *self.http_task.lock() = Some(http_handle);

                // Optional STUN server (UDP)
                tracing::info!(
                    service = "derp",
                    tag = self.tag.as_ref(),
                    listen = %listen_addr,
                    stun = %self.stun_addr,
                    stun_enabled = self.stun_enabled,
                    "Starting DERP service"
                );

                if self.stun_enabled {
                    let std_udp = StdUdpSocket::bind(self.stun_addr)?;
                    std_udp.set_nonblocking(true)?;
                    let udp_socket = UdpSocket::from_std(std_udp)?;
                    let _stun_addr = udp_socket.local_addr().unwrap_or(self.stun_addr);
                    let tag = self.tag.clone();

                    let stun_shutdown = shutdown.clone();
                    let stun_handle = tokio::spawn(async move {
                        if let Err(e) = Self::run_stun_server(udp_socket, stun_shutdown, tag).await
                        {
                            tracing::error!(service = "derp", error = %e, "STUN server failed");
                        }
                    });

                    *self.stun_task.lock() = Some(stun_handle);
                } else {
                    tracing::info!(
                        service = "derp",
                        tag = self.tag.as_ref(),
                        "STUN disabled for DERP service"
                    );
                }
                // Ensure metrics surface even before clients connect.
                sb_metrics::set_derp_clients(&self.tag, 0);

                // Mesh peers
                if let Some(psk) = mesh_psk.clone() {
                    let mut tasks = self.mesh_tasks.lock();
                    for peer in &self.mesh_with {
                        let peer_addr = peer.clone();
                        let psk = psk.clone();
                        let tag = self.tag.clone();
                        let client_registry = self.client_registry.clone();
                        let server_key = self.server_key;
                        let shutdown = shutdown.clone();

                        let task = tokio::spawn(async move {
                            Self::run_mesh_client(
                                peer_addr,
                                psk,
                                tag,
                                client_registry,
                                server_key,
                                shutdown,
                            )
                            .await;
                        });
                        tasks.push(task);
                    }
                }

                Ok(())
            }
            StartStage::PostStart | StartStage::Started => Ok(()),
        }
    }

    fn close(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        tracing::info!(
            service = "derp",
            tag = self.tag.as_ref(),
            "Closing DERP service"
        );

        self.running.store(false, Ordering::SeqCst);
        self.shutdown_notify.notify_waiters();
        sb_metrics::set_derp_clients(&self.tag, 0);

        if let Some(handle) = self.stun_task.lock().take() {
            // We don't block on join here to avoid deadlocks in shutdown
            // The notify signal should terminate the loop
            drop(handle);
        }

        if let Some(handle) = self.http_task.lock().take() {
            // We don't block on join here to avoid deadlocks in shutdown
            // The notify signal should terminate the loop
            drop(handle);
        }

        {
            let mut tasks = self.mesh_tasks.lock();
            for task in tasks.drain(..) {
                drop(task);
            }
        }

        Ok(())
    }
}

/// Load or generate DERP server key.
///
/// If `key_path` is provided and file exists, load key from file.
/// If file doesn't exist, generate new key and save it.
/// If no path provided, generate ephemeral key (logs warning).
fn load_or_generate_server_key(key_path: Option<&str>) -> io::Result<PublicKey> {
    if let Some(path) = key_path {
        // Try to load existing key
        match load_key_from_file(path) {
            Ok(key) => {
                tracing::info!(service = "derp", path = path, "Loaded server key from file");
                Ok(key)
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                // File doesn't exist, generate and save new key
                tracing::info!(
                    service = "derp",
                    path = path,
                    "Generating new server key (file not found)"
                );
                let key = generate_secure_server_key()?;
                save_key_to_file(path, &key)?;
                tracing::info!(
                    service = "derp",
                    path = path,
                    "Saved new server key to file"
                );
                Ok(key)
            }
            Err(e) => {
                // Other error (permissions, corruption, etc.)
                Err(io::Error::other(format!(
                    "Failed to load server key from {}: {}",
                    path, e
                )))
            }
        }
    } else {
        // No path provided, generate ephemeral key
        tracing::warn!(
            service = "derp",
            "No derp_server_key_path configured - generating ephemeral key (will change on restart)"
        );
        generate_secure_server_key()
    }
}

/// Generate cryptographically secure server key using ring.
fn generate_secure_server_key() -> io::Result<PublicKey> {
    use ring::rand::{SecureRandom, SystemRandom};

    let rng = SystemRandom::new();
    let mut key = [0u8; 32];
    rng.fill(&mut key)
        .map_err(|e| io::Error::other(format!("RNG error: {}", e)))?;
    Ok(key)
}

/// Load server key from file (32 bytes raw binary).
fn load_key_from_file(path: &str) -> io::Result<PublicKey> {
    let mut file = fs::File::open(path)?;
    let mut key = [0u8; 32];
    file.read_exact(&mut key)?;
    Ok(key)
}

/// Save server key to file with secure permissions (0600 on Unix).
fn save_key_to_file(path: &str, key: &PublicKey) -> io::Result<()> {
    use std::path::Path;

    // Create parent directories if needed
    if let Some(parent) = Path::new(path).parent() {
        fs::create_dir_all(parent)?;
    }

    // Write key to file
    let mut file = fs::File::create(path)?;
    file.write_all(key)?;

    // Set secure permissions (owner read/write only) on Unix
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = file.metadata()?.permissions();
        perms.set_mode(0o600);
        fs::set_permissions(path, perms)?;
    }

    Ok(())
}

/// Load TLS certificates from PEM file.
fn load_tls_certs(path: &str) -> io::Result<Vec<CertificateDer<'static>>> {
    let cert_bytes = fs::read(path)?;
    let mut cursor = std::io::Cursor::new(cert_bytes);
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cursor)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Failed to parse certificates: {}", e),
            )
        })?;

    if certs.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "No certificates found in PEM file",
        ));
    }

    Ok(certs)
}

/// Load TLS private key from PEM file.
fn load_tls_private_key(path: &str) -> io::Result<PrivateKeyDer<'static>> {
    let key_bytes = fs::read(path)?;
    let mut cursor = std::io::Cursor::new(key_bytes);

    loop {
        match rustls_pemfile::read_one(&mut cursor).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Failed to parse private key: {}", e),
            )
        })? {
            Some(rustls_pemfile::Item::Pkcs8Key(k)) => {
                return Ok(PrivateKeyDer::Pkcs8(k));
            }
            Some(rustls_pemfile::Item::Pkcs1Key(k)) => {
                return Ok(PrivateKeyDer::Pkcs1(k));
            }
            Some(rustls_pemfile::Item::Sec1Key(k)) => {
                return Ok(PrivateKeyDer::Sec1(k));
            }
            Some(_other) => continue,
            None => break,
        }
    }

    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "No private key found in PEM file",
    ))
}

/// Create TLS acceptor from certificate and key paths.
fn create_tls_acceptor(
    cert_path: Option<&str>,
    key_path: Option<&str>,
) -> io::Result<Option<Arc<TlsAcceptor>>> {
    match (cert_path, key_path) {
        (Some(cert), Some(key)) => {
            let certs = load_tls_certs(cert)?;
            let private_key = load_tls_private_key(key)?;

            let config = ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(certs, private_key)
                .map_err(|e| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("TLS configuration error: {}", e),
                    )
                })?;

            Ok(Some(Arc::new(TlsAcceptor::from(Arc::new(config)))))
        }
        (None, None) => Ok(None), // No TLS configured
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Both cert_path and key_path must be provided for TLS",
        )),
    }
}

fn load_mesh_psk(
    ir: &ServiceIR,
) -> Result<Option<String>, Box<dyn std::error::Error + Send + Sync>> {
    if let Some(psk) = &ir.derp_mesh_psk {
        return Ok(Some(psk.trim().to_string()));
    }

    if let Some(psk_path) = &ir.derp_mesh_psk_file {
        let content = fs::read_to_string(psk_path)?;
        let trimmed = content.trim();
        if trimmed.is_empty() {
            return Err(
                io::Error::new(io::ErrorKind::InvalidData, "derp_mesh_psk_file is empty").into(),
            );
        }
        return Ok(Some(trimmed.to_string()));
    }

    Ok(None)
}

/// Build a DERP service.
pub fn build_derp_service(ir: &ServiceIR, ctx: &ServiceContext) -> Option<Arc<dyn Service>> {
    match DerpService::from_ir(ir, ctx) {
        Ok(service) => Some(service as Arc<dyn Service>),
        Err(e) => {
            tracing::error!(
                service = "derp",
                error = %e,
                "Failed to create DERP service"
            );
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sb_config::ir::ServiceType;
    use std::time::Duration;
    use tokio::time::sleep;

    #[test]
    fn test_stun_packet_parsing() {
        // Binding Request
        let packet = vec![
            0x00, 0x01, // Type: Binding Request
            0x00, 0x00, // Length: 0
            0x21, 0x12, 0xA4, 0x42, // Magic Cookie
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A,
            0x0B, // Transaction ID
        ];

        let peer = "127.0.0.1:12345".parse().unwrap();
        let response = DerpService::handle_stun_packet(&packet, peer)
            .expect("Should handle valid STUN packet");

        // Verify response header
        assert_eq!(response[0], 0x01); // Binding Response
        assert_eq!(response[1], 0x01);
        assert_eq!(response[4], 0x21); // Magic Cookie

        // Verify XOR-MAPPED-ADDRESS
        // Attribute Type 0x0020
        // Find attribute in response
        let mut idx = 20;
        let mut found = false;
        while idx < response.len() {
            let attr_type = u16::from_be_bytes([response[idx], response[idx + 1]]);
            let attr_len = u16::from_be_bytes([response[idx + 2], response[idx + 3]]);

            if attr_type == 0x0020 {
                found = true;
                // Check port
                let xor_port = u16::from_be_bytes([response[idx + 6], response[idx + 7]]);
                let port = xor_port ^ 0x2112;
                assert_eq!(port, 12345);
                break;
            }
            idx += 4 + attr_len as usize;
        }
        assert!(found, "XOR-MAPPED-ADDRESS not found");
    }

    #[tokio::test]
    async fn test_http_stub_serves_ok_and_404() {
        let port = match alloc_port() {
            Ok(port) => port,
            Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
                eprintln!("skipping http stub test: {e}");
                return;
            }
            Err(e) => panic!("failed to allocate port: {e}"),
        };
        let ir = ServiceIR {
            ty: ServiceType::Derp,
            tag: Some("derp-http".to_string()),
            resolved_listen: None,
            resolved_listen_port: None,
            ssmapi_listen: None,
            ssmapi_listen_port: None,
            ssmapi_servers: None,
            ssmapi_cache_path: None,
            ssmapi_tls_cert_path: None,
            ssmapi_tls_key_path: None,
            derp_listen: Some("127.0.0.1".to_string()),
            derp_listen_port: Some(port),
            derp_config_path: None,
            derp_verify_client_endpoint: None,
            derp_verify_client_url: None,
            derp_home: None,
            derp_mesh_with: None,
            derp_mesh_psk: None,
            derp_mesh_psk_file: None,
            derp_server_key_path: None,
            derp_stun_enabled: Some(false), // isolate HTTP for the test
            derp_stun_listen_port: None,
            derp_tls_cert_path: None,
            derp_tls_key_path: None,
        };

        let ctx = ServiceContext::default();
        let service = build_derp_service(&ir, &ctx).expect("service should build");

        service.start(StartStage::Initialize).unwrap();
        if let Err(e) = service.start(StartStage::Start) {
            if let Some(io_err) = e.downcast_ref::<io::Error>() {
                if io_err.kind() == io::ErrorKind::PermissionDenied {
                    eprintln!("skipping http stub test during start: {io_err}");
                    return;
                }
            }
            panic!("start failed: {e}");
        }

        // Allow server to bind before connecting.
        sleep(Duration::from_millis(50)).await;

        let ok_response = send_http_request(
            port,
            "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(
            ok_response.contains("200 OK"),
            "expected 200 OK response, got: {ok_response}"
        );
        assert!(
            ok_response.ends_with("OK\n") || ok_response.contains("\r\n\r\nOK\n"),
            "expected OK body, got: {ok_response}"
        );

        let not_found = send_http_request(
            port,
            "GET /missing HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(
            not_found.contains("404 Not Found"),
            "expected 404 response, got: {not_found}"
        );

        service.close().unwrap();
    }

    #[tokio::test]
    async fn test_http_stub_over_tls() {
        use rustls::pki_types::ServerName;
        use rustls::{ClientConfig, RootCertStore};
        use tokio_rustls::TlsConnector;

        let port = match alloc_port() {
            Ok(port) => port,
            Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
                eprintln!("skipping tls http stub test: {e}");
                return;
            }
            Err(e) => panic!("failed to allocate port: {e}"),
        };

        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let cert_pem = cert.cert.pem();
        let key_pem = cert.key_pair.serialize_pem();
        let cert_file = tempfile::NamedTempFile::new().unwrap();
        let key_file = tempfile::NamedTempFile::new().unwrap();
        fs::write(cert_file.path(), cert_pem).unwrap();
        fs::write(key_file.path(), key_pem).unwrap();

        let ir = ServiceIR {
            ty: ServiceType::Derp,
            tag: Some("derp-http-tls".to_string()),
            resolved_listen: None,
            resolved_listen_port: None,
            ssmapi_listen: None,
            ssmapi_listen_port: None,
            ssmapi_servers: None,
            ssmapi_cache_path: None,
            ssmapi_tls_cert_path: None,
            ssmapi_tls_key_path: None,
            derp_listen: Some("127.0.0.1".to_string()),
            derp_listen_port: Some(port),
            derp_config_path: None,
            derp_verify_client_endpoint: None,
            derp_verify_client_url: None,
            derp_home: None,
            derp_mesh_with: None,
            derp_mesh_psk: None,
            derp_mesh_psk_file: None,
            derp_server_key_path: None,
            derp_stun_enabled: Some(false), // isolate HTTP for the test
            derp_stun_listen_port: None,
            derp_tls_cert_path: Some(cert_file.path().to_string_lossy().to_string()),
            derp_tls_key_path: Some(key_file.path().to_string_lossy().to_string()),
        };

        let ctx = ServiceContext::default();
        let service = build_derp_service(&ir, &ctx).expect("service should build");

        service.start(StartStage::Initialize).unwrap();
        if let Err(e) = service.start(StartStage::Start) {
            if let Some(io_err) = e.downcast_ref::<io::Error>() {
                if io_err.kind() == io::ErrorKind::PermissionDenied {
                    eprintln!("skipping tls http stub test during start: {io_err}");
                    return;
                }
            }
            panic!("start failed: {e}");
        }

        sleep(Duration::from_millis(50)).await;

        let mut roots = RootCertStore::empty();
        let cert_der = rustls::pki_types::CertificateDer::from(cert.cert.der().to_vec());
        roots.add(cert_der).expect("add root");
        let client_config = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let connector = TlsConnector::from(Arc::new(client_config));

        let server_name = ServerName::try_from("localhost").unwrap();
        let tcp = TcpStream::connect(("127.0.0.1", port))
            .await
            .expect("connect tls");
        let mut tls_stream = connector
            .connect(server_name, tcp)
            .await
            .expect("tls handshake");

        tls_stream
            .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .await
            .expect("write request");
        let mut buf = Vec::new();
        tls_stream
            .read_to_end(&mut buf)
            .await
            .expect("read response");
        let response = String::from_utf8_lossy(&buf);
        assert!(
            response.contains("200 OK"),
            "expected 200 OK over TLS, got: {response}"
        );

        service.close().unwrap();
    }

    #[tokio::test]
    async fn test_mock_relay_pairs_two_clients() {
        let port = match alloc_port() {
            Ok(port) => port,
            Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
                eprintln!("skipping relay test: {e}");
                return;
            }
            Err(e) => panic!("failed to allocate port: {e}"),
        };
        let ir = ServiceIR {
            ty: ServiceType::Derp,
            tag: Some("derp-relay".to_string()),
            resolved_listen: None,
            resolved_listen_port: None,
            ssmapi_listen: None,
            ssmapi_listen_port: None,
            ssmapi_servers: None,
            ssmapi_cache_path: None,
            ssmapi_tls_cert_path: None,
            ssmapi_tls_key_path: None,
            derp_listen: Some("127.0.0.1".to_string()),
            derp_listen_port: Some(port),
            derp_config_path: None,
            derp_verify_client_endpoint: None,
            derp_verify_client_url: None,
            derp_home: None,
            derp_mesh_with: None,
            derp_mesh_psk: None,
            derp_mesh_psk_file: None,
            derp_server_key_path: None,
            derp_stun_enabled: Some(false),
            derp_stun_listen_port: None,
            derp_tls_cert_path: None,
            derp_tls_key_path: None,
        };

        let ctx = ServiceContext::default();
        let service = build_derp_service(&ir, &ctx).expect("service should build");

        service.start(StartStage::Initialize).unwrap();
        if let Err(e) = service.start(StartStage::Start) {
            if let Some(io_err) = e.downcast_ref::<io::Error>() {
                if io_err.kind() == io::ErrorKind::PermissionDenied {
                    eprintln!("skipping relay test during start: {io_err}");
                    return;
                }
            }
            panic!("start failed: {e}");
        }

        tokio::time::sleep(Duration::from_millis(50)).await;

        let addr = ("127.0.0.1", port);
        let mut c1 = TcpStream::connect(addr).await.expect("connect c1");
        let mut c2 = TcpStream::connect(addr).await.expect("connect c2");

        c1.write_all(b"DERP session test\n")
            .await
            .expect("handshake c1");
        c2.write_all(b"DERP session test\n")
            .await
            .expect("handshake c2");

        // Small pause to ensure pairing.
        tokio::time::sleep(Duration::from_millis(20)).await;

        c1.write_all(b"hello").await.expect("c1 write");
        let mut buf = [0u8; 5];
        c2.read_exact(&mut buf).await.expect("c2 read");
        assert_eq!(&buf, b"hello");

        c2.write_all(b"world").await.expect("c2 write");
        let mut buf2 = [0u8; 5];
        c1.read_exact(&mut buf2).await.expect("c1 read");
        assert_eq!(&buf2, b"world");

        service.close().unwrap();
    }

    #[tokio::test]
    async fn test_mock_relay_requires_token() {
        let port = match alloc_port() {
            Ok(port) => port,
            Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
                eprintln!("skipping relay auth test: {e}");
                return;
            }
            Err(e) => panic!("failed to allocate port: {e}"),
        };

        let ir = ServiceIR {
            ty: ServiceType::Derp,
            tag: Some("derp-auth".to_string()),
            resolved_listen: None,
            resolved_listen_port: None,
            ssmapi_listen: None,
            ssmapi_listen_port: None,
            ssmapi_servers: None,
            ssmapi_cache_path: None,
            ssmapi_tls_cert_path: None,
            ssmapi_tls_key_path: None,
            derp_listen: Some("127.0.0.1".to_string()),
            derp_listen_port: Some(port),
            derp_config_path: None,
            derp_verify_client_endpoint: None,
            derp_verify_client_url: None,
            derp_home: None,
            derp_mesh_with: None,
            derp_mesh_psk: Some("s3cret".to_string()),
            derp_mesh_psk_file: None,
            derp_server_key_path: None,
            derp_stun_enabled: Some(false),
            derp_stun_listen_port: None,
            derp_tls_cert_path: None,
            derp_tls_key_path: None,
        };

        let ctx = ServiceContext::default();
        let service = build_derp_service(&ir, &ctx).expect("service should build");

        service.start(StartStage::Initialize).unwrap();
        if let Err(e) = service.start(StartStage::Start) {
            if let Some(io_err) = e.downcast_ref::<io::Error>() {
                if io_err.kind() == io::ErrorKind::PermissionDenied {
                    eprintln!("skipping relay auth test during start: {io_err}");
                    return;
                }
            }
            panic!("start failed: {e}");
        }

        tokio::time::sleep(Duration::from_millis(50)).await;
        let addr = ("127.0.0.1", port);

        // Missing token should be rejected.
        let mut unauth = TcpStream::connect(addr).await.expect("connect unauth");
        unauth
            .write_all(b"DERP session auth-test\n")
            .await
            .expect("handshake unauth");
        let mut unauth_buf = Vec::new();
        let _ = unauth.read_to_end(&mut unauth_buf).await;
        let unauth_str = String::from_utf8_lossy(&unauth_buf);
        assert!(
            unauth_str.contains("ERR unauthorized"),
            "expected unauthorized response, got: {unauth_str}"
        );

        // With token, relay should pair.
        let mut a = TcpStream::connect(addr).await.expect("connect a");
        let mut b = TcpStream::connect(addr).await.expect("connect b");
        a.write_all(b"DERP session auth-ok token=s3cret\n")
            .await
            .expect("handshake a");
        b.write_all(b"DERP session auth-ok token=s3cret\n")
            .await
            .expect("handshake b");

        tokio::time::sleep(Duration::from_millis(20)).await;
        a.write_all(b"ping").await.expect("a write");
        let mut buf = [0u8; 4];
        b.read_exact(&mut buf).await.expect("b read");
        assert_eq!(&buf, b"ping");

        service.close().unwrap();
    }

    async fn send_http_request(port: u16, request: &str) -> String {
        let mut stream = TcpStream::connect(("127.0.0.1", port))
            .await
            .expect("connect to stub");
        stream
            .write_all(request.as_bytes())
            .await
            .expect("write request");
        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await.expect("read response");
        String::from_utf8_lossy(&buf).to_string()
    }

    fn alloc_port() -> io::Result<u16> {
        StdTcpListener::bind("127.0.0.1:0")
            .and_then(|listener| listener.local_addr())
            .map(|addr| addr.port())
    }

    #[tokio::test]
    async fn test_derp_protocol_end_to_end() {
        use super::super::protocol::DerpFrame;
        use sb_config::ir::ServiceType;
        use tokio::net::TcpStream;

        let port = match alloc_port() {
            Ok(port) => port,
            Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
                eprintln!("skipping derp test: {e}");
                return;
            }
            Err(e) => panic!("failed to allocate port: {e}"),
        };

        // Create server
        let ir = ServiceIR {
            ty: ServiceType::Derp,
            tag: Some("test-derp".to_string()),
            derp_listen: Some("127.0.0.1".to_string()),
            derp_listen_port: Some(port),
            derp_stun_enabled: Some(false),
            derp_config_path: None,
            derp_verify_client_endpoint: None,
            derp_verify_client_url: None,
            derp_home: None,
            derp_mesh_with: None,
            derp_mesh_psk: None,
            derp_mesh_psk_file: None,
            derp_server_key_path: None,
            derp_stun_listen_port: None,
            derp_tls_cert_path: None,
            derp_tls_key_path: None,
            resolved_listen: None,
            resolved_listen_port: None,
            ssmapi_listen: None,
            ssmapi_listen_port: None,
            ssmapi_servers: None,
            ssmapi_cache_path: None,
            ssmapi_tls_cert_path: None,
            ssmapi_tls_key_path: None,
        };

        let ctx = ServiceContext::default();
        let service = DerpService::from_ir(&ir, &ctx).expect("Failed to create service");

        // Start service (not async)
        service
            .start(StartStage::Start)
            .expect("Failed to start service");

        tokio::time::sleep(Duration::from_millis(50)).await;

        let addr = service.listen_addr;

        // Create two clients
        let client1_key = [1u8; 32];
        let client2_key = [2u8; 32];

        // Client 1 connects
        let mut stream1 = TcpStream::connect(addr)
            .await
            .expect("Failed to connect client 1");

        // Read ServerKey from server
        let server_key_frame = DerpFrame::read_from_async(&mut stream1)
            .await
            .expect("Failed to read ServerKey");
        assert!(matches!(server_key_frame, DerpFrame::ServerKey { .. }));

        // Send ClientInfo
        let client_info1 = DerpFrame::ClientInfo { key: client1_key };
        client_info1
            .write_to_async(&mut stream1)
            .await
            .expect("Failed to send ClientInfo");

        // Client 2 connects
        let mut stream2 = TcpStream::connect(addr)
            .await
            .expect("Failed to connect client 2");

        // Read ServerKey
        let _ = DerpFrame::read_from_async(&mut stream2)
            .await
            .expect("Failed to read ServerKey for client 2");

        // Send ClientInfo
        let client_info2 = DerpFrame::ClientInfo { key: client2_key };
        client_info2
            .write_to_async(&mut stream2)
            .await
            .expect("Failed to send ClientInfo for client 2");

        // Give server time to register clients
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Client 1 sends packet to Client 2
        let test_packet = vec![0xAA, 0xBB, 0xCC, 0xDD];
        let send_frame = DerpFrame::SendPacket {
            dst_key: client2_key,
            packet: test_packet.clone(),
        };
        send_frame
            .write_to_async(&mut stream1)
            .await
            .expect("Failed to send packet from client 1");

        // Client 2 should receive the packet
        tokio::time::timeout(Duration::from_secs(2), async {
            let recv_frame = DerpFrame::read_from_async(&mut stream2)
                .await
                .expect("Failed to read packet on client 2");

            match recv_frame {
                DerpFrame::RecvPacket { src_key, packet } => {
                    assert_eq!(src_key, client1_key, "Wrong source key");
                    assert_eq!(packet, test_packet, "Packet content mismatch");
                }
                other => panic!("Expected RecvPacket, got {:?}", other.frame_type()),
            }
        })
        .await
        .expect("Timeout waiting for packet");

        // Shutdown
        service.close().expect("Failed to close service");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    #[tokio::test]
    async fn test_derp_protocol_over_tls_end_to_end() {
        use rustls::pki_types::ServerName;
        use rustls::{ClientConfig, RootCertStore};
        use sb_config::ir::ServiceType;
        use tokio::net::TcpStream;
        use tokio_rustls::TlsConnector;

        let port = match alloc_port() {
            Ok(port) => port,
            Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
                eprintln!("skipping derp tls test: {e}");
                return;
            }
            Err(e) => panic!("failed to allocate port: {e}"),
        };

        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let cert_pem = cert.cert.pem();
        let key_pem = cert.key_pair.serialize_pem();
        let cert_file = tempfile::NamedTempFile::new().unwrap();
        let key_file = tempfile::NamedTempFile::new().unwrap();
        fs::write(cert_file.path(), cert_pem).unwrap();
        fs::write(key_file.path(), key_pem).unwrap();

        let ir = ServiceIR {
            ty: ServiceType::Derp,
            tag: Some("test-derp-tls".to_string()),
            derp_listen: Some("127.0.0.1".to_string()),
            derp_listen_port: Some(port),
            derp_stun_enabled: Some(false),
            derp_config_path: None,
            derp_verify_client_endpoint: None,
            derp_verify_client_url: None,
            derp_home: None,
            derp_mesh_with: None,
            derp_mesh_psk: None,
            derp_mesh_psk_file: None,
            derp_server_key_path: None,
            derp_stun_listen_port: None,
            derp_tls_cert_path: Some(cert_file.path().to_string_lossy().to_string()),
            derp_tls_key_path: Some(key_file.path().to_string_lossy().to_string()),
            resolved_listen: None,
            resolved_listen_port: None,
            ssmapi_listen: None,
            ssmapi_listen_port: None,
            ssmapi_servers: None,
            ssmapi_cache_path: None,
            ssmapi_tls_cert_path: None,
            ssmapi_tls_key_path: None,
        };

        let ctx = ServiceContext::default();
        let service = DerpService::from_ir(&ir, &ctx).expect("Failed to create service");

        if let Err(e) = service.start(StartStage::Start) {
            if let Some(io_err) = e.downcast_ref::<io::Error>() {
                if io_err.kind() == io::ErrorKind::PermissionDenied {
                    eprintln!("skipping derp tls test during start: {io_err}");
                    return;
                }
            }
            panic!("start failed: {e}");
        }

        tokio::time::sleep(Duration::from_millis(50)).await;

        let mut roots = RootCertStore::empty();
        let cert_der = rustls::pki_types::CertificateDer::from(cert.cert.der().to_vec());
        roots.add(cert_der).expect("add root");
        let client_config = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let connector = TlsConnector::from(Arc::new(client_config));
        let server_name = ServerName::try_from("localhost").unwrap();

        let mut stream1 = connector
            .connect(
                server_name.clone(),
                TcpStream::connect(("127.0.0.1", port))
                    .await
                    .expect("connect client1"),
            )
            .await
            .expect("tls handshake client1");

        let mut stream2 = connector
            .connect(
                server_name,
                TcpStream::connect(("127.0.0.1", port))
                    .await
                    .expect("connect client2"),
            )
            .await
            .expect("tls handshake client2");

        let client1_key = [1u8; 32];
        let client2_key = [2u8; 32];

        // Read ServerKey frames
        let _ = DerpFrame::read_from_async(&mut stream1)
            .await
            .expect("server key for client1");
        let _ = DerpFrame::read_from_async(&mut stream2)
            .await
            .expect("server key for client2");

        // Send ClientInfo
        let client_info1 = DerpFrame::ClientInfo { key: client1_key };
        client_info1
            .write_to_async(&mut stream1)
            .await
            .expect("send client1 info");

        let client_info2 = DerpFrame::ClientInfo { key: client2_key };
        client_info2
            .write_to_async(&mut stream2)
            .await
            .expect("send client2 info");

        tokio::time::sleep(Duration::from_millis(50)).await;

        // Send packet from client1 to client2
        let packet = vec![9, 8, 7, 6];
        let send_frame = DerpFrame::SendPacket {
            dst_key: client2_key,
            packet: packet.clone(),
        };
        send_frame
            .write_to_async(&mut stream1)
            .await
            .expect("send packet from client1");

        // Client2 should receive packet
        tokio::time::timeout(Duration::from_secs(2), async {
            let recv_frame = DerpFrame::read_from_async(&mut stream2)
                .await
                .expect("recv frame on client2");
            match recv_frame {
                DerpFrame::RecvPacket {
                    src_key,
                    packet: recv,
                } => {
                    assert_eq!(src_key, client1_key, "wrong source key");
                    assert_eq!(recv, packet, "packet content mismatch");
                }
                other => panic!("expected RecvPacket, got {:?}", other.frame_type()),
            }
        })
        .await
        .expect("timeout waiting for TLS packet");

        service.close().expect("Failed to close service");
    }

    // ────────────────────────────────────────────────────────────────────────────
    // Persistent Key Storage Tests
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_generate_secure_key_uniqueness() {
        let key1 = generate_secure_server_key().unwrap();
        let key2 = generate_secure_server_key().unwrap();
        // Keys should be different (cryptographically secure)
        assert_ne!(key1, key2);
        assert_eq!(key1.len(), 32);
        assert_eq!(key2.len(), 32);
    }

    #[test]
    fn test_key_save_load_roundtrip() {
        use tempfile::NamedTempFile;

        let temp_file = NamedTempFile::new().unwrap();
        let path = temp_file.path().to_str().unwrap();

        let original_key = generate_secure_server_key().unwrap();
        save_key_to_file(path, &original_key).unwrap();
        let loaded_key = load_key_from_file(path).unwrap();

        assert_eq!(original_key, loaded_key);
    }

    #[test]
    fn test_load_or_generate_creates_new_key() {
        use tempfile::tempdir;

        let temp_dir = tempdir().unwrap();
        let key_path = temp_dir.path().join("derp_server.key");
        let path_str = key_path.to_str().unwrap();

        // Key file shouldn't exist yet
        assert!(!key_path.exists());

        // First call should generate and save key
        let key1 = load_or_generate_server_key(Some(path_str)).unwrap();

        // File should now exist
        assert!(key_path.exists());

        // Second call should load same key
        let key2 = load_or_generate_server_key(Some(path_str)).unwrap();
        assert_eq!(key1, key2);
    }

    #[test]
    fn test_ephemeral_key_without_path() {
        // Should generate ephemeral key without error
        let key = load_or_generate_server_key(None).unwrap();
        assert_eq!(key.len(), 32);

        // Each call should generate different key
        let key2 = load_or_generate_server_key(None).unwrap();
        assert_ne!(key, key2);
    }

    #[cfg(unix)]
    #[test]
    fn test_key_file_permissions() {
        use std::os::unix::fs::PermissionsExt;
        use tempfile::NamedTempFile;

        let temp_file = NamedTempFile::new().unwrap();
        let path = temp_file.path().to_str().unwrap();

        let key = generate_secure_server_key().unwrap();
        save_key_to_file(path, &key).unwrap();

        let metadata = fs::metadata(path).unwrap();
        let mode = metadata.permissions().mode();
        // Should be owner read/write only (0600)
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn test_save_key_creates_parent_directories() {
        use tempfile::tempdir;

        let temp_dir = tempdir().unwrap();
        let key_path = temp_dir.path().join("subdir/deep/derp_server.key");
        let path_str = key_path.to_str().unwrap();

        let key = generate_secure_server_key().unwrap();
        save_key_to_file(path_str, &key).unwrap();

        // Parent directories and file should exist
        assert!(key_path.exists());
        assert!(key_path.parent().unwrap().exists());
    }

    #[test]
    fn test_load_key_with_wrong_size_fails() {
        use std::io::Write;
        use tempfile::NamedTempFile;

        let mut temp_file = NamedTempFile::new().unwrap();
        let path = temp_file.path().to_string_lossy().to_string();

        // Write only 16 bytes (should be 32)
        temp_file.write_all(&[0u8; 16]).unwrap();
        temp_file.flush().unwrap();

        // Should fail because file is too small
        let result = load_key_from_file(&path);
        assert!(result.is_err());
    }
}
