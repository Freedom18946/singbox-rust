//! DERP service implementation.

use super::client_registry::ClientRegistry;
use super::protocol::{ClientInfoPayload, DerpFrame, FrameType, PublicKey};
use crate::service::{Service, ServiceContext, StartStage};
use bytes::Bytes;
use hyper::body::HttpBody as _;
use hyper::header::{
    CONNECTION, CONTENT_TYPE, LOCATION, SEC_WEBSOCKET_ACCEPT, SEC_WEBSOCKET_KEY,
    SEC_WEBSOCKET_PROTOCOL, UPGRADE,
};
use hyper::service::service_fn;
use hyper::{Body, Method, Request as HyperRequest, Response as HyperResponse, StatusCode, Version};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::ServerConfig;
use rustls_pemfile;
use sb_config::ir::ServiceIR;
use sb_metrics;
use std::collections::HashMap;
use std::convert::Infallible;
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
use tokio_tungstenite::tungstenite::handshake::derive_accept_key;
use tokio_tungstenite::tungstenite::protocol::Role;
use tokio_tungstenite::WebSocketStream;

/// DERP service implementation.
///
/// Provides:
/// - STUN server (UDP) for connectivity checks
/// - HTTP server stub (returns 200 OK for root/health, 404 for others)
/// - DERP protocol server (real frame-based client-to-client relay)
/// - TCP mock relay (legacy, for backward compatibility)
use futures::{FutureExt, SinkExt, StreamExt};

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

fn is_valid_mesh_psk(psk: &str) -> bool {
    if psk.len() != 64 {
        return false;
    }
    psk.as_bytes()
        .iter()
        .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

const DERP_HOME_PAGE: &str = r#"
<h1>DERP</h1>
<p>
  This is a <a href="https://tailscale.com/">Tailscale</a> DERP server.
</p>

<p>
  It provides STUN, interactive connectivity establishment, and relaying of end-to-end encrypted traffic
  for Tailscale clients.
</p>

<p>
  Documentation:
</p>

<ul>

<li><a href="https://tailscale.com/kb/1232/derp-servers">About DERP</a></li>
<li><a href="https://pkg.go.dev/tailscale.com/derp">Protocol & Go docs</a></li>
<li><a href="https://github.com/tailscale/tailscale/tree/main/cmd/derper#derp">How to run a DERP server</a></li>

</body>
</html>
"#;

fn add_browser_headers(headers: &mut hyper::HeaderMap) {
    headers.insert(
        hyper::header::STRICT_TRANSPORT_SECURITY,
        hyper::header::HeaderValue::from_static("max-age=63072000; includeSubDomains"),
    );
    headers.insert(
        hyper::header::CONTENT_SECURITY_POLICY,
        hyper::header::HeaderValue::from_static("default-src 'self'; frame-ancestors 'none'; form-action 'self'; base-uri 'self'; block-all-mixed-content; object-src 'none'"),
    );
    headers.insert(
        hyper::header::X_CONTENT_TYPE_OPTIONS,
        hyper::header::HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        hyper::header::X_FRAME_OPTIONS,
        hyper::header::HeaderValue::from_static("DENY"),
    );
}

fn query_param<'a>(query: Option<&'a str>, key: &str) -> Option<&'a str> {
    let query = query?;
    for pair in query.split('&') {
        let mut it = pair.splitn(2, '=');
        let k = it.next().unwrap_or("");
        if k == key {
            return Some(it.next().unwrap_or(""));
        }
    }
    None
}

struct HyperBodyReader {
    body: Body,
    buf: Bytes,
    pos: usize,
}

impl HyperBodyReader {
    fn new(body: Body) -> Self {
        Self {
            body,
            buf: Bytes::new(),
            pos: 0,
        }
    }
}

impl AsyncRead for HyperBodyReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.pos < self.buf.len() {
            let available = self.buf.len() - self.pos;
            let to_read = std::cmp::min(available, buf.remaining());
            buf.put_slice(&self.buf[self.pos..self.pos + to_read]);
            self.pos += to_read;
            if self.pos >= self.buf.len() {
                self.buf = Bytes::new();
                self.pos = 0;
            }
            return Poll::Ready(Ok(()));
        }

        match Pin::new(&mut self.body).poll_data(cx) {
            Poll::Ready(Some(Ok(chunk))) => {
                self.buf = chunk;
                self.pos = 0;
                self.poll_read(cx, buf)
            }
            Poll::Ready(Some(Err(e))) => Poll::Ready(Err(io::Error::other(format!(
                "http body read error: {e}"
            )))),
            Poll::Ready(None) => Poll::Ready(Ok(())), // EOF
            Poll::Pending => Poll::Pending,
        }
    }
}

struct HyperBodyWriter {
    sender: Option<hyper::body::Sender>,
}

impl HyperBodyWriter {
    fn new(sender: hyper::body::Sender) -> Self {
        Self {
            sender: Some(sender),
        }
    }
}

impl AsyncWrite for HyperBodyWriter {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let sender = match self.sender.as_mut() {
            Some(s) => s,
            None => {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "http response body closed",
                )))
            }
        };

        match sender.poll_ready(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(())) => match sender.try_send_data(Bytes::copy_from_slice(buf)) {
                Ok(()) => Poll::Ready(Ok(buf.len())),
                Err(_bytes) => Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "http response body closed",
                ))),
            },
            Poll::Ready(Err(e)) => Poll::Ready(Err(io::Error::other(format!(
                "http body send error: {e}"
            )))),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.sender = None;
        Poll::Ready(Ok(()))
    }
}

struct HyperDuplex {
    reader: HyperBodyReader,
    writer: HyperBodyWriter,
}

impl HyperDuplex {
    fn new(reader: HyperBodyReader, writer: HyperBodyWriter) -> Self {
        Self { reader, writer }
    }
}

impl AsyncRead for HyperDuplex {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.reader).poll_read(cx, buf)
    }
}

impl AsyncWrite for HyperDuplex {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.writer).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.writer).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.writer).poll_shutdown(cx)
    }
}

struct DerpWebSocketStreamAdapter<S> {
    inner: WebSocketStream<S>,
    read_buffer: Vec<u8>,
    read_pos: usize,
    write_pending_len: Option<usize>,
}

impl<S> DerpWebSocketStreamAdapter<S> {
    fn new(inner: WebSocketStream<S>) -> Self {
        Self {
            inner,
            read_buffer: Vec::new(),
            read_pos: 0,
            write_pending_len: None,
        }
    }
}

impl<S> AsyncRead for DerpWebSocketStreamAdapter<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.read_pos < self.read_buffer.len() {
            let available = self.read_buffer.len() - self.read_pos;
            let to_read = std::cmp::min(available, buf.remaining());
            buf.put_slice(&self.read_buffer[self.read_pos..self.read_pos + to_read]);
            self.read_pos += to_read;
            if self.read_pos >= self.read_buffer.len() {
                self.read_buffer.clear();
                self.read_pos = 0;
            }
            return Poll::Ready(Ok(()));
        }

        match self.inner.poll_next_unpin(cx) {
            Poll::Ready(Some(Ok(msg))) => match msg {
                tokio_tungstenite::tungstenite::Message::Binary(data) => {
                    self.read_buffer = data;
                    self.read_pos = 0;
                    self.poll_read(cx, buf)
                }
                tokio_tungstenite::tungstenite::Message::Text(text) => {
                    tracing::warn!(service = "derp", text = %text, "unexpected websocket text frame");
                    self.poll_read(cx, buf)
                }
                tokio_tungstenite::tungstenite::Message::Close(_) => Poll::Ready(Ok(())),
                tokio_tungstenite::tungstenite::Message::Ping(_) => self.poll_read(cx, buf),
                tokio_tungstenite::tungstenite::Message::Pong(_) => self.poll_read(cx, buf),
                tokio_tungstenite::tungstenite::Message::Frame(_) => self.poll_read(cx, buf),
            },
            Poll::Ready(Some(Err(e))) => Poll::Ready(Err(io::Error::other(format!(
                "websocket read error: {e}"
            )))),
            Poll::Ready(None) => Poll::Ready(Ok(())),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<S> AsyncWrite for DerpWebSocketStreamAdapter<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        // If a previous write queued a frame, flush it fully before accepting more.
        if let Some(len) = self.write_pending_len.take() {
            match self.inner.poll_flush_unpin(cx) {
                Poll::Ready(Ok(())) => return Poll::Ready(Ok(len)),
                Poll::Ready(Err(e)) => {
                    return Poll::Ready(Err(io::Error::other(format!(
                        "websocket flush error: {e}"
                    ))))
                }
                Poll::Pending => {
                    self.write_pending_len = Some(len);
                    return Poll::Pending;
                }
            }
        }

        let msg = tokio_tungstenite::tungstenite::Message::Binary(buf.to_vec());
        match self.inner.poll_ready_unpin(cx) {
            Poll::Ready(Ok(())) => {
                if let Err(e) = self.inner.start_send_unpin(msg) {
                    return Poll::Ready(Err(io::Error::other(format!(
                        "websocket write error: {e}"
                    ))));
                }
                let len = buf.len();
                match self.inner.poll_flush_unpin(cx) {
                    Poll::Ready(Ok(())) => Poll::Ready(Ok(len)),
                    Poll::Ready(Err(e)) => Poll::Ready(Err(io::Error::other(format!(
                        "websocket flush error: {e}"
                    )))),
                    Poll::Pending => {
                        self.write_pending_len = Some(len);
                        Poll::Pending
                    }
                }
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(io::Error::other(format!(
                "websocket poll_ready error: {e}"
            )))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.inner.poll_flush_unpin(cx) {
            Poll::Ready(Ok(())) => {
                self.write_pending_len = None;
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(io::Error::other(format!(
                "websocket flush error: {e}"
            )))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.inner.poll_close_unpin(cx) {
            Poll::Ready(Ok(())) => {
                self.write_pending_len = None;
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(io::Error::other(format!(
                "websocket close error: {e}"
            )))),
            Poll::Pending => Poll::Pending,
        }
    }
}

#[derive(Clone)]
struct DerpHttpState {
    tag: Arc<str>,
    peer: SocketAddr,
    client_registry: Arc<ClientRegistry>,
    server_key: PublicKey,
    mesh_psk: Option<String>,
    /// Parsed mesh key (32 bytes) for Go-compatible mesh detection via ClientInfo.
    mesh_key: Option<[u8; 32]>,
    home: Arc<str>,
    verify_client_urls: Arc<[String]>,
    verify_client_endpoints: Arc<[String]>,
}

impl DerpHttpState {
    async fn handle(self, mut req: HyperRequest<Body>) -> Result<HyperResponse<Body>, Infallible> {
        let path = req.uri().path();
        let resp = match path {
            "/derp" => self.handle_derp(&mut req),
            "/derp/mesh" => self.handle_mesh(&mut req),
            "/derp/probe" | "/derp/latency-check" => self.handle_probe(&req),
            "/bootstrap-dns" => self.handle_bootstrap_dns(&req).await,
            "/robots.txt" => self.handle_robots(),
            "/generate_204" => self.handle_generate_204(&req),
            _ => self.handle_home(),
        };

        let status_code = resp.status().as_u16().to_string();
        sb_metrics::inc_derp_http(&self.tag, &status_code);
        Ok(resp)
    }

    fn handle_generate_204(&self, req: &HyperRequest<Body>) -> HyperResponse<Body> {
        const NO_CONTENT_CHALLENGE_HEADER: hyper::header::HeaderName =
            hyper::header::HeaderName::from_static("x-tailscale-challenge");
        const NO_CONTENT_RESPONSE_HEADER: hyper::header::HeaderName =
            hyper::header::HeaderName::from_static("x-tailscale-response");

        fn is_challenge_char(c: char) -> bool {
            matches!(c, 'a'..='z' | 'A'..='Z' | '0'..='9' | '.' | '-' | '_')
        }

        let mut resp = HyperResponse::new(Body::empty());
        if let Some(challenge) = req
            .headers()
            .get(NO_CONTENT_CHALLENGE_HEADER)
            .and_then(|v| v.to_str().ok())
        {
            let ok = challenge.len() <= 64 && challenge.chars().all(is_challenge_char);
            if ok {
                let val = format!("response {challenge}");
                if let Ok(header_val) = hyper::header::HeaderValue::from_str(&val) {
                    resp.headers_mut().insert(NO_CONTENT_RESPONSE_HEADER, header_val);
                }
            }
        }
        *resp.status_mut() = StatusCode::NO_CONTENT;
        resp
    }

    fn handle_robots(&self) -> HyperResponse<Body> {
        let mut resp = HyperResponse::new(Body::from("User-agent: *\nDisallow: /\n"));
        resp.headers_mut().insert(
            CONTENT_TYPE,
            hyper::header::HeaderValue::from_static("text/plain; charset=utf-8"),
        );
        add_browser_headers(resp.headers_mut());
        resp
    }

    fn handle_home(&self) -> HyperResponse<Body> {
        let home = self.home.as_ref();
        if home.is_empty() {
            let mut resp = HyperResponse::new(Body::from(DERP_HOME_PAGE));
            resp.headers_mut().insert(
                CONTENT_TYPE,
                hyper::header::HeaderValue::from_static("text/html; charset=utf-8"),
            );
            add_browser_headers(resp.headers_mut());
            return resp;
        }

        if home == "blank" {
            let mut resp = HyperResponse::new(Body::empty());
            resp.headers_mut().insert(
                CONTENT_TYPE,
                hyper::header::HeaderValue::from_static("text/html; charset=utf-8"),
            );
            add_browser_headers(resp.headers_mut());
            return resp;
        }

        // Validated in from_ir: must be http:// or https://
        let mut resp = HyperResponse::new(Body::empty());
        *resp.status_mut() = StatusCode::FOUND;
        resp.headers_mut()
            .insert(LOCATION, hyper::header::HeaderValue::from_str(home).unwrap());
        add_browser_headers(resp.headers_mut());
        resp
    }

    fn handle_probe(&self, req: &HyperRequest<Body>) -> HyperResponse<Body> {
        match *req.method() {
            Method::HEAD | Method::GET => {
                let mut resp = HyperResponse::new(Body::empty());
                resp.headers_mut().insert(
                    hyper::header::ACCESS_CONTROL_ALLOW_ORIGIN,
                    hyper::header::HeaderValue::from_static("*"),
                );
                resp
            }
            _ => Self::text(StatusCode::METHOD_NOT_ALLOWED, "bogus probe method\n"),
        }
    }

    async fn handle_bootstrap_dns(&self, req: &HyperRequest<Body>) -> HyperResponse<Body> {
        let mut resp = HyperResponse::new(Body::empty());
        resp.headers_mut().insert(
            CONTENT_TYPE,
            hyper::header::HeaderValue::from_static("application/json"),
        );
        resp.headers_mut().insert(
            CONNECTION,
            hyper::header::HeaderValue::from_static("close"),
        );
        add_browser_headers(resp.headers_mut());

        let Some(domain) = query_param(req.uri().query(), "q") else {
            *resp.body_mut() = Body::from("{}");
            return resp;
        };

        let Some(resolver) = crate::dns::global::get() else {
            *resp.body_mut() = Body::from("{}");
            return resp;
        };

        match resolver.resolve(domain).await {
            Ok(answer) => {
                let addrs: Vec<String> = answer.ips.into_iter().map(|ip| ip.to_string()).collect();
                let json = serde_json::json!({ domain: addrs });
                *resp.body_mut() = Body::from(json.to_string());
                resp
            }
            Err(e) => {
                *resp.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                tracing::warn!(service = "derp", error = %e, domain, "bootstrap-dns lookup failed");
                resp
            }
        }
    }

    fn is_derp_websocket(req: &HyperRequest<Body>) -> bool {
        let Some(upgrade) = req.headers().get(UPGRADE) else {
            return false;
        };
        let upgrade = match upgrade.to_str() {
            Ok(v) => v.to_ascii_lowercase(),
            Err(_) => return false,
        };
        if upgrade != "websocket" {
            return false;
        }
        let proto = req
            .headers()
            .get(SEC_WEBSOCKET_PROTOCOL)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        proto.contains("derp")
    }

    fn handle_derp(&self, req: &mut HyperRequest<Body>) -> HyperResponse<Body> {
        let upgrade = req
            .headers()
            .get(UPGRADE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        let upgrade = upgrade.to_ascii_lowercase();

        if upgrade != "websocket" && upgrade != "derp" {
            if !upgrade.is_empty() {
                tracing::debug!(service = "derp", peer = %self.peer, upgrade = %upgrade, "Weird DERP upgrade header");
            }
            return Self::text(
                StatusCode::UPGRADE_REQUIRED,
                "DERP requires connection upgrade\n",
            );
        }

        if req.version() != Version::HTTP_11 {
            return Self::text(
                StatusCode::INTERNAL_SERVER_ERROR,
                "HTTP does not support general TCP support\n",
            );
        }

        if upgrade == "websocket" && Self::is_derp_websocket(req) {
            return self.handle_derp_websocket(req);
        }

        self.handle_derp_upgrade(req, false)
    }

    fn handle_mesh(&self, req: &mut HyperRequest<Body>) -> HyperResponse<Body> {
        // DEPRECATED: /derp/mesh + x-derp-mesh-psk is deprecated.
        // Use mesh_key in ClientInfo payload instead (Go-compatible SetMeshKey model).
        tracing::warn!(
            service = "derp",
            peer = %self.peer,
            "DEPRECATED: /derp/mesh endpoint is deprecated. Use mesh_key in ClientInfo instead."
        );

        let Some(expected) = self.mesh_psk.as_deref() else {
            return Self::text(StatusCode::NOT_FOUND, "not found\n");
        };
        let provided = req
            .headers()
            .get("x-derp-mesh-psk")
            .and_then(|v| v.to_str().ok())
            .map(str::trim);
        if provided != Some(expected) {
            return Self::text(StatusCode::UNAUTHORIZED, "mesh psk required\n");
        }
        self.handle_derp_upgrade(req, true)
    }

    fn handle_derp_upgrade(&self, req: &mut HyperRequest<Body>, is_mesh_peer: bool) -> HyperResponse<Body> {
        let on_upgrade = hyper::upgrade::on(req);

        let tag = self.tag.clone();
        let peer = self.peer;
        let client_registry = self.client_registry.clone();
        let server_key = self.server_key;
        let verify_client_urls = self.verify_client_urls.clone();
        let verify_client_endpoints = self.verify_client_endpoints.clone();
        let mesh_key = self.mesh_key;

        tokio::spawn(async move {
            match on_upgrade.await {
                Ok(upgraded) => {
                    if let Err(e) = DerpService::handle_derp_client(
                        upgraded,
                        peer,
                        tag,
                        client_registry,
                        server_key,
                        is_mesh_peer,
                        verify_client_urls,
                        verify_client_endpoints,
                        mesh_key,
                    )
                    .await
                    {
                        tracing::debug!(service = "derp", peer = %peer, error = %e, "derp upgraded connection ended");
                    }
                }
                Err(e) => tracing::debug!(service = "derp", peer = %peer, error = %e, "derp upgrade failed"),
            }
        });

        const DERP_VERSION_HEADER: hyper::header::HeaderName =
            hyper::header::HeaderName::from_static("derp-version");
        const DERP_PUBLIC_KEY_HEADER: hyper::header::HeaderName =
            hyper::header::HeaderName::from_static("derp-public-key");

        let mut resp = HyperResponse::new(Body::empty());
        *resp.status_mut() = StatusCode::SWITCHING_PROTOCOLS;
        resp.headers_mut()
            .insert(UPGRADE, hyper::header::HeaderValue::from_static("DERP"));
        resp.headers_mut()
            .insert(CONNECTION, hyper::header::HeaderValue::from_static("Upgrade"));
        resp.headers_mut().insert(
            DERP_VERSION_HEADER,
            hyper::header::HeaderValue::from_static("2"),
        );
        resp.headers_mut().insert(
            DERP_PUBLIC_KEY_HEADER,
            hyper::header::HeaderValue::from_str(&hex::encode(server_key)).unwrap(),
        );
        resp
    }

    fn handle_derp_websocket(&self, req: &mut HyperRequest<Body>) -> HyperResponse<Body> {
        let Some(key) = req.headers().get(SEC_WEBSOCKET_KEY) else {
            return Self::text(StatusCode::BAD_REQUEST, "missing sec-websocket-key\n");
        };
        let accept_key = derive_accept_key(key.as_bytes());

        let on_upgrade = hyper::upgrade::on(req);

        let tag = self.tag.clone();
        let peer = self.peer;
        let client_registry = self.client_registry.clone();
        let server_key = self.server_key;
        let verify_client_urls = self.verify_client_urls.clone();
        let verify_client_endpoints = self.verify_client_endpoints.clone();
        let mesh_key = self.mesh_key;

        tokio::spawn(async move {
            match on_upgrade.await {
                Ok(upgraded) => {
                    let ws_stream =
                        WebSocketStream::from_raw_socket(upgraded, Role::Server, None).await;
                    let adapter = DerpWebSocketStreamAdapter::new(ws_stream);
                    if let Err(e) = DerpService::handle_derp_client(
                        adapter,
                        peer,
                        tag,
                        client_registry,
                        server_key,
                        false,
                        verify_client_urls,
                        verify_client_endpoints,
                        mesh_key,
                    )
                    .await
                    {
                        tracing::debug!(service = "derp", peer = %peer, error = %e, "derp websocket ended");
                    }
                }
                Err(e) => tracing::debug!(service = "derp", peer = %peer, error = %e, "websocket upgrade failed"),
            }
        });

        let mut resp = HyperResponse::new(Body::empty());
        *resp.status_mut() = StatusCode::SWITCHING_PROTOCOLS;
        resp.headers_mut()
            .insert(UPGRADE, hyper::header::HeaderValue::from_static("websocket"));
        resp.headers_mut()
            .insert(CONNECTION, hyper::header::HeaderValue::from_static("Upgrade"));
        resp.headers_mut().insert(
            SEC_WEBSOCKET_ACCEPT,
            hyper::header::HeaderValue::from_str(&accept_key).unwrap(),
        );
        resp.headers_mut().insert(
            SEC_WEBSOCKET_PROTOCOL,
            hyper::header::HeaderValue::from_static("derp"),
        );
        resp
    }

    fn handle_derp_stream(&self, req: &mut HyperRequest<Body>, is_mesh_peer: bool) -> HyperResponse<Body> {
        let (sender, body) = Body::channel();
        let reader = HyperBodyReader::new(std::mem::take(req.body_mut()));
        let writer = HyperBodyWriter::new(sender);
        let io = HyperDuplex::new(reader, writer);

        let tag = self.tag.clone();
        let peer = self.peer;
        let client_registry = self.client_registry.clone();
        let server_key = self.server_key;
        let verify_client_urls = self.verify_client_urls.clone();
        let verify_client_endpoints = self.verify_client_endpoints.clone();
        let mesh_key = self.mesh_key;

        tokio::spawn(async move {
            if let Err(e) = DerpService::handle_derp_client(
                io,
                peer,
                tag,
                client_registry,
                server_key,
                is_mesh_peer,
                verify_client_urls,
                verify_client_endpoints,
                mesh_key,
            )
            .await
            {
                tracing::debug!(service = "derp", peer = %peer, error = %e, "derp stream ended");
            }
        });

        let mut resp = HyperResponse::new(body);
        resp.headers_mut().insert(
            CONTENT_TYPE,
            hyper::header::HeaderValue::from_static("application/octet-stream"),
        );
        resp
    }

    fn text(status: StatusCode, body: &'static str) -> HyperResponse<Body> {
        let mut resp = HyperResponse::new(Body::from(body));
        *resp.status_mut() = status;
        resp.headers_mut().insert(
            CONTENT_TYPE,
            hyper::header::HeaderValue::from_static("text/plain; charset=utf-8"),
        );
        resp
    }
}

pub struct DerpService {
    tag: Arc<str>,
    listen_addr: SocketAddr,
    stun_addr: SocketAddr,
    stun_enabled: bool,
    mesh_psk: Option<String>,
    home: String,
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
    /// URLs for client verification (HTTP-based)
    verify_client_urls: Vec<String>,
    /// Tailscale endpoint tags for client verification
    verify_client_endpoints: Vec<String>,
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
        if let Some(psk) = mesh_psk.as_deref() {
            if !is_valid_mesh_psk(psk) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "derp_mesh_psk must contain exactly 64 lowercase hex digits",
                )
                .into());
            }
        }

        let home = ir.derp_home.clone().unwrap_or_default();
        if !home.is_empty()
            && home != "blank"
            && !home.starts_with("http://")
            && !home.starts_with("https://")
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid derp_home value: {home}"),
            )
            .into());
        }

        // Load or generate server key (persistent if path configured)
        let server_key = load_or_generate_server_key(ir.derp_server_key_path.as_deref())?;

        // Create TLS acceptor if configured
        let tls_acceptor = create_tls_acceptor(
            ir.derp_tls_cert_path.as_deref(),
            ir.derp_tls_key_path.as_deref(),
        )?;

        let mesh_with = ir.derp_mesh_with.clone().unwrap_or_default();
        let verify_client_urls = ir.derp_verify_client_url.clone().unwrap_or_default();
        let verify_client_endpoints = ir.derp_verify_client_endpoint.clone().unwrap_or_default();

        if tls_acceptor.is_some() {
            tracing::info!(
                service = "derp",
                tag = tag.as_ref(),
                "TLS enabled for DERP connections"
            );
        }

        if !verify_client_urls.is_empty() || !verify_client_endpoints.is_empty() {
            tracing::info!(
                service = "derp",
                tag = tag.as_ref(),
                verify_urls = verify_client_urls.len(),
                verify_endpoints = verify_client_endpoints.len(),
                "Client verification enabled"
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
            home,
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
            verify_client_urls,
            verify_client_endpoints,
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

    /// HTTP server for DERP endpoints (HTTP/1.1 + HTTP/2).
    #[allow(clippy::too_many_arguments)]
    async fn run_http_server(
        listener: TcpListener,
        shutdown: Arc<Notify>,
        tag: Arc<str>,
        home: Arc<str>,
        rate_limiter: Arc<RateLimiter>,
        client_registry: Arc<ClientRegistry>,
        server_key: PublicKey,
        pending_relays: Arc<parking_lot::Mutex<HashMap<String, RelayStream>>>,
        mesh_psk: Option<String>,
        verify_client_urls: Arc<[String]>,
        verify_client_endpoints: Arc<[String]>,
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
                    let home = home.clone();
                    let verify_client_urls = verify_client_urls.clone();
                    let verify_client_endpoints = verify_client_endpoints.clone();

                    tokio::spawn(async move {
                        // Parse mesh_psk hex string to mesh_key bytes
                        let mesh_key: Option<[u8; 32]> = mesh_psk.as_ref().and_then(|psk| {
                            if psk.len() != 64 {
                                return None;
                            }
                            let mut key = [0u8; 32];
                            for (i, chunk) in psk.as_bytes().chunks(2).enumerate() {
                                if chunk.len() != 2 || i >= 32 {
                                    return None;
                                }
                                let high = match chunk[0] {
                                    b'0'..=b'9' => chunk[0] - b'0',
                                    b'a'..=b'f' => chunk[0] - b'a' + 10,
                                    b'A'..=b'F' => chunk[0] - b'A' + 10,
                                    _ => return None,
                                };
                                let low = match chunk[1] {
                                    b'0'..=b'9' => chunk[1] - b'0',
                                    b'a'..=b'f' => chunk[1] - b'a' + 10,
                                    b'A'..=b'F' => chunk[1] - b'A' + 10,
                                    _ => return None,
                                };
                                key[i] = (high << 4) | low;
                            }
                            Some(key)
                        });
                        let http_state = DerpHttpState {
                            tag: tag.clone(),
                            peer: peer_addr,
                            client_registry: client_registry.clone(),
                            server_key,
                            mesh_psk: mesh_psk.clone(),
                            mesh_key,
                            home,
                            verify_client_urls,
                            verify_client_endpoints,
                        };

                        let result = match tls_acceptor {
                            Some(acceptor) => {
                                match acceptor.accept(stream).await {
                                    Ok(tls_stream) => {
                                        tracing::debug!(service = "derp", peer = %peer_addr, "Accepted DERP TLS connection");
                                        Self::handle_http_connection(
                                            tls_stream,
                                            peer_addr,
                                            http_state,
                                            pending_relays,
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
                                    http_state,
                                    pending_relays,
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
        http_state: DerpHttpState,
        pending_relays: Arc<parking_lot::Mutex<HashMap<String, RelayStream>>>,
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
                http_state.tag.clone(),
                http_state.client_registry.clone(),
                http_state.server_key,
                false, // is_mesh_peer
                http_state.verify_client_urls.clone(),
                http_state.verify_client_endpoints.clone(),
                http_state.mesh_key,
            )
            .await;
        }

        let prefix = &buf[..read];
        let initial_data = prefix.to_vec();

        // Check for HTTP
        if Self::looks_like_http(prefix) {
            let mut http_buf = initial_data;

            // Fast-start DERP clients (Go derphttp_client) send `Derp-Fast-Start: 1` and then
            // immediately start speaking DERP frames after the HTTP request without waiting for
            // the 101 Switching Protocols response. To preserve compatibility, we must not send
            // any HTTP response bytes for this path.
            if !http_buf.starts_with(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n") {
                const MAX_HDR_BYTES: usize = 16 * 1024;
                let mut header_end = http_buf
                    .windows(4)
                    .position(|w| w == b"\r\n\r\n")
                    .map(|i| i + 4);

                while header_end.is_none() && http_buf.len() < MAX_HDR_BYTES {
                    let mut tmp = [0u8; 1024];
                    let n = match timeout(Duration::from_millis(200), stream.read(&mut tmp)).await
                    {
                        Ok(result) => result?,
                        Err(_) => 0,
                    };
                    if n == 0 {
                        break;
                    }
                    http_buf.extend_from_slice(&tmp[..n]);
                    header_end = http_buf
                        .windows(4)
                        .position(|w| w == b"\r\n\r\n")
                        .map(|i| i + 4);
                }

                if let Some(end) = header_end {
                    let head = String::from_utf8_lossy(&http_buf[..end]);
                    let mut lines = head.split("\r\n");
                    let first = lines.next().unwrap_or("");
                    let mut parts = first.split_whitespace();
                    let _method = parts.next().unwrap_or("");
                    let path = parts.next().unwrap_or("");

                    let mut upgrade: Option<String> = None;
                    let mut fast_start = false;
                    for line in lines {
                        if line.is_empty() {
                            break;
                        }
                        let mut it = line.splitn(2, ':');
                        let key = it.next().unwrap_or("").trim().to_ascii_lowercase();
                        let val = it.next().unwrap_or("").trim();
                        match key.as_str() {
                            "upgrade" => upgrade = Some(val.to_ascii_lowercase()),
                            "derp-fast-start" => fast_start = val == "1",
                            _ => {}
                        }
                    }

                    if fast_start && path == "/derp" && upgrade.as_deref() == Some("derp") {
                        let leftover = http_buf[end..].to_vec();
                        let prefixed = PrefixedStream::new(stream, leftover);
                        return Self::handle_derp_client(
                            prefixed,
                            peer,
                            http_state.tag.clone(),
                            http_state.client_registry.clone(),
                            http_state.server_key,
                            false, // is_mesh_peer
                            http_state.verify_client_urls.clone(),
                            http_state.verify_client_endpoints.clone(),
                            http_state.mesh_key,
                        )
                        .await;
                    }
                }
            }

            let prefixed = PrefixedStream::new(stream, http_buf);
            return Self::serve_http_connection(prefixed, http_state).await;
        }

        // Check for DERP protocol (starts with frame type byte)
        if Self::looks_like_derp_protocol(prefix) {
            tracing::debug!(service = "derp", peer = %peer, "Detected DERP protocol connection");
            let prefixed = PrefixedStream::new(stream, initial_data);
            return Self::handle_derp_client(
                prefixed,
                peer,
                http_state.tag.clone(),
                http_state.client_registry.clone(),
                http_state.server_key,
                false, // is_mesh_peer
                http_state.verify_client_urls.clone(),
                http_state.verify_client_endpoints.clone(),
                http_state.mesh_key,
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
                http_state.client_registry.metrics().connect_failed("bad_handshake");
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

        if let Err(e) = Self::validate_token(&handshake, http_state.mesh_psk.as_deref()) {
            let _ = prefixed_stream
                .write_all(b"ERR unauthorized (invalid DERP token)\n")
                .await;
            let _ = prefixed_stream.shutdown().await;
            http_state.client_registry.metrics().connect_failed("unauthorized");
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
        if prefix.starts_with(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n") {
            return true;
        }
        HTTP_PREFIXES.iter().any(|p| prefix.starts_with(p))
    }

    async fn serve_http_connection<S>(stream: S, state: DerpHttpState) -> io::Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let service = service_fn(move |req| {
            let state = state.clone();
            async move { state.handle(req).await }
        });

        hyper::server::conn::Http::new()
            .serve_connection(stream, service)
            .with_upgrades()
            .await
            .map_err(|e| io::Error::other(format!("derp http serve_connection error: {e}")))?;

        Ok(())
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

    /// Verify a client via configured HTTP URLs.
    ///
    /// Sends POST requests to all configured verify URLs with the client's
    /// public key. Returns Ok(true) if any URL returns 200/204, Ok(false) if
    /// no URLs configured, or Err if all URLs reject.
    async fn verify_client_via_urls(
        verify_urls: &[String],
        client_key: &PublicKey,
    ) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        if verify_urls.is_empty() {
            return Ok(false); // No verification required
        }

        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .map_err(|e| io::Error::other(format!("Failed to create HTTP client: {}", e)))?;

        let key_hex = format!("{:x?}", client_key);

        for url in verify_urls {
            let response = client
                .post(url)
                .header("Content-Type", "application/json")
                .body(format!(r#"{{"publicKey":"{}"}}"#, key_hex))
                .send()
                .await;

            match response {
                Ok(resp) if resp.status().is_success() => {
                    tracing::debug!(service = "derp", url = %url, key = ?client_key, "Client verified via URL");
                    return Ok(true);
                }
                Ok(resp) => {
                    tracing::debug!(service = "derp", url = %url, status = %resp.status(), "Verify URL rejected client");
                }
                Err(e) => {
                    tracing::warn!(service = "derp", url = %url, error = %e, "Verify URL request failed");
                }
            }
        }

        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "All verify URLs rejected client",
        ).into())
    }

    /// Verify a DERP client via Tailscale LocalClient endpoints (socket paths).
    /// Uses WhoIsNodeKey API to check if client is a registered Tailscale node.
    /// Returns Ok(true) if verified, Ok(false) if no endpoints configured, Err if all reject.
    async fn verify_client_via_endpoints(
        verify_endpoints: &[String],
        client_key: &PublicKey,
    ) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        if verify_endpoints.is_empty() {
            return Ok(false); // No verification required
        }

        // Format the client key as hex for the whois query
        let key_hex = client_key.iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>();

        for endpoint in verify_endpoints {
            match Self::check_whois_endpoint(endpoint, &key_hex).await {
                Ok(true) => {
                    tracing::debug!(
                        service = "derp",
                        endpoint = %endpoint,
                        key = %key_hex,
                        "Client verified via Tailscale LocalClient"
                    );
                    return Ok(true);
                }
                Ok(false) => {
                    tracing::debug!(
                        service = "derp",
                        endpoint = %endpoint,
                        "Client key not found at endpoint"
                    );
                }
                Err(e) => {
                    tracing::warn!(
                        service = "derp",
                        endpoint = %endpoint,
                        error = %e,
                        "Failed to query Tailscale endpoint"
                    );
                }
            }
        }

        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Client not found in any configured Tailscale endpoints",
        ).into())
    }

    /// Check a single Tailscale LocalClient endpoint for the client key.
    /// Connects via Unix socket or HTTP and calls WhoIsNodeKey API.
    async fn check_whois_endpoint(
        endpoint: &str,
        key_hex: &str,
    ) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        // Tailscale LocalAPI path: /localapi/v0/whois?addr=<nodekey_hex>
        let query = format!("/localapi/v0/whois?addr={}", key_hex);

        if endpoint.starts_with('/') || endpoint.starts_with("unix:") {
            // Unix socket path
            #[cfg(unix)]
            {
                use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
                use tokio::net::UnixStream;

                let socket_path = endpoint.strip_prefix("unix:").unwrap_or(endpoint);
                let mut stream = UnixStream::connect(socket_path).await?;

                // Send HTTP request over Unix socket
                let request = format!(
                    "GET {} HTTP/1.1\r\nHost: local-tailscaled.sock\r\nConnection: close\r\n\r\n",
                    query
                );
                stream.write_all(request.as_bytes()).await?;
                stream.shutdown().await?;

                // Read response
                let mut reader = BufReader::new(stream);
                let mut status_line = String::new();
                reader.read_line(&mut status_line).await?;

                // Check if status is 200 OK
                if status_line.contains("200") {
                    return Ok(true);
                }
                return Ok(false);
            }
            #[cfg(not(unix))]
            {
                return Err("Unix sockets not supported on this platform".into());
            }
        } else {
            // HTTP endpoint (e.g., http://localhost:8080)
            let url = format!("{}{}", endpoint.trim_end_matches('/'), query);
            let client = reqwest::Client::builder()
                .timeout(Duration::from_secs(5))
                .build()?;

            let resp = client.get(&url).send().await?;
            if resp.status().is_success() {
                return Ok(true);
            }
            Ok(false)
        }
    }

    async fn handle_derp_client<S>(
        stream: S,
        peer: SocketAddr,
        tag: Arc<str>,
        client_registry: Arc<ClientRegistry>,
        server_key: PublicKey,
        is_mesh_peer: bool,
        verify_client_urls: Arc<[String]>,
        verify_client_endpoints: Arc<[String]>,
        server_mesh_key: Option<[u8; 32]>,
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
        let (client_key, is_mesh_peer) = match DerpFrame::read_from_async(&mut read_half).await {
            Ok(DerpFrame::ClientInfo { key, encrypted_info }) => {
                // Check if client provided a mesh key that matches server's mesh key
                let mut detected_mesh_peer = is_mesh_peer;
                if !detected_mesh_peer && !encrypted_info.is_empty() {
                    if let Some(ref server_mk) = server_mesh_key {
                        // Try to parse ClientInfoPayload from encrypted_info
                        // Note: Currently no encryption, just JSON in encrypted_info field
                        if let Ok(payload) = ClientInfoPayload::from_json(&encrypted_info) {
                            if let Some(client_mk) = payload.mesh_key {
                                if client_mk == *server_mk {
                                    tracing::info!(
                                        service = "derp",
                                        peer = %peer,
                                        "Client authenticated as mesh peer via mesh_key"
                                    );
                                    detected_mesh_peer = true;
                                }
                            }
                        }
                    }
                }
                (key, detected_mesh_peer)
            }
            Ok(DerpFrame::ServerKey { key }) if is_mesh_peer => (key, true),
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

        if !is_mesh_peer {
            match Self::verify_client_via_urls(verify_client_urls.as_ref(), &client_key).await {
                Ok(true) => {}
                Ok(false) => {} // no verification configured
                Err(e) => {
                    client_registry.metrics().connect_failed("verify_url");
                    tracing::warn!(service = "derp", peer = %peer, client_key = ?client_key, error = %e, "Client verification failed");
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "client verification failed",
                    ));
                }
            }

            // Verify via Tailscale LocalClient endpoints (if configured)
            match Self::verify_client_via_endpoints(verify_client_endpoints.as_ref(), &client_key).await {
                Ok(true) => {}
                Ok(false) => {} // no endpoint verification configured
                Err(e) => {
                    client_registry.metrics().connect_failed("verify_endpoint");
                    tracing::warn!(service = "derp", peer = %peer, client_key = ?client_key, error = %e, "Client endpoint verification failed");
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "client endpoint verification failed",
                    ));
                }
            }
        }

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
                DerpFrame::PeerPresent { key, .. } => {
                    if is_mesh_peer {
                        client_registry.register_remote_client(key, client_key);
                    }
                }
                DerpFrame::PeerGone { key, .. } => {
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
                                            Arc::from(Vec::<String>::new().into_boxed_slice()),
                                            Arc::from(Vec::<String>::new().into_boxed_slice()),
                                            None, // mesh_key not needed - already is_mesh_peer=true
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
                let home: Arc<str> = Arc::from(self.home.clone().into_boxed_str());
                let verify_client_urls: Arc<[String]> =
                    Arc::from(self.verify_client_urls.clone().into_boxed_slice());
                let verify_client_endpoints: Arc<[String]> =
                    Arc::from(self.verify_client_endpoints.clone().into_boxed_slice());

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
                let verify_client_urls_http = verify_client_urls.clone();
                let verify_client_endpoints_http = verify_client_endpoints.clone();
                let home_http = home.clone();
                let http_handle = tokio::spawn(async move {
                    if let Err(e) = Self::run_http_server(
                        http_listener,
                        http_shutdown,
                        tag,
                        home_http,
                        rate_limiter,
                        client_registry,
                        server_key,
                        pending_relays,
                        mesh_psk_http,
                        verify_client_urls_http,
                        verify_client_endpoints_http,
                        tls_acceptor,
                    )
                    .await
                    {
                        tracing::error!(service = "derp", error = %e, "HTTP server failed");
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

            let mut config = ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(certs, private_key)
                .map_err(|e| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("TLS configuration error: {}", e),
                    )
                })?;

            // Match Go behavior: advertise HTTP/2 + HTTP/1.1 via ALPN.
            config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

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

    fn install_rustls_crypto_provider() {
        static ONCE: std::sync::Once = std::sync::Once::new();
        ONCE.call_once(|| {
            // rustls 0.23 requires an explicit process-level provider when multiple backends are enabled.
            let _ = rustls::crypto::ring::default_provider().install_default();
        });
    }

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
    async fn test_http_endpoints_plaintext() {
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
        assert!(ok_response.contains("<h1>DERP</h1>"), "expected home page, got: {ok_response}");
        let ok_lower = ok_response.to_ascii_lowercase();
        assert!(
            ok_lower.contains("strict-transport-security:"),
            "expected HSTS header, got: {ok_response}"
        );
        assert!(
            ok_lower.contains("content-security-policy:"),
            "expected CSP header, got: {ok_response}"
        );
        assert!(
            ok_lower.contains("x-frame-options: deny"),
            "expected X-Frame-Options header, got: {ok_response}"
        );
        assert!(
            ok_lower.contains("x-content-type-options: nosniff"),
            "expected X-Content-Type-Options header, got: {ok_response}"
        );

        let unknown_path = send_http_request(
            port,
            "GET /missing HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(
            unknown_path.contains("200 OK"),
            "expected 200 response, got: {unknown_path}"
        );
        assert!(
            unknown_path.contains("<h1>DERP</h1>"),
            "expected home fallback, got: {unknown_path}"
        );

        let robots = send_http_request(
            port,
            "GET /robots.txt HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(robots.contains("200 OK"), "expected 200, got: {robots}");
        assert!(
            robots.contains("User-agent: *\nDisallow: /"),
            "expected robots body, got: {robots}"
        );
        let robots_lower = robots.to_ascii_lowercase();
        assert!(
            robots_lower.contains("strict-transport-security:"),
            "expected HSTS header on robots.txt, got: {robots}"
        );

        let no_content = send_http_request(
            port,
            "GET /generate_204 HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(
            no_content.contains("204"),
            "expected 204 response, got: {no_content}"
        );

        struct StaticDns;
        #[async_trait::async_trait]
        impl crate::dns::Resolver for StaticDns {
            async fn resolve(&self, _domain: &str) -> anyhow::Result<crate::dns::DnsAnswer> {
                use crate::dns::cache::{Rcode, Source};
                Ok(crate::dns::DnsAnswer::new(
                    vec!["1.2.3.4".parse().unwrap()],
                    Duration::from_secs(60),
                    Source::Static,
                    Rcode::NoError,
                ))
            }

            fn name(&self) -> &str {
                "static_dns"
            }
        }

        crate::dns::global::set(Arc::new(StaticDns));
        let bootstrap = send_http_request(
            port,
            "GET /bootstrap-dns?q=example.com HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(
            bootstrap.contains("{\"example.com\":[\"1.2.3.4\"]}"),
            "expected bootstrap-dns JSON, got: {bootstrap}"
        );
        let bootstrap_lower = bootstrap.to_ascii_lowercase();
        assert!(
            bootstrap_lower.contains("strict-transport-security:"),
            "expected HSTS header on bootstrap-dns, got: {bootstrap}"
        );
        crate::dns::global::clear();

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

        install_rustls_crypto_provider();

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
        assert!(
            response.contains("<h1>DERP</h1>"),
            "expected home page over TLS, got: {response}"
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

        let psk = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

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
            derp_mesh_psk: Some(psk.to_string()),
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
        let handshake_a = format!("DERP session auth-ok token={psk}\n");
        a.write_all(handshake_a.as_bytes())
            .await
            .expect("handshake a");
        let handshake_b = format!("DERP session auth-ok token={psk}\n");
        b.write_all(handshake_b.as_bytes())
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

    async fn connect_derp_upgrade(
        port: u16,
        client_key: PublicKey,
        fast_start: bool,
    ) -> PrefixedStream<TcpStream> {
        let mut stream = TcpStream::connect(("127.0.0.1", port))
            .await
            .expect("connect");

        let mut req =
            String::from("GET /derp HTTP/1.1\r\nHost: localhost\r\nUpgrade: DERP\r\nConnection: Upgrade\r\n");
        if fast_start {
            req.push_str("Derp-Fast-Start: 1\r\n");
        }
        req.push_str("\r\n");

        stream
            .write_all(req.as_bytes())
            .await
            .expect("write request");
        stream.flush().await.expect("flush request");

        let mut prefix = Vec::new();
        if !fast_start {
            let mut tmp = [0u8; 1024];
            loop {
                let n = stream.read(&mut tmp).await.expect("read response");
                assert!(n > 0, "connection closed before response");
                prefix.extend_from_slice(&tmp[..n]);
                if let Some(idx) = prefix.windows(4).position(|w| w == b"\r\n\r\n") {
                    let end = idx + 4;
                    let head = String::from_utf8_lossy(&prefix[..end]);
                    assert!(
                        head.contains("101 Switching Protocols"),
                        "expected 101 response, got: {head}"
                    );
                    prefix = prefix[end..].to_vec();
                    break;
                }
                assert!(prefix.len() <= 16 * 1024, "response headers too large");
            }
        }

        let mut derp = PrefixedStream::new(stream, prefix);
        let server_key = DerpFrame::read_from_async(&mut derp)
            .await
            .expect("server key");
        assert!(matches!(server_key, DerpFrame::ServerKey { .. }));

        DerpFrame::ClientInfo { key: client_key, encrypted_info: vec![] }
            .write_to_async(&mut derp)
            .await
            .expect("clientinfo");
        derp.flush().await.expect("flush clientinfo");

        derp
    }

    #[tokio::test]
    async fn test_derp_over_websocket_ping_pong() {
        use sb_transport::websocket::{WebSocketConfig, WebSocketDialer};
        use sb_transport::Dialer;

        let port = match alloc_port() {
            Ok(port) => port,
            Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
                eprintln!("skipping derp ws test: {e}");
                return;
            }
            Err(e) => panic!("failed to allocate port: {e}"),
        };

        let ir = ServiceIR {
            ty: ServiceType::Derp,
            tag: Some("derp-ws".to_string()),
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
        service.start(StartStage::Start).expect("start");
        tokio::time::sleep(Duration::from_millis(50)).await;

        let ws_cfg = WebSocketConfig {
            path: "/derp".to_string(),
            headers: vec![("Sec-WebSocket-Protocol".to_string(), "derp".to_string())],
            ..Default::default()
        };
        let dialer = WebSocketDialer::new(ws_cfg, Box::new(sb_transport::TcpDialer::default()));
        let mut stream = dialer
            .connect("127.0.0.1", port)
            .await
            .expect("ws connect");

        let server_key = DerpFrame::read_from_async(&mut stream)
            .await
            .expect("server key");
        assert!(matches!(server_key, DerpFrame::ServerKey { .. }));

        DerpFrame::ClientInfo { key: [9u8; 32], encrypted_info: vec![] }
            .write_to_async(&mut stream)
            .await
            .expect("clientinfo");
        stream.flush().await.expect("flush clientinfo");

        let ping_data = [1u8, 2, 3, 4, 5, 6, 7, 8];
        DerpFrame::Ping { data: ping_data }
            .write_to_async(&mut stream)
            .await
            .expect("ping");
        stream.flush().await.expect("flush ping");

        let pong = tokio::time::timeout(Duration::from_secs(2), DerpFrame::read_from_async(&mut stream))
            .await
            .expect("timeout")
            .expect("read pong");
        assert!(matches!(pong, DerpFrame::Pong { data } if data == ping_data));

        service.close().unwrap();
    }

    #[tokio::test]
    async fn test_derp_over_http_upgrade_end_to_end() {
        let port = match alloc_port() {
            Ok(port) => port,
            Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
                eprintln!("skipping derp http upgrade test: {e}");
                return;
            }
            Err(e) => panic!("failed to allocate port: {e}"),
        };

        let ir = ServiceIR {
            ty: ServiceType::Derp,
            tag: Some("derp-h1-upgrade".to_string()),
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
        service.start(StartStage::Start).expect("start");
        tokio::time::sleep(Duration::from_millis(50)).await;

        let mut c1 = connect_derp_upgrade(port, [1u8; 32], false).await;
        let mut c2 = connect_derp_upgrade(port, [2u8; 32], false).await;

        // Client1 -> Client2
        let packet = vec![0xAA, 0xBB, 0xCC, 0xDD];
        DerpFrame::SendPacket {
            dst_key: [2u8; 32],
            packet: packet.clone(),
        }
        .write_to_async(&mut c1)
        .await
        .expect("send packet");
        c1.flush().await.expect("flush send packet");

        let recv =
            tokio::time::timeout(Duration::from_secs(2), DerpFrame::read_from_async(&mut c2))
                .await
                .expect("timeout waiting for packet")
                .expect("read frame");
        match recv {
            DerpFrame::RecvPacket { src_key, packet: got } => {
                assert_eq!(src_key, [1u8; 32]);
                assert_eq!(got, packet);
            }
            other => panic!("expected RecvPacket, got {:?}", other.frame_type()),
        }

        // Drive a simple ping/pong on the other direction too.
        let ping_data = [9u8, 8, 7, 6, 5, 4, 3, 2];
        DerpFrame::Ping { data: ping_data }
            .write_to_async(&mut c2)
            .await
            .expect("send ping");
        c2.flush().await.expect("flush ping");
        let pong =
            tokio::time::timeout(Duration::from_secs(2), DerpFrame::read_from_async(&mut c2))
                .await
                .expect("timeout")
                .expect("read pong");
        assert!(matches!(pong, DerpFrame::Pong { data } if data == ping_data));

        service.close().unwrap();
    }

    #[tokio::test]
    async fn test_derp_http_fast_start_end_to_end() {
        let port = match alloc_port() {
            Ok(port) => port,
            Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
                eprintln!("skipping derp fast-start test: {e}");
                return;
            }
            Err(e) => panic!("failed to allocate port: {e}"),
        };

        let ir = ServiceIR {
            ty: ServiceType::Derp,
            tag: Some("derp-fast-start".to_string()),
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
        service.start(StartStage::Start).expect("start");
        tokio::time::sleep(Duration::from_millis(50)).await;

        let mut c = connect_derp_upgrade(port, [3u8; 32], true).await;

        let ping_data = [1u8, 2, 3, 4, 5, 6, 7, 8];
        DerpFrame::Ping { data: ping_data }
            .write_to_async(&mut c)
            .await
            .expect("send ping");
        c.flush().await.expect("flush ping");

        let pong = tokio::time::timeout(Duration::from_secs(2), DerpFrame::read_from_async(&mut c))
            .await
            .expect("timeout")
            .expect("read pong");
        assert!(matches!(pong, DerpFrame::Pong { data } if data == ping_data));

        service.close().unwrap();
    }

    #[tokio::test]
    async fn test_derp_requires_http_upgrade() {
        let port = match alloc_port() {
            Ok(port) => port,
            Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
                eprintln!("skipping derp upgrade-required test: {e}");
                return;
            }
            Err(e) => panic!("failed to allocate port: {e}"),
        };

        let ir = ServiceIR {
            ty: ServiceType::Derp,
            tag: Some("derp-upgrade-required".to_string()),
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
        service.start(StartStage::Start).expect("start");
        tokio::time::sleep(Duration::from_millis(50)).await;

        let resp = send_http_request(
            port,
            "GET /derp HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(
            resp.contains("426") || resp.contains("Upgrade Required"),
            "expected 426 upgrade required, got: {resp}"
        );
        assert!(
            resp.contains("DERP requires connection upgrade"),
            "expected upgrade-required body, got: {resp}"
        );

        service.close().unwrap();
    }

    #[tokio::test]
    async fn test_derp_probe_handler() {
        let port = match alloc_port() {
            Ok(port) => port,
            Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
                eprintln!("skipping derp probe test: {e}");
                return;
            }
            Err(e) => panic!("failed to allocate port: {e}"),
        };

        let ir = ServiceIR {
            ty: ServiceType::Derp,
            tag: Some("derp-probe".to_string()),
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
        service.start(StartStage::Start).expect("start");
        tokio::time::sleep(Duration::from_millis(50)).await;

        let probe_get = send_http_request(
            port,
            "GET /derp/probe HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
        .await;
        let probe_get_lower = probe_get.to_ascii_lowercase();
        assert!(
            probe_get_lower.contains("200 ok"),
            "expected 200 probe response, got: {probe_get}"
        );
        assert!(
            probe_get_lower.contains("access-control-allow-origin: *"),
            "expected CORS header on probe response, got: {probe_get}"
        );
        assert!(
            !probe_get_lower.contains("strict-transport-security:"),
            "probe should not include browser headers, got: {probe_get}"
        );

        let probe_post = send_http_request(
            port,
            "POST /derp/probe HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
        )
        .await;
        let probe_post_lower = probe_post.to_ascii_lowercase();
        assert!(
            probe_post_lower.contains("405"),
            "expected 405 probe response, got: {probe_post}"
        );
        assert!(
            probe_post.contains("bogus probe method"),
            "expected probe body, got: {probe_post}"
        );

        service.close().unwrap();
    }

    #[tokio::test]
    async fn test_generate_204_challenge_response() {
        let port = match alloc_port() {
            Ok(port) => port,
            Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
                eprintln!("skipping generate_204 challenge test: {e}");
                return;
            }
            Err(e) => panic!("failed to allocate port: {e}"),
        };

        let ir = ServiceIR {
            ty: ServiceType::Derp,
            tag: Some("derp-204".to_string()),
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
        service.start(StartStage::Start).expect("start");
        tokio::time::sleep(Duration::from_millis(50)).await;

        let challenge = "abcDEF0123.-_";
        let req = format!(
            "GET /generate_204 HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nX-Tailscale-Challenge: {challenge}\r\n\r\n"
        );
        let resp = send_http_request(port, &req).await;
        assert!(resp.contains("204"), "expected 204 response, got: {resp}");
        assert!(
            resp.contains(&format!("response {challenge}")),
            "expected challenge response header, got: {resp}"
        );
        let resp_lower = resp.to_ascii_lowercase();
        assert!(
            resp_lower.contains("x-tailscale-response:"),
            "expected x-tailscale-response header, got: {resp}"
        );
        assert!(
            !resp_lower.contains("strict-transport-security:"),
            "generate_204 should not include browser headers, got: {resp}"
        );

        let bad_req = "GET /generate_204 HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nX-Tailscale-Challenge: bad!\r\n\r\n";
        let bad_resp = send_http_request(port, bad_req).await;
        assert!(
            !bad_resp.to_ascii_lowercase().contains("x-tailscale-response:"),
            "expected no response header for invalid challenge, got: {bad_resp}"
        );

        service.close().unwrap();
    }

    #[tokio::test]
    async fn test_verify_client_url_enforced() {
        use hyper::service::{make_service_fn, service_fn};
        use tokio::sync::oneshot;

        // Start a local verify server: POST /ok => 204, POST /deny => 403.
        let std_listener = match StdTcpListener::bind("127.0.0.1:0") {
            Ok(listener) => listener,
            Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
                eprintln!("skipping verify_client_url test: {e}");
                return;
            }
            Err(e) => panic!("bind verify server: {e}"),
        };
        std_listener.set_nonblocking(true).expect("nonblocking");
        let verify_addr = std_listener.local_addr().expect("verify addr");
        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();

        let make_svc = make_service_fn(|_conn| async {
            Ok::<_, Infallible>(service_fn(|req: HyperRequest<Body>| async move {
                let status = match (req.method(), req.uri().path()) {
                    (&hyper::Method::POST, "/ok") => StatusCode::NO_CONTENT,
                    (&hyper::Method::POST, "/deny") => StatusCode::FORBIDDEN,
                    _ => StatusCode::NOT_FOUND,
                };
                Ok::<_, Infallible>({
                    let mut resp = HyperResponse::new(Body::empty());
                    *resp.status_mut() = status;
                    resp
                })
            }))
        });

        let server = hyper::Server::from_tcp(std_listener)
            .unwrap()
            .serve(make_svc)
            .with_graceful_shutdown(async move {
                let _ = shutdown_rx.await;
            });
        let verify_handle = tokio::spawn(async move {
            let _ = server.await;
        });

        // Start DERP service with verify_client_url=/ok (should accept).
        let port_ok = match alloc_port() {
            Ok(port) => port,
            Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
                eprintln!("skipping verify_client_url test: {e}");
                let _ = shutdown_tx.send(());
                verify_handle.abort();
                return;
            }
            Err(e) => panic!("failed to allocate port: {e}"),
        };
        let ir_ok = ServiceIR {
            ty: ServiceType::Derp,
            tag: Some("derp-verify-ok".to_string()),
            derp_listen: Some("127.0.0.1".to_string()),
            derp_listen_port: Some(port_ok),
            derp_stun_enabled: Some(false),
            derp_verify_client_url: Some(vec![format!("http://{}/ok", verify_addr)]),
            derp_config_path: None,
            derp_verify_client_endpoint: None,
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
        let derp_ok = DerpService::from_ir(&ir_ok, &ctx).expect("derp ok service");
        derp_ok.start(StartStage::Start).expect("start derp ok");
        tokio::time::sleep(Duration::from_millis(50)).await;

        let mut ok_stream = TcpStream::connect(("127.0.0.1", port_ok)).await.expect("connect");
        let _ = DerpFrame::read_from_async(&mut ok_stream)
            .await
            .expect("server key");
        DerpFrame::ClientInfo { key: [7u8; 32], encrypted_info: vec![] }
            .write_to_async(&mut ok_stream)
            .await
            .expect("client info");
        DerpFrame::Ping { data: [1, 1, 2, 3, 5, 8, 13, 21] }
            .write_to_async(&mut ok_stream)
            .await
            .expect("ping");
        let pong = tokio::time::timeout(Duration::from_secs(2), DerpFrame::read_from_async(&mut ok_stream))
            .await
            .expect("timeout")
            .expect("pong");
        assert!(matches!(pong, DerpFrame::Pong { .. }));
        derp_ok.close().unwrap();

        // Start DERP service with verify_client_url=/deny (should reject).
        let port_deny = match alloc_port() {
            Ok(port) => port,
            Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
                eprintln!("skipping verify_client_url deny test: {e}");
                derp_ok.close().ok();
                let _ = shutdown_tx.send(());
                verify_handle.abort();
                return;
            }
            Err(e) => panic!("failed to allocate port: {e}"),
        };
        let ir_deny = ServiceIR {
            ty: ServiceType::Derp,
            tag: Some("derp-verify-deny".to_string()),
            derp_listen: Some("127.0.0.1".to_string()),
            derp_listen_port: Some(port_deny),
            derp_stun_enabled: Some(false),
            derp_verify_client_url: Some(vec![format!("http://{}/deny", verify_addr)]),
            derp_config_path: None,
            derp_verify_client_endpoint: None,
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
        let derp_deny = DerpService::from_ir(&ir_deny, &ctx).expect("derp deny service");
        derp_deny.start(StartStage::Start).expect("start derp deny");
        tokio::time::sleep(Duration::from_millis(50)).await;

        let mut deny_stream = TcpStream::connect(("127.0.0.1", port_deny)).await.expect("connect");
        let _ = DerpFrame::read_from_async(&mut deny_stream)
            .await
            .expect("server key");
        DerpFrame::ClientInfo { key: [8u8; 32], encrypted_info: vec![] }
            .write_to_async(&mut deny_stream)
            .await
            .expect("client info");

        // The server should close after verification fails; expect read error/EOF quickly.
        let denied = tokio::time::timeout(Duration::from_secs(2), DerpFrame::read_from_async(&mut deny_stream)).await;
        assert!(denied.is_err() || denied.unwrap().is_err(), "expected deny to close connection");
        derp_deny.close().unwrap();

        // Shutdown verify server.
        let _ = shutdown_tx.send(());
        verify_handle.abort();
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
        let client_info1 = DerpFrame::ClientInfo { key: client1_key, encrypted_info: vec![] };
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
        let client_info2 = DerpFrame::ClientInfo { key: client2_key, encrypted_info: vec![] };
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

        install_rustls_crypto_provider();

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
        let client_info1 = DerpFrame::ClientInfo { key: client1_key, encrypted_info: vec![] };
        client_info1
            .write_to_async(&mut stream1)
            .await
            .expect("send client1 info");

        let client_info2 = DerpFrame::ClientInfo { key: client2_key, encrypted_info: vec![] };
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
