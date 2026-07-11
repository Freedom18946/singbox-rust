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

#[allow(dead_code)]
struct HyperBodyReader {
    body: Body,
    buf: Bytes,
    pos: usize,
}

impl HyperBodyReader {
    #[allow(dead_code)]
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
            Poll::Ready(Some(Err(e))) => {
                Poll::Ready(Err(io::Error::other(format!("http body read error: {e}"))))
            }
            Poll::Ready(None) => Poll::Ready(Ok(())), // EOF
            Poll::Pending => Poll::Pending,
        }
    }
}

#[allow(dead_code)]
struct HyperBodyWriter {
    sender: Option<hyper::body::Sender>,
}

impl HyperBodyWriter {
    #[allow(dead_code)]
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
            Poll::Ready(Err(e)) => {
                Poll::Ready(Err(io::Error::other(format!("http body send error: {e}"))))
            }
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

#[allow(dead_code)]
struct HyperDuplex {
    reader: HyperBodyReader,
    writer: HyperBodyWriter,
}

impl HyperDuplex {
    #[allow(dead_code)]
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
            Poll::Ready(Some(Err(e))) => {
                Poll::Ready(Err(io::Error::other(format!("websocket read error: {e}"))))
            }
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
                    Poll::Ready(Err(e)) => {
                        Poll::Ready(Err(io::Error::other(format!("websocket flush error: {e}"))))
                    }
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
            Poll::Ready(Err(e)) => {
                Poll::Ready(Err(io::Error::other(format!("websocket flush error: {e}"))))
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.inner.poll_close_unpin(cx) {
            Poll::Ready(Ok(())) => {
                self.write_pending_len = None;
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(e)) => {
                Poll::Ready(Err(io::Error::other(format!("websocket close error: {e}"))))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

#[derive(Clone)]
struct DerpHttpState {
    tag: Arc<str>,
    peer: SocketAddr,
    client_registry: Arc<ClientRegistry>,
    server_private_key: PrivateKey,
    server_public_key: PublicKey,
    mesh_psk: Option<String>,
    home: Arc<str>,
    runtime: DerpRuntimeCtx,
    verify_client_urls: Arc<[DerpVerifyClientUrlCfg]>,
    verify_client_endpoints: Arc<parking_lot::RwLock<Vec<String>>>,
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
                    resp.headers_mut()
                        .insert(NO_CONTENT_RESPONSE_HEADER, header_val);
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
        let Ok(location) = hyper::header::HeaderValue::from_str(home) else {
            return Self::text(StatusCode::INTERNAL_SERVER_ERROR, "invalid home redirect\n");
        };
        resp.headers_mut().insert(LOCATION, location);
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
        resp.headers_mut()
            .insert(CONNECTION, hyper::header::HeaderValue::from_static("close"));
        add_browser_headers(resp.headers_mut());

        let Some(domain) = query_param(req.uri().query(), "q") else {
            *resp.body_mut() = Body::from("{}");
            return resp;
        };

        let Some(router) = self.runtime.dns_router.as_ref() else {
            tracing::warn!(
                service = "derp",
                domain,
                "bootstrap-dns requested but no dns_router injected"
            );
            *resp.body_mut() = Body::from("{}");
            return resp;
        };

        match router.lookup(&DnsQueryContext::new(), domain).await {
            Ok(ips) => {
                let addrs: Vec<String> = ips.into_iter().map(|ip| ip.to_string()).collect();
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

    fn handle_derp_upgrade(
        &self,
        req: &mut HyperRequest<Body>,
        is_mesh_peer: bool,
    ) -> HyperResponse<Body> {
        let on_upgrade = hyper::upgrade::on(req);

        let tag = self.tag.clone();
        let peer = self.peer;
        let client_registry = self.client_registry.clone();
        let server_private_key = self.server_private_key;
        let server_public_key = self.server_public_key;
        let runtime = self.runtime.clone();
        let verify_client_urls = self.verify_client_urls.clone();
        let verify_client_endpoints = self.verify_client_endpoints.clone();
        let mesh_psk = self.mesh_psk.clone();

        tokio::spawn(async move {
            match on_upgrade.await {
                Ok(upgraded) => {
                    if let Err(e) = DerpService::handle_derp_client(
                        upgraded,
                        peer,
                        tag,
                        client_registry,
                        server_private_key,
                        server_public_key,
                        is_mesh_peer,
                        runtime,
                        verify_client_urls,
                        verify_client_endpoints,
                        mesh_psk,
                    )
                    .await
                    {
                        tracing::debug!(service = "derp", peer = %peer, error = %e, "derp upgraded connection ended");
                    }
                }
                Err(e) => {
                    tracing::debug!(service = "derp", peer = %peer, error = %e, "derp upgrade failed")
                }
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
        resp.headers_mut().insert(
            CONNECTION,
            hyper::header::HeaderValue::from_static("Upgrade"),
        );
        resp.headers_mut().insert(
            DERP_VERSION_HEADER,
            hyper::header::HeaderValue::from_static("2"),
        );
        let Ok(public_key) =
            hyper::header::HeaderValue::from_str(&hex::encode(server_public_key))
        else {
            return Self::text(StatusCode::INTERNAL_SERVER_ERROR, "invalid server key\n");
        };
        resp.headers_mut().insert(DERP_PUBLIC_KEY_HEADER, public_key);
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
        let server_private_key = self.server_private_key;
        let server_public_key = self.server_public_key;
        let runtime = self.runtime.clone();
        let verify_client_urls = self.verify_client_urls.clone();
        let verify_client_endpoints = self.verify_client_endpoints.clone();
        let mesh_psk = self.mesh_psk.clone();

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
                        server_private_key,
                        server_public_key,
                        false,
                        runtime,
                        verify_client_urls,
                        verify_client_endpoints,
                        mesh_psk,
                    )
                    .await
                    {
                        tracing::debug!(service = "derp", peer = %peer, error = %e, "derp websocket ended");
                    }
                }
                Err(e) => {
                    tracing::debug!(service = "derp", peer = %peer, error = %e, "websocket upgrade failed")
                }
            }
        });

        let mut resp = HyperResponse::new(Body::empty());
        *resp.status_mut() = StatusCode::SWITCHING_PROTOCOLS;
        resp.headers_mut().insert(
            UPGRADE,
            hyper::header::HeaderValue::from_static("websocket"),
        );
        resp.headers_mut().insert(
            CONNECTION,
            hyper::header::HeaderValue::from_static("Upgrade"),
        );
        let Ok(accept_header) = hyper::header::HeaderValue::from_str(&accept_key) else {
            return Self::text(StatusCode::INTERNAL_SERVER_ERROR, "invalid websocket accept\n");
        };
        resp.headers_mut()
            .insert(SEC_WEBSOCKET_ACCEPT, accept_header);
        resp.headers_mut().insert(
            SEC_WEBSOCKET_PROTOCOL,
            hyper::header::HeaderValue::from_static("derp"),
        );
        resp
    }

    #[allow(dead_code)]
    fn handle_derp_stream(
        &self,
        req: &mut HyperRequest<Body>,
        is_mesh_peer: bool,
    ) -> HyperResponse<Body> {
        let (sender, body) = Body::channel();
        let reader = HyperBodyReader::new(std::mem::take(req.body_mut()));
        let writer = HyperBodyWriter::new(sender);
        let io = HyperDuplex::new(reader, writer);

        let tag = self.tag.clone();
        let peer = self.peer;
        let client_registry = self.client_registry.clone();
        let server_private_key = self.server_private_key;
        let server_public_key = self.server_public_key;
        let runtime = self.runtime.clone();
        let verify_client_urls = self.verify_client_urls.clone();
        let verify_client_endpoints = self.verify_client_endpoints.clone();
        let mesh_psk = self.mesh_psk.clone();

        tokio::spawn(async move {
            if let Err(e) = DerpService::handle_derp_client(
                io,
                peer,
                tag,
                client_registry,
                server_private_key,
                server_public_key,
                is_mesh_peer,
                runtime,
                verify_client_urls,
                verify_client_endpoints,
                mesh_psk,
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
