impl DerpService {
    /// HTTP server for DERP endpoints (HTTP/1.1 + HTTP/2).
    #[allow(clippy::too_many_arguments)]
    async fn run_http_server(
        listener: TcpListener,
        shutdown: Arc<Notify>,
        tag: Arc<str>,
        home: Arc<str>,
        rate_limiter: Arc<RateLimiter>,
        client_registry: Arc<ClientRegistry>,
        server_private_key: PrivateKey,
        server_public_key: PublicKey,
        pending_relays: Arc<parking_lot::Mutex<HashMap<String, RelayStream>>>,
        mesh_psk: Option<String>,
        runtime: DerpRuntimeCtx,
        verify_client_urls: Arc<[DerpVerifyClientUrlCfg]>,
        verify_client_endpoints: Arc<parking_lot::RwLock<Vec<String>>>,
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
                    let runtime = runtime.clone();

                    tokio::spawn(async move {
                        let http_state = DerpHttpState {
                            tag: tag.clone(),
                            peer: peer_addr,
                            client_registry: client_registry.clone(),
                            server_private_key,
                            server_public_key,
                            mesh_psk: mesh_psk.clone(),
                            home,
                            runtime,
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
                http_state.server_private_key,
                http_state.server_public_key,
                false, // is_mesh_peer
                http_state.runtime.clone(),
                http_state.verify_client_urls.clone(),
                http_state.verify_client_endpoints.clone(),
                http_state.mesh_psk.clone(),
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
                    let n = match timeout(Duration::from_millis(200), stream.read(&mut tmp)).await {
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
                            http_state.server_private_key,
                            http_state.server_public_key,
                            false, // is_mesh_peer
                            http_state.runtime.clone(),
                            http_state.verify_client_urls.clone(),
                            http_state.verify_client_endpoints.clone(),
                            http_state.mesh_psk.clone(),
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
                http_state.server_private_key,
                http_state.server_public_key,
                false, // is_mesh_peer
                http_state.runtime.clone(),
                http_state.verify_client_urls.clone(),
                http_state.verify_client_endpoints.clone(),
                http_state.mesh_psk.clone(),
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
                http_state
                    .client_registry
                    .metrics()
                    .connect_failed("bad_handshake");
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
            http_state
                .client_registry
                .metrics()
                .connect_failed("unauthorized");
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
}
