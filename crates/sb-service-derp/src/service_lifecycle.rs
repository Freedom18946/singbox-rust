impl DerpService {
    /// Create a new DERP service from IR configuration.
    pub fn from_ir(
        ir: &ServiceIR,
        ctx: &ServiceContext,
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
            .listen
            .as_deref()
            .unwrap_or("127.0.0.1")
            .parse()
            .map_err(|e| format!("invalid listen address: {}", e))?;
        let listen_port = ir.listen_port.unwrap_or(3478);
        let listen_addr = SocketAddr::new(listen_ip, listen_port);

        // Listen options for server bind (Go parity: option.ListenOptions).
        let bind_interface = ir
            .bind_interface
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string());
        let routing_mark = ir.routing_mark;
        let reuse_addr = ir.reuse_addr.unwrap_or(false);
        let tcp_fast_open = ir.tcp_fast_open.unwrap_or(false);
        let tcp_multi_path = ir.tcp_multi_path.unwrap_or(false);

        // STUN: match Go sing-box semantics: only start STUN when `stun` is configured and enabled.
        let (stun_enabled, stun_addr, stun_options) = if let Some(stun) = &ir.stun {
            let stun_ip = stun
                .listen
                .as_deref()
                .unwrap_or("::")
                .parse()
                .map_err(|e| format!("invalid stun listen address: {}", e))?;
            let port = stun.listen_port.unwrap_or(3478);
            let port = if port == 0 { 3478 } else { port };
            (
                stun.enabled,
                SocketAddr::new(stun_ip, port),
                Some(stun.clone()),
            )
        } else {
            let addr = SocketAddr::new(IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED), 3478);
            (false, addr, None)
        };

        let mesh_psk = load_mesh_psk(ir)?;
        if let Some(psk) = mesh_psk.as_deref() {
            if !is_valid_mesh_psk(psk) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "mesh_psk must contain exactly 64 lowercase hex digits",
                )
                .into());
            }
        }

        let home = ir.home.clone().unwrap_or_default();
        if !home.is_empty()
            && home != "blank"
            && !home.starts_with("http://")
            && !home.starts_with("https://")
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid home value: {home}"),
            )
            .into());
        }

        let config_path = ir
            .config_path
            .as_deref()
            .map(str::trim)
            .filter(|p| !p.is_empty())
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "missing config_path"))?;

        // Load or generate server private key (persistent; Go-compatible `derper.key` JSON)
        let server_private_key = load_or_generate_server_private_key(Some(config_path))?;
        let server_public_key = derive_public_key(&server_private_key);

        let tls = ir.tls.as_ref().filter(|t| t.enabled).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "TLS is required for DERP server",
            )
        })?;
        let cert_path = tls.certificate_path.as_deref().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "missing tls.certificate_path")
        })?;
        let key_path = tls
            .key_path
            .as_deref()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "missing tls.key_path"))?;

        // Create TLS acceptor (required by Go parity)
        let tls_acceptor = create_tls_acceptor(Some(cert_path), Some(key_path))?;
        let runtime = DerpRuntimeCtx {
            dns_router: ctx.dns_router.clone(),
            outbounds: ctx.outbounds.clone(),
        };

        let endpoints = ctx.endpoints.clone();

        let mesh_with: Vec<DerpMeshPeerCfg> = ir
            .mesh_with
            .clone()
            .map(|l: Listable<StringOrObj<DerpMeshPeerIR>>| l.items)
            .unwrap_or_default()
            .into_iter()
            .map(|v| v.into_inner())
            .filter_map(|v| {
                let server = v.server.trim().to_string();
                if server.is_empty() {
                    return None;
                }
                let port = v.server_port.unwrap_or(0);
                let port = if port == 0 { 443 } else { port };
                Some(DerpMeshPeerCfg {
                    server,
                    port,
                    host: v
                        .host
                        .as_deref()
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                        .map(|s| s.to_string()),
                    tls: v.tls.clone(),
                    dial: v.dial.clone(),
                })
            })
            .collect();

        let verify_client_urls: Vec<DerpVerifyClientUrlCfg> = ir
            .verify_client_url
            .clone()
            .map(|l: Listable<StringOrObj<DerpVerifyClientUrlIR>>| l.items)
            .unwrap_or_default()
            .into_iter()
            .map(|v| v.into_inner())
            .filter_map(|v| {
                let raw = v.url.trim();
                if raw.is_empty() {
                    return None;
                }
                let url = match Url::parse(raw) {
                    Ok(u) => u,
                    Err(e) => {
                        tracing::warn!(service = "derp", tag = tag.as_ref(), url = raw, error = %e, "invalid verify_client_url");
                        return None;
                    }
                };
                Some(DerpVerifyClientUrlCfg { url, dial: v.dial })
            })
            .collect();

        let verify_client_endpoint_tags: Vec<String> = ir
            .verify_client_endpoint
            .clone()
            .map(|l: Listable<String>| l.items)
            .unwrap_or_default()
            .into_iter()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();

        if tls_acceptor.is_some() {
            tracing::info!(
                service = "derp",
                tag = tag.as_ref(),
                "TLS enabled for DERP connections"
            );
        }

        if !verify_client_urls.is_empty() || !verify_client_endpoint_tags.is_empty() {
            tracing::info!(
                service = "derp",
                tag = tag.as_ref(),
                verify_urls = verify_client_urls.len(),
                verify_endpoints = verify_client_endpoint_tags.len(),
                "Client verification enabled"
            );
        }

        tracing::info!(
            service = "derp",
            tag = tag.as_ref(),
            listen = %listen_addr,
            stun_port = stun_addr.port(),
            stun_enabled,
            tls_enabled = tls_acceptor.is_some(),
            mesh_psk = mesh_psk.as_deref().map(|_| "<redacted>"),
            mesh_peers = mesh_with.len(),
            server_public_key = ?server_public_key,
            "DERP service initialized (HTTP + STUN + DERP protocol + legacy mock relay)"
        );

        Ok(Arc::new(Self {
            tag: tag.clone(),
            listen_addr,
            bind_interface,
            routing_mark,
            reuse_addr,
            tcp_fast_open,
            tcp_multi_path,
            stun_addr,
            stun_enabled,
            stun_options,
            mesh_psk,
            home,
            server_private_key,
            server_public_key,
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
            verify_client_endpoint_tags,
            verify_client_endpoint_sockets: Arc::new(parking_lot::RwLock::new(Vec::new())),
            runtime,
            endpoints,
        }))
    }

    /// Create a customized TCP listener with options (socket2).
    fn create_listener(&self) -> io::Result<TcpListener> {
        // These listen options are Linux/Android-only today. Touch them unconditionally so
        // macOS builds (and clippy -D warnings) don't treat them as dead fields.
        let _ = (&self.bind_interface, self.routing_mark, self.tcp_fast_open);

        let domain = if self.listen_addr.is_ipv4() {
            Domain::IPV4
        } else {
            Domain::IPV6
        };
        let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;

        if self.reuse_addr {
            #[cfg(not(windows))]
            socket.set_reuse_address(true)?;
            #[cfg(not(windows))]
            socket.set_reuse_port(true)?;
        }

        #[cfg(any(target_os = "linux", target_os = "android"))]
        if let Some(mark) = self.routing_mark {
            socket.set_mark(mark)?;
        }

        #[cfg(any(target_os = "linux", target_os = "android"))]
        if let Some(ref iface) = self.bind_interface {
            socket.bind_to_device(Some(iface.as_bytes()))?;
        }

        #[cfg(any(target_os = "linux", target_os = "android"))]
        if self.tcp_fast_open {
            socket.set_tcp_fastopen(256)?;
        }

        if self.tcp_multi_path {
            #[cfg(target_os = "linux")]
            {
                // MPTCP server sockets aren't directly supported by socket2; keep config visible.
            }
        }

        socket.bind(&self.listen_addr.into())?;
        socket.listen(128)?;

        socket.set_nonblocking(true)?;
        let std_listener: std::net::TcpListener = socket.into();
        TcpListener::from_std(std_listener)
    }

    /// Create a UDP socket for STUN with listen options (socket2).
    fn create_stun_socket(&self) -> io::Result<UdpSocket> {
        let Some(stun) = self.stun_options.as_ref() else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "stun not configured",
            ));
        };
        if !self.stun_enabled {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "stun disabled"));
        }
        if stun.netns.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "stun.netns is not supported yet",
            ));
        }

        let domain = if self.stun_addr.is_ipv4() {
            Domain::IPV4
        } else {
            Domain::IPV6
        };
        let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;

        let reuse = stun.reuse_addr.unwrap_or(false);
        if reuse {
            #[cfg(not(windows))]
            socket.set_reuse_address(true)?;
            #[cfg(not(windows))]
            socket.set_reuse_port(true)?;
        }

        #[cfg(any(target_os = "linux", target_os = "android"))]
        if let Some(mark) = stun.routing_mark {
            socket.set_mark(mark)?;
        }

        #[cfg(any(target_os = "linux", target_os = "android"))]
        if let Some(ref iface) = stun.bind_interface {
            socket.bind_to_device(Some(iface.as_bytes()))?;
        }

        socket.bind(&self.stun_addr.into())?;
        socket.set_nonblocking(true)?;
        let std_udp: std::net::UdpSocket = socket.into();
        UdpSocket::from_std(std_udp)
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
}
