impl DerpService {
    fn build_derp_dialer(
        runtime: &DerpRuntimeCtx,
        dial: &DerpDialOptionsIR,
        tls: Option<Arc<ClientConfig>>,
        target_sni: Option<&str>,
    ) -> io::Result<Box<dyn Dialer>> {
        // Base dialer (TCP or detour).
        let mut base: Box<dyn Dialer> = if let Some(detour) = dial
            .detour
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            let outbounds = runtime.outbounds.clone().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "dial.detour requires ServiceContext.outbounds",
                )
            })?;
            let detour = detour.to_string();
            Box::new(FnDialer::new(move |host: &str, port: u16| {
                let outbounds = outbounds.clone();
                let detour = detour.clone();
                let host = host.to_string();
                Box::pin(async move {
                    let target = sb_core::outbound::RouteTarget::Named(detour);
                    let ep = if let Ok(ip) = host.parse::<IpAddr>() {
                        sb_core::outbound::Endpoint::Ip(SocketAddr::new(ip, port))
                    } else {
                        sb_core::outbound::Endpoint::Domain(host, port)
                    };
                    outbounds
                        .connect_tcp_stream(&target, ep)
                        .await
                        .map_err(DialError::from)
                })
                    as std::pin::Pin<
                        Box<
                            dyn std::future::Future<Output = Result<IoStream, DialError>>
                                + Send
                                + 'static,
                        >,
                    >
            }))
        } else {
            let mut builder = TransportBuilder::tcp();
            if let Some(iface) = dial
                .bind_interface
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
            {
                builder = builder.bind_interface(iface.to_string());
            }
            if let Some(v4) = dial
                .inet4_bind_address
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
            {
                if let Ok(ip) = v4.parse::<std::net::Ipv4Addr>() {
                    builder = builder.bind_v4(ip);
                }
            }
            if let Some(v6) = dial
                .inet6_bind_address
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
            {
                if let Ok(ip) = v6.parse::<std::net::Ipv6Addr>() {
                    builder = builder.bind_v6(ip);
                }
            }
            if let Some(mark) = dial.routing_mark {
                builder = builder.routing_mark(mark);
            }
            if let Some(reuse) = dial.reuse_addr {
                builder = builder.reuse_addr(reuse);
            }
            if let Some(timeout) = Self::parse_dial_timeout(&dial.connect_timeout)? {
                builder = builder.connect_timeout(timeout);
            }
            if let Some(tfo) = dial.tcp_fast_open {
                builder = builder.tcp_fast_open(tfo);
            }
            if let Some(mptcp) = dial.tcp_multi_path {
                builder = builder.tcp_multi_path(mptcp);
            }
            if let Some(udp_frag) = dial.udp_fragment {
                builder = builder.udp_fragment(udp_frag);
            }
            if let Some(ref netns) = dial.netns {
                #[cfg(target_os = "linux")]
                {
                    builder = builder.netns(netns.trim().to_string());
                }
                #[cfg(not(target_os = "linux"))]
                {
                    let _ = netns;
                    return Err(io::Error::new(
                        io::ErrorKind::Unsupported,
                        "dial.netns is only supported on Linux",
                    ));
                }
            }
            builder.build()
        };

        // Domain resolver wrapper (Go parity: Dial Fields `domain_resolver.server`).
        if let Some(dr) = dial
            .domain_resolver
            .as_ref()
            .and_then(|d| d.0.server.as_deref())
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            let router = runtime.dns_router.clone().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "dial.domain_resolver requires ServiceContext.dns_router",
                )
            })?;
            let transport = dr.to_string();
            let inner = Arc::new(base);
            base = Box::new(FnDialer::new(move |host: &str, port: u16| {
                let router = router.clone();
                let transport = transport.clone();
                let inner = inner.clone();
                let host_s = host.to_string();
                Box::pin(async move {
                    if DerpService::is_ip_literal(&host_s) {
                        return Dialer::connect(inner.as_ref(), &host_s, port).await;
                    }
                    let ctx = DnsQueryContext::new().with_transport(transport);
                    let ips = router.lookup(&ctx, &host_s).await.map_err(|e| {
                        DialError::Other(format!("domain_resolver lookup failed: {e}"))
                    })?;
                    let Some(ip) = ips.into_iter().next() else {
                        return Err(DialError::Other("domain_resolver returned no IPs".into()));
                    };
                    let ip_s = ip.to_string();
                    Dialer::connect(inner.as_ref(), &ip_s, port).await
                })
                    as std::pin::Pin<
                        Box<
                            dyn std::future::Future<Output = Result<IoStream, DialError>>
                                + Send
                                + 'static,
                        >,
                    >
            }));
        }

        // TLS wrapper (if requested by caller).
        if let Some(cfg) = tls {
            let sni = target_sni.map(|s| s.to_string());
            base = TransportBuilder::with_inner(base)
                .tls(cfg, sni, None)
                .build();
        }

        Ok(base)
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
        let key_hex = client_key
            .iter()
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
        )
        .into())
    }

    /// Check a single Tailscale LocalClient endpoint for the client key.
    /// Connects via Unix socket and calls WhoIsNodeKey API.
    async fn check_whois_endpoint(
        endpoint: &str,
        key_hex: &str,
    ) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        // Tailscale LocalAPI path: /localapi/v0/whois?addr=<nodekey_hex>
        let query = format!("/localapi/v0/whois?addr={}", key_hex);

        let socket_path = endpoint.strip_prefix("unix:").unwrap_or(endpoint);
        if !socket_path.starts_with('/') {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "verify_client_endpoint expects endpoint tags (resolved to LocalAPI socket paths) only",
            )
            .into());
        }

        // Unix socket path
        #[cfg(unix)]
        {
            use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
            use tokio::net::UnixStream;

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
            Ok(false)
        }
        #[cfg(not(unix))]
        {
            Err("Unix sockets not supported on this platform".into())
        }
    }
}
