impl DerpService {
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
        runtime: &DerpRuntimeCtx,
        verify_urls: &[DerpVerifyClientUrlCfg],
        client_key: &PublicKey,
    ) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        if verify_urls.is_empty() {
            return Ok(false); // No verification required
        }

        let key_hex = client_key
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>();

        const VERIFY_TIMEOUT: Duration = Duration::from_secs(10);

        for cfg in verify_urls {
            let url = &cfg.url;
            let scheme = url.scheme();
            if scheme != "http" && scheme != "https" {
                tracing::warn!(
                    service = "derp",
                    url = %url,
                    scheme = %scheme,
                    "verify_client_url unsupported scheme"
                );
                continue;
            }

            let host = match url.host_str() {
                Some(h) if !h.is_empty() => h,
                _ => {
                    tracing::warn!(service = "derp", url = %url, "verify_client_url missing host");
                    continue;
                }
            };
            let port = match url.port_or_known_default() {
                Some(p) => p,
                None => {
                    tracing::warn!(service = "derp", url = %url, "verify_client_url missing port");
                    continue;
                }
            };

            let mut path = url.path().to_string();
            if path.is_empty() {
                path.push('/');
            }
            if let Some(q) = url.query() {
                path.push('?');
                path.push_str(q);
            }

            let tls = if scheme == "https" {
                Some(Self::build_derp_tls_config(None)?)
            } else {
                None
            };

            let dialer = Self::build_derp_dialer(runtime, &cfg.dial, tls, Some(host))?;
            let stream = dialer
                .connect(host, port)
                .await
                .map_err(|e| io::Error::other(format!("verify dial failed: {e}")))?;

            let (mut sender, conn) = hyper::client::conn::Builder::new()
                .handshake(stream)
                .await
                .map_err(|e| io::Error::other(format!("verify http1 handshake failed: {e}")))?;
            tokio::spawn(async move {
                if let Err(e) = conn.await {
                    tracing::debug!(service = "derp", error = %e, "verify_client_url http connection ended");
                }
            });

            let body = format!(r#"{{"publicKey":"{}"}}"#, key_hex);
            let req = HyperRequest::builder()
                .method(Method::POST)
                .uri(path)
                .header("Host", host)
                .header("Content-Type", "application/json")
                .body(Body::from(body))
                .map_err(|e| io::Error::other(format!("verify request build failed: {e}")))?;

            let resp = match timeout(VERIFY_TIMEOUT, sender.send_request(req)).await {
                Ok(Ok(r)) => r,
                Ok(Err(e)) => {
                    tracing::warn!(service = "derp", url = %url, error = %e, "Verify URL request failed");
                    continue;
                }
                Err(_) => {
                    tracing::warn!(service = "derp", url = %url, "Verify URL request timed out");
                    continue;
                }
            };

            if resp.status().is_success() {
                tracing::debug!(service = "derp", url = %url, key = %key_hex, "Client verified via URL");
                return Ok(true);
            }
            tracing::debug!(
                service = "derp",
                url = %url,
                status = %resp.status(),
                "Verify URL rejected client"
            );
        }

        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "All verify URLs rejected client",
        )
        .into())
    }

    fn parse_dial_timeout(v: &Option<String>) -> io::Result<Option<Duration>> {
        let Some(s) = v.as_deref() else {
            return Ok(None);
        };
        let s = s.trim();
        if s.is_empty() {
            return Ok(None);
        }
        humantime::parse_duration(s).map(Some).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("bad duration {s}: {e}"),
            )
        })
    }

    fn is_ip_literal(host: &str) -> bool {
        host.parse::<IpAddr>().is_ok()
    }

    fn build_derp_tls_config(
        opts: Option<&DerpOutboundTlsOptionsIR>,
    ) -> io::Result<Arc<ClientConfig>> {
        sb_tls::ensure_crypto_provider();

        let Some(opts) = opts else {
            return Ok(sb_tls::global::get_effective());
        };
        if !opts.enabled {
            return Ok(sb_tls::global::get_effective());
        }

        let mut roots = sb_tls::global::base_root_store();

        for path in &opts.ca_paths {
            let path = path.trim();
            if path.is_empty() {
                continue;
            }
            for cert in load_tls_certs(path)? {
                roots.add(cert).map_err(|e| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("Failed to add TLS root cert from {path}: {e}"),
                    )
                })?;
            }
        }

        for pem in &opts.ca_pem {
            let pem = pem.trim();
            if pem.is_empty() {
                continue;
            }
            let mut cursor = std::io::Cursor::new(pem.as_bytes());
            let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cursor)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| {
                    io::Error::new(io::ErrorKind::InvalidData, format!("bad ca_pem: {e}"))
                })?;
            for cert in certs {
                roots.add(cert).map_err(|e| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("Failed to add TLS root cert from ca_pem: {e}"),
                    )
                })?;
            }
        }

        let mut cfg = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();

        if let Some(alpn) = opts.alpn.as_ref() {
            cfg.alpn_protocols = alpn.iter().map(|s| s.as_bytes().to_vec()).collect();
        }

        if opts.insecure.unwrap_or(false) {
            let v = sb_tls::danger::NoVerify::new();
            cfg.dangerous()
                .set_certificate_verifier(std::sync::Arc::new(v));
        }

        Ok(Arc::new(cfg))
    }
}
