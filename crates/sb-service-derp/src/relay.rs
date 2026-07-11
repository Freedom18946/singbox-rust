impl DerpService {
    #[allow(clippy::too_many_arguments)]
    async fn handle_derp_client<S>(
        stream: S,
        peer: SocketAddr,
        tag: Arc<str>,
        client_registry: Arc<ClientRegistry>,
        server_private_key: PrivateKey,
        server_public_key: PublicKey,
        is_mesh_peer: bool,
        runtime: DerpRuntimeCtx,
        verify_client_urls: Arc<[DerpVerifyClientUrlCfg]>,
        verify_client_endpoints: Arc<parking_lot::RwLock<Vec<String>>>,
        server_mesh_key: Option<String>,
    ) -> io::Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        tracing::info!(service = "derp", tag = %tag, peer = %peer, "DERP client connected");

        let (mut read_half, mut write_half) = tokio::io::split(stream);

        // Send ServerKey frame (public key, Go-compatible)
        let server_key_frame = DerpFrame::ServerKey {
            key: server_public_key,
        };
        server_key_frame
            .write_to_async(&mut write_half)
            .await
            .map_err(|e| io::Error::other(format!("Failed to send ServerKey: {}", e)))?;

        // Read ClientInfo frame (or legacy ServerKey if mesh peer).
        let (client_key, client_info, is_mesh_peer) = match DerpFrame::read_from_async(
            &mut read_half,
        )
        .await
        {
            Ok(DerpFrame::ClientInfo {
                key,
                encrypted_info,
            }) => {
                // Go server rejects overly large client info early to avoid JSON resource exhaustion.
                // Ref: `derp_server.go recvClientKey` (fl > 256<<10).
                if encrypted_info.len().saturating_add(32) > 256 << 10 {
                    client_registry.metrics().connect_failed("handshake");
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "long client info",
                    ));
                }
                if encrypted_info.len() < NONCE_LEN {
                    client_registry.metrics().connect_failed("handshake");
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "short client info",
                    ));
                }

                let msg = open_from(&server_private_key, &key, &encrypted_info).map_err(|e| {
                    io::Error::new(io::ErrorKind::InvalidData, format!("msgbox: {e}"))
                })?;
                let payload = ClientInfoPayload::from_json(&msg)
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("msg: {e}")))?;

                let mut detected_mesh_peer = is_mesh_peer;
                if !detected_mesh_peer {
                    if let Some(server_mk) = server_mesh_key.as_deref() {
                        if payload.mesh_key.as_deref() == Some(server_mk) {
                            tracing::info!(
                                service = "derp",
                                peer = %peer,
                                "Client authenticated as mesh peer via meshKey"
                            );
                            detected_mesh_peer = true;
                        }
                    }
                }
                (key, Some(payload), detected_mesh_peer)
            }
            Ok(DerpFrame::ServerKey { key }) if is_mesh_peer => (key, None, true),
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

        tracing::info!(
            service = "derp",
            peer = %peer,
            client_key = ?client_key,
            is_mesh_peer,
            "Client registered"
        );

        if !is_mesh_peer {
            match Self::verify_client_via_urls(&runtime, verify_client_urls.as_ref(), &client_key)
                .await
            {
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
            let sockets = verify_client_endpoints.read().clone();
            match Self::verify_client_via_endpoints(&sockets, &client_key).await {
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

        if client_info.is_some() {
            let info = ServerInfoPayload::new(PROTOCOL_VERSION as u32);
            let msgbox = seal_to(&server_private_key, &client_key, &info.to_json())
                .map_err(|e| io::Error::other(format!("send server info: {e}")))?;
            DerpFrame::ServerInfo {
                encrypted_info: msgbox,
            }
            .write_to_async(&mut write_half)
            .await
            .map_err(|e| io::Error::other(format!("Failed to send ServerInfo: {e}")))?;
        }

        // Go derp server only sends peer presence updates to mesh watchers (WatchConns).
        if !is_mesh_peer {
            client_registry.broadcast_peer_present_to_mesh_watchers(
                &client_key,
                Some(peer),
                sb_transport::derp::protocol::peer_present_flags::IS_REGULAR,
            );
        }

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
                DerpFrame::PeerPresent { key: _key, .. } => {
                    // PeerPresent is sent *to* mesh peers (WatchConns). Ignore incoming.
                }
                DerpFrame::PeerGone { key: _key, .. } => {
                    // PeerGone is sent *to* mesh peers (WatchConns). Ignore incoming.
                }
                DerpFrame::WatchConns => {
                    if is_mesh_peer {
                        if let Err(e) = client_registry.register_mesh_watcher(client_key) {
                            tracing::warn!(
                                service = "derp",
                                peer = %peer,
                                key = ?client_key,
                                error = %e,
                                "Failed to register mesh watcher"
                            );
                            continue;
                        }
                        if let Err(e) =
                            client_registry.send_existing_clients_to_mesh_watcher(&client_key)
                        {
                            tracing::warn!(
                                service = "derp",
                                peer = %peer,
                                key = ?client_key,
                                error = %e,
                                "Failed to send existing clients to mesh watcher"
                            );
                        }
                    } else {
                        tracing::warn!(service = "derp", peer = %peer, client = ?client_key, "Received WatchConns from non-mesh peer");
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
            client_registry.broadcast_peer_gone_to_mesh_watchers(
                &client_key,
                sb_transport::derp::protocol::PeerGoneReason::Disconnected,
            );
        }

        // Cancel write task
        write_task.abort();

        tracing::info!(service = "derp", peer = %peer, client = ?client_key, "Client disconnected");
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    async fn run_mesh_client(
        peer: DerpMeshPeerCfg,
        psk: String,
        _tag: Arc<str>,
        runtime: DerpRuntimeCtx,
        client_registry: Arc<ClientRegistry>,
        server_private_key: PrivateKey,
        server_public_key: PublicKey,
        shutdown: Arc<Notify>,
    ) {
        fn format_host_port(host: &str, port: u16) -> String {
            if host.contains(':') && !host.starts_with('[') {
                format!("[{host}]:{port}")
            } else {
                format!("{host}:{port}")
            }
        }

        let peer_addr_str = format_host_port(&peer.server, peer.port);
        let hostname = peer.host.clone().unwrap_or_else(|| peer.server.clone());
        let host_header = if peer.port == 0 || peer.port == 443 {
            hostname.clone()
        } else {
            format_host_port(&hostname, peer.port)
        };
        let tls_enabled = peer.tls.as_ref().is_some_and(|t| t.enabled);
        let sni_override = peer
            .tls
            .as_ref()
            .and_then(|t| t.server_name.as_deref())
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
            .unwrap_or_else(|| hostname.clone());

        loop {
            if shutdown.notified().now_or_never().is_some() {
                break;
            }

            tracing::info!(service = "derp", peer = %peer_addr_str, "Connecting to mesh peer");

            let tls = if tls_enabled {
                match Self::build_derp_tls_config(peer.tls.as_ref()) {
                    Ok(cfg) => Some(cfg),
                    Err(e) => {
                        tracing::error!(service = "derp", peer = %peer_addr_str, error = %e, "Failed to build mesh TLS config");
                        tokio::time::sleep(Duration::from_secs(5)).await;
                        continue;
                    }
                }
            } else {
                None
            };

            let dialer = match Self::build_derp_dialer(
                &runtime,
                &peer.dial,
                tls,
                Some(&sni_override),
            ) {
                Ok(d) => d,
                Err(e) => {
                    tracing::error!(service = "derp", peer = %peer_addr_str, error = %e, "Failed to build mesh dialer");
                    tokio::time::sleep(Duration::from_secs(5)).await;
                    continue;
                }
            };

            let mut stream = match dialer.connect(&peer.server, peer.port).await {
                Ok(s) => s,
                Err(e) => {
                    tracing::error!(service = "derp", peer = %peer_addr_str, error = %e, "Failed to connect to mesh peer");
                    tokio::time::sleep(Duration::from_secs(5)).await;
                    continue;
                }
            };

            // Send HTTP upgrade request (Go mesh model uses /derp; mesh auth happens in ClientInfo.meshKey).
            let req = format!(
                "GET /derp HTTP/1.1\r\n\
		                         Host: {}\r\n\
		                         Connection: Upgrade\r\n\
		                         Upgrade: derp\r\n\
		                         \r\n",
                host_header
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
            let mut prefix: Vec<u8> = Vec::new();

            loop {
                match stream.read(&mut buf[filled..]).await {
                    Ok(n) if n > 0 => {
                        filled += n;
                        let response = String::from_utf8_lossy(&buf[..filled]);
                        if let Some(idx) = response.find("\r\n\r\n") {
                            if response.contains("101 Switching Protocols") {
                                tracing::info!(service = "derp", peer = %peer_addr_str, "Mesh handshake successful");
                                prefix = buf[idx + 4..filled].to_vec();
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

            if handshake_done {
                let mut derp = PrefixedStream::new(stream, prefix);

                // DERP v2 client handshake: read ServerKey, send ClientInfo with meshKey.
                let server_key_frame = match DerpFrame::read_from_async(&mut derp).await {
                    Ok(f) => f,
                    Err(e) => {
                        tracing::error!(
                            service = "derp",
                            peer = %peer_addr_str,
                            error = %e,
                            "Failed to read ServerKey from mesh peer"
                        );
                        tokio::time::sleep(Duration::from_secs(5)).await;
                        continue;
                    }
                };
                let peer_public_key = match server_key_frame {
                    DerpFrame::ServerKey { key } => key,
                    other => {
                        tracing::warn!(
                            service = "derp",
                            peer = %peer_addr_str,
                            frame = ?other.frame_type(),
                            "Expected ServerKey from mesh peer"
                        );
                        tokio::time::sleep(Duration::from_secs(5)).await;
                        continue;
                    }
                };

                if peer_public_key == server_public_key {
                    tracing::warn!(
                        service = "derp",
                        peer = %peer_addr_str,
                        "Detected self-connect mesh peer (same public key); ignoring"
                    );
                    tokio::time::sleep(Duration::from_secs(30)).await;
                    continue;
                }

                let payload = ClientInfoPayload::new(PROTOCOL_VERSION as u32)
                    .with_mesh_key(psk.clone())
                    .with_can_ack_pings(true);
                let msgbox =
                    match seal_to(&server_private_key, &peer_public_key, &payload.to_json()) {
                        Ok(m) => m,
                        Err(e) => {
                            tracing::error!(
                                service = "derp",
                                peer = %peer_addr_str,
                                error = %e,
                                "Failed to seal mesh ClientInfo"
                            );
                            tokio::time::sleep(Duration::from_secs(5)).await;
                            continue;
                        }
                    };

                if let Err(e) = (DerpFrame::ClientInfo {
                    key: server_public_key,
                    encrypted_info: msgbox,
                })
                .write_to_async(&mut derp)
                .await
                {
                    tracing::error!(
                        service = "derp",
                        peer = %peer_addr_str,
                        error = %e,
                        "Failed to send mesh ClientInfo"
                    );
                    tokio::time::sleep(Duration::from_secs(5)).await;
                    continue;
                }
                if let Err(e) = derp.flush().await {
                    tracing::error!(
                        service = "derp",
                        peer = %peer_addr_str,
                        error = %e,
                        "Failed to flush mesh ClientInfo"
                    );
                    tokio::time::sleep(Duration::from_secs(5)).await;
                    continue;
                }

                // Read ServerInfo (encrypted) and sanity-check version.
                match DerpFrame::read_from_async(&mut derp).await {
                    Ok(DerpFrame::ServerInfo { encrypted_info }) => {
                        if let Ok(clear) =
                            open_from(&server_private_key, &peer_public_key, &encrypted_info)
                        {
                            let clear = String::from_utf8_lossy(&clear);
                            if !clear.contains(&format!("\"version\":{}", PROTOCOL_VERSION)) {
                                tracing::warn!(
                                    service = "derp",
                                    peer = %peer_addr_str,
                                    payload = %clear,
                                    "Unexpected ServerInfo payload from mesh peer"
                                );
                            }
                        }
                    }
                    Ok(other) => {
                        tracing::warn!(
                            service = "derp",
                            peer = %peer_addr_str,
                            frame = ?other.frame_type(),
                            "Expected ServerInfo after ClientInfo"
                        );
                    }
                    Err(e) => {
                        tracing::warn!(
                            service = "derp",
                            peer = %peer_addr_str,
                            error = %e,
                            "Failed to read ServerInfo from mesh peer"
                        );
                    }
                }

                // Subscribe to peer presence updates (Go `WatchConns`).
                if let Err(e) = DerpFrame::WatchConns.write_to_async(&mut derp).await {
                    tracing::error!(
                        service = "derp",
                        peer = %peer_addr_str,
                        error = %e,
                        "Failed to send WatchConns to mesh peer"
                    );
                    tokio::time::sleep(Duration::from_secs(5)).await;
                    continue;
                }
                let _ = derp.flush().await;

                // Create channel for sending frames to this mesh peer.
                let (tx, mut rx) = mpsc::unbounded_channel();
                let tx_for_read = tx.clone();
                if let Err(e) = client_registry.register_mesh_forwarder(peer_public_key, tx) {
                    tracing::error!(
                        service = "derp",
                        peer = %peer_addr_str,
                        key = ?peer_public_key,
                        error = %e,
                        "Failed to register outbound mesh peer"
                    );
                    tokio::time::sleep(Duration::from_secs(5)).await;
                    continue;
                }

                let (mut read_half, mut write_half) = tokio::io::split(derp);
                let write_task = tokio::spawn(async move {
                    while let Some(frame) = rx.recv().await {
                        if let Err(e) = frame.write_to_async(&mut write_half).await {
                            tracing::debug!(
                                service = "derp",
                                peer = ?peer_public_key,
                                error = %e,
                                "Failed to write frame to mesh peer"
                            );
                            break;
                        }
                    }
                });

                let peer_key_for_read = peer_public_key;

                // Read loop: process peer presence updates and forwarded packets.
                loop {
                    tokio::select! {
                        _ = shutdown.notified() => {
                            break;
                        }
                        frame = DerpFrame::read_from_async(&mut read_half) => {
                            let frame = match frame {
                                Ok(f) => f,
                                Err(e) => {
                                    tracing::debug!(service = "derp", peer = %peer_addr_str, error = %e, "Mesh peer connection closed");
                                    break;
                                }
                            };

                            match frame {
                                DerpFrame::PeerPresent { key, .. } => {
                                    client_registry.register_remote_client(key, peer_key_for_read);
                                }
                                DerpFrame::PeerGone { key, .. } => {
                                    client_registry.unregister_remote_client(&key);
                                }
                                DerpFrame::ForwardPacket {
                                    src_key,
                                    dst_key,
                                    packet,
                                } => {
                                    if let Err(e) = client_registry
                                        .handle_forward_packet(&src_key, &dst_key, packet)
                                    {
                                        tracing::debug!(service = "derp", peer = %peer_addr_str, error = %e, "Failed to handle forwarded packet from mesh peer");
                                    }
                                }
                                DerpFrame::Ping { data } => {
                                    let _ = tx_for_read.send(DerpFrame::Pong { data });
                                }
                                DerpFrame::KeepAlive => {}
                                _ => {}
                            }
                        }
                    }
                }

                client_registry.unregister_mesh_forwarder(&peer_key_for_read);
                write_task.abort();
            } else {
                tokio::time::sleep(Duration::from_secs(1)).await;
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

    #[cfg(test)]
    pub(crate) fn has_remote_client(&self, key: &PublicKey) -> bool {
        self.client_registry.is_remote_registered(key)
    }
}
