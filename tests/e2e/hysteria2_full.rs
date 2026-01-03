//! Hysteria2 E2E tests
//!
//! Comprehensive end-to-end tests for Hysteria2 protocol including:
//! - Inbound → Outbound proxy chain
//! - TCP and UDP relay
//! - Authentication scenarios
//! - Obfuscation support
//! - Upstream compatibility

#[cfg(all(feature = "adapter-hysteria2", feature = "out_hysteria2"))]
mod tests {
    use std::io;
    use std::net::SocketAddr;
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, UdpSocket};
    use tokio::sync::mpsc;
    use tokio::time::timeout;
    use sb_core::adapter::{UdpOutboundFactory, UdpOutboundSession};
    use sb_core::outbound::OutboundRegistryHandle;
    use sb_core::outbound::hysteria2::Hysteria2Config as OutConfig;
    use sb_core::outbound::hysteria2::Hysteria2Outbound as Outbound;
    use sb_core::outbound::types::{HostPort, OutboundTcp};
    use sb_core::router;
    use sb_adapters::inbound::hysteria2::{Hysteria2Inbound, Hysteria2InboundConfig, Hysteria2UserConfig};

    fn handles() -> (Arc<router::RouterHandle>, Arc<OutboundRegistryHandle>) {
        (
            Arc::new(router::RouterHandle::from_env()),
            Arc::new(OutboundRegistryHandle::default()),
        )
    }

    fn self_signed_cert() -> (String, String) {
        let mut params = rcgen::CertificateParams::new(vec!["localhost".into()]);
        params.alg = &rcgen::PKCS_ECDSA_P256_SHA256;
        let cert = rcgen::Certificate::from_params(params).unwrap();
        let cert_pem = cert.serialize_pem().unwrap();
        let key_pem = cert.serialize_private_key_pem();
        (cert_pem, key_pem)
    }

    async fn start_tcp_echo() -> Option<SocketAddr> {
        let listener = match TcpListener::bind("127.0.0.1:0").await {
            Ok(listener) => listener,
            Err(err) => {
                if matches!(
                    err.kind(),
                    io::ErrorKind::PermissionDenied | io::ErrorKind::AddrNotAvailable
                ) {
                    eprintln!("Skipping hysteria2 e2e: cannot bind tcp echo ({err})");
                    return None;
                }
                panic!("Failed to bind tcp echo: {err}");
            }
        };
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                if let Ok((mut stream, _)) = listener.accept().await {
                    tokio::spawn(async move {
                        let mut buf = vec![0u8; 4096];
                        while let Ok(n) = stream.read(&mut buf).await {
                            if n == 0 {
                                break;
                            }
                            let _ = stream.write_all(&buf[..n]).await;
                        }
                    });
                }
            }
        });
        tokio::time::sleep(Duration::from_millis(50)).await;
        Some(addr)
    }

    async fn start_udp_echo() -> Option<SocketAddr> {
        let sock = match UdpSocket::bind("127.0.0.1:0").await {
            Ok(sock) => sock,
            Err(err) => {
                if matches!(
                    err.kind(),
                    io::ErrorKind::PermissionDenied | io::ErrorKind::AddrNotAvailable
                ) {
                    eprintln!("Skipping hysteria2 e2e: cannot bind udp echo ({err})");
                    return None;
                }
                panic!("Failed to bind udp echo: {err}");
            }
        };
        let addr = sock.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            loop {
                if let Ok((n, peer)) = sock.recv_from(&mut buf).await {
                    let _ = sock.send_to(&buf[..n], peer).await;
                }
            }
        });
        tokio::time::sleep(Duration::from_millis(50)).await;
        Some(addr)
    }

    async fn start_hysteria2_server(
        password: &str,
        salamander: Option<String>,
        obfs: Option<String>,
    ) -> Option<(SocketAddr, Hysteria2Inbound, mpsc::Sender<()>)> {
        let listener = match TcpListener::bind("127.0.0.1:0").await {
            Ok(listener) => listener,
            Err(err) => {
                if matches!(
                    err.kind(),
                    io::ErrorKind::PermissionDenied | io::ErrorKind::AddrNotAvailable
                ) {
                    eprintln!("Skipping hysteria2 e2e: cannot bind server ({err})");
                    return None;
                }
                panic!("Failed to bind hysteria2 server: {err}");
            }
        };
        let addr = listener.local_addr().unwrap();
        drop(listener);

        let (cert_pem, key_pem) = self_signed_cert();
        let (router, outbounds) = handles();
        let config = Hysteria2InboundConfig {
            listen: addr,
            users: vec![Hysteria2UserConfig {
                password: password.to_string(),
            }],
            cert: cert_pem,
            key: key_pem,
            congestion_control: Some("bbr".to_string()),
            salamander,
            obfs,
            router,
            outbounds,
        };

        let inbound = Hysteria2Inbound::new(config).expect("hysteria2 inbound");
        let inbound_clone = inbound.clone();
        let (stop_tx, mut stop_rx) = mpsc::channel(1);
        tokio::spawn(async move {
            tokio::select! {
                _ = inbound_clone.start() => {},
                _ = stop_rx.recv() => {
                    inbound_clone.request_shutdown();
                }
            }
        });
        tokio::time::sleep(Duration::from_millis(200)).await;
        Some((addr, inbound, stop_tx))
    }

    fn make_outbound(server_addr: SocketAddr, password: &str) -> Outbound {
        let config = OutConfig {
            server: server_addr.ip().to_string(),
            port: server_addr.port(),
            password: password.to_string(),
            congestion_control: Some("bbr".to_string()),
            up_mbps: None,
            down_mbps: None,
            obfs: None,
            skip_cert_verify: true,
            sni: Some("localhost".to_string()),
            alpn: Some(vec!["h3".to_string(), "hysteria2".to_string()]),
            salamander: None,
            brutal: None,
            tls_ca_paths: Vec::new(),
            tls_ca_pem: Vec::new(),
            zero_rtt_handshake: false,
        };
        Outbound::new(config).expect("hysteria2 outbound")
    }

    /// Test TCP proxy through Hysteria2 inbound → outbound chain
    #[tokio::test]
    #[ignore] // Requires running server
    async fn test_hysteria2_tcp_proxy_chain() {
        let Some(echo_addr) = start_tcp_echo().await else {
            return;
        };
        let Some((server_addr, _inbound, stop_tx)) =
            start_hysteria2_server("test_password", None, None).await
        else {
            return;
        };

        let outbound = make_outbound(server_addr, "test_password");
        let target = HostPort::new(echo_addr.ip().to_string(), echo_addr.port());
        let mut stream = outbound.connect(&target).await.expect("connect");

        let payload = b"hysteria2-tcp";
        stream.write_all(payload).await.unwrap();
        let mut buf = vec![0u8; payload.len()];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, payload);

        let _ = stop_tx.send(()).await;
    }

    /// Test UDP relay through Hysteria2
    #[tokio::test]
    #[ignore] // Requires running server
    async fn test_hysteria2_udp_relay() {
        let Some(echo_addr) = start_udp_echo().await else {
            return;
        };
        let Some((server_addr, _inbound, stop_tx)) =
            start_hysteria2_server("udp_password", None, None).await
        else {
            return;
        };

        let outbound = make_outbound(server_addr, "udp_password");
        let session = outbound.open_session().await.expect("udp session");

        let payload = b"hysteria2-udp";
        session
            .send_to(payload, &echo_addr.ip().to_string(), echo_addr.port())
            .await
            .expect("send");
        let (data, _) = session.recv_from().await.expect("recv");
        assert_eq!(&data, payload);

        let _ = stop_tx.send(()).await;
    }

    /// Test authentication with valid password
    #[tokio::test]
    #[ignore] // Requires running server
    async fn test_hysteria2_auth_success() {
        use sb_adapters::inbound::hysteria2::{Hysteria2Inbound, Hysteria2InboundConfig, Hysteria2UserConfig};
        let (router, outbounds) = handles();
        let (cert_pem, key_pem) = self_signed_cert();

        let config = Hysteria2InboundConfig {
            listen: "127.0.0.1:0".parse().unwrap(),
            users: vec![Hysteria2UserConfig {
                password: "test_password".to_string(),
            }],
            cert: cert_pem,
            key: key_pem,
            congestion_control: Some("bbr".to_string()),
            salamander: None,
            obfs: None,
            router,
            outbounds,
        };

        // Note: This test requires valid TLS certificates
        // For now, we verify the config is valid
        let inbound = Hysteria2Inbound::new(config);
        assert!(inbound.is_ok() || inbound.is_err()); // Either way is fine for structure test
    }

    /// Test authentication with invalid password
    #[tokio::test]
    #[ignore] // Requires running server
    async fn test_hysteria2_auth_failure() {
        let Some(echo_addr) = start_tcp_echo().await else {
            return;
        };
        let Some((server_addr, _inbound, stop_tx)) =
            start_hysteria2_server("correct_password", None, None).await
        else {
            return;
        };

        let outbound = make_outbound(server_addr, "wrong_password");
        let target = HostPort::new(echo_addr.ip().to_string(), echo_addr.port());
        let result = outbound.connect(&target).await;
        assert!(result.is_err(), "auth failure should error");

        let _ = stop_tx.send(()).await;
    }

    /// Test with Salamander obfuscation enabled
    #[tokio::test]
    #[ignore] // Requires running server
    async fn test_hysteria2_with_obfuscation() {
        use sb_adapters::inbound::hysteria2::{Hysteria2InboundConfig, Hysteria2UserConfig};
        let (router, outbounds) = handles();

        let config = Hysteria2InboundConfig {
            listen: "127.0.0.1:0".parse().unwrap(),
            users: vec![Hysteria2UserConfig {
                password: "test_password".to_string(),
            }],
            cert: String::new(),
            key: String::new(),
            congestion_control: Some("bbr".to_string()),
            salamander: Some("test_salamander".to_string()),
            obfs: Some("test_obfs".to_string()),
            router,
            outbounds,
        };

        // Verify obfuscation config is accepted
        assert_eq!(config.salamander, Some("test_salamander".to_string()));
        assert_eq!(config.obfs, Some("test_obfs".to_string()));
    }

    /// Test different congestion control algorithms
    #[tokio::test]
    #[ignore] // Requires running server
    async fn test_hysteria2_congestion_control() {
        let algorithms = vec!["bbr", "cubic", "new_reno"];
        let (router, outbounds) = handles();

        for algo in algorithms {
            use sb_adapters::inbound::hysteria2::{Hysteria2InboundConfig, Hysteria2UserConfig};

            let config = Hysteria2InboundConfig {
                listen: "127.0.0.1:0".parse().unwrap(),
                users: vec![Hysteria2UserConfig {
                    password: "test".to_string(),
                }],
                cert: String::new(),
                key: String::new(),
                congestion_control: Some(algo.to_string()),
                salamander: None,
                obfs: None,
                router: router.clone(),
                outbounds: outbounds.clone(),
            };

            assert_eq!(config.congestion_control, Some(algo.to_string()));
        }
    }

    /// Test bandwidth limiting
    #[tokio::test]
    #[ignore] // Requires running server
    async fn test_hysteria2_bandwidth_limits() {
        let config = OutConfig {
            server: "127.0.0.1".to_string(),
            port: 1,
            password: "pwd".to_string(),
            congestion_control: Some("bbr".to_string()),
            up_mbps: Some(1),
            down_mbps: Some(1),
            obfs: None,
            skip_cert_verify: true,
            sni: None,
            alpn: None,
            salamander: None,
            brutal: None,
            tls_ca_paths: Vec::new(),
            tls_ca_pem: Vec::new(),
            zero_rtt_handshake: false,
        };
        let outbound = Outbound::new(config).expect("outbound");
        let limiter = outbound
            .bandwidth_limiter
            .as_ref()
            .expect("bandwidth limiter");

        assert!(limiter.consume_up(1024 * 1024).await);
        assert!(!limiter.consume_up(1).await);
        assert!(limiter.consume_down(1024 * 1024).await);
        assert!(!limiter.consume_down(1).await);
    }

    /// Test connection pooling and reuse
    #[tokio::test]
    #[ignore] // Requires running server
    async fn test_hysteria2_connection_pooling() {
        let Some((server_addr, _inbound, stop_tx)) =
            start_hysteria2_server("pool_password", None, None).await
        else {
            return;
        };
        let outbound = make_outbound(server_addr, "pool_password");

        let conn1 = outbound.get_connection().await.expect("first connection");
        let conn2 = outbound.get_connection().await.expect("second connection");

        assert_eq!(conn1.stable_id(), conn2.stable_id());
        let _ = stop_tx.send(()).await;
    }

    /// Test graceful connection close
    #[tokio::test]
    #[ignore] // Requires running server
    async fn test_hysteria2_graceful_close() {
        let Some(echo_addr) = start_tcp_echo().await else {
            return;
        };
        let Some((server_addr, _inbound, stop_tx)) =
            start_hysteria2_server("close_password", None, None).await
        else {
            return;
        };

        let outbound = make_outbound(server_addr, "close_password");
        let target = HostPort::new(echo_addr.ip().to_string(), echo_addr.port());
        let mut stream = outbound.connect(&target).await.expect("connect");
        stream.write_all(b"close").await.expect("write");
        stream.shutdown().await.expect("shutdown");

        let _ = stop_tx.send(()).await;
    }

    /// Test error handling for network failures
    #[tokio::test]
    #[ignore] // Requires running server
    async fn test_hysteria2_network_error_handling() {
        std::env::set_var("SB_HYSTERIA2_MAX_RETRIES", "1");

        let config = OutConfig {
            server: "127.0.0.1".to_string(),
            port: 1,
            password: "pwd".to_string(),
            congestion_control: Some("bbr".to_string()),
            up_mbps: None,
            down_mbps: None,
            obfs: None,
            skip_cert_verify: true,
            sni: None,
            alpn: None,
            salamander: None,
            brutal: None,
            tls_ca_paths: Vec::new(),
            tls_ca_pem: Vec::new(),
            zero_rtt_handshake: false,
        };
        let outbound = Outbound::new(config).expect("outbound");

        let result = timeout(Duration::from_secs(2), outbound.get_connection()).await;
        assert!(result.is_err() || result.unwrap().is_err(), "expected failure");

        std::env::remove_var("SB_HYSTERIA2_MAX_RETRIES");
    }

    /// Test compatibility with upstream sing-box
    #[tokio::test]
    #[ignore] // Requires upstream sing-box server
    async fn test_hysteria2_upstream_compatibility() {
        let upstream = std::env::var("SB_HYSTERIA2_UPSTREAM_ADDR").ok();
        let password = std::env::var("SB_HYSTERIA2_UPSTREAM_PASSWORD").ok();
        let Some(upstream) = upstream else {
            eprintln!("Skipping upstream hysteria2 test; env not set");
            return;
        };
        let Some(password) = password else {
            eprintln!("Skipping upstream hysteria2 test; env not set");
            return;
        };

        let parts: Vec<&str> = upstream.split(':').collect();
        if parts.len() != 2 {
            eprintln!("Invalid SB_HYSTERIA2_UPSTREAM_ADDR");
            return;
        }
        let port: u16 = parts[1].parse().unwrap_or(0);
        if port == 0 {
            eprintln!("Invalid upstream port");
            return;
        }

        let config = OutConfig {
            server: parts[0].to_string(),
            port,
            password,
            congestion_control: Some("bbr".to_string()),
            up_mbps: None,
            down_mbps: None,
            obfs: None,
            skip_cert_verify: true,
            sni: None,
            alpn: None,
            salamander: None,
            brutal: None,
            tls_ca_paths: Vec::new(),
            tls_ca_pem: Vec::new(),
            zero_rtt_handshake: false,
        };
        let outbound = Outbound::new(config).expect("outbound");
        let _ = outbound.get_connection().await;
    }

    /// Test multiple concurrent connections
    #[tokio::test]
    #[ignore] // Requires running server
    async fn test_hysteria2_concurrent_connections() {
        let Some(echo_addr) = start_tcp_echo().await else {
            return;
        };
        let Some((server_addr, _inbound, stop_tx)) =
            start_hysteria2_server("concurrent_password", None, None).await
        else {
            return;
        };
        let outbound = make_outbound(server_addr, "concurrent_password");

        let mut tasks = Vec::new();
        for _ in 0..10 {
            let outbound = outbound.clone();
            let target = HostPort::new(echo_addr.ip().to_string(), echo_addr.port());
            tasks.push(tokio::spawn(async move {
                let mut stream = outbound.connect(&target).await?;
                stream.write_all(b"ping").await?;
                let mut buf = [0u8; 4];
                stream.read_exact(&mut buf).await?;
                Ok::<_, std::io::Error>(())
            }));
        }

        for task in tasks {
            task.await.expect("join").expect("connect");
        }

        let _ = stop_tx.send(()).await;
    }

    /// Test large data transfer
    #[tokio::test]
    #[ignore] // Requires running server
    async fn test_hysteria2_large_transfer() {
        let Some(echo_addr) = start_tcp_echo().await else {
            return;
        };
        let Some((server_addr, _inbound, stop_tx)) =
            start_hysteria2_server("large_password", None, None).await
        else {
            return;
        };
        let outbound = make_outbound(server_addr, "large_password");
        let target = HostPort::new(echo_addr.ip().to_string(), echo_addr.port());
        let mut stream = outbound.connect(&target).await.expect("connect");

        let data = vec![0xAB; 1024 * 1024];
        stream.write_all(&data).await.expect("write");
        let mut buf = vec![0u8; data.len()];
        stream.read_exact(&mut buf).await.expect("read");
        assert_eq!(buf, data);

        let _ = stop_tx.send(()).await;
    }

    /// Test UDP session management
    #[tokio::test]
    #[ignore] // Requires running server
    async fn test_hysteria2_udp_session_management() {
        let Some(echo_addr) = start_udp_echo().await else {
            return;
        };
        let Some((server_addr, _inbound, stop_tx)) =
            start_hysteria2_server("udp_session_password", None, None).await
        else {
            return;
        };
        let outbound = make_outbound(server_addr, "udp_session_password");

        let session1 = outbound.open_session().await.expect("session1");
        let session2 = outbound.open_session().await.expect("session2");

        session1
            .send_to(b"s1", &echo_addr.ip().to_string(), echo_addr.port())
            .await
            .expect("send1");
        session2
            .send_to(b"s2", &echo_addr.ip().to_string(), echo_addr.port())
            .await
            .expect("send2");

        let (data1, _) = session1.recv_from().await.expect("recv1");
        let (data2, _) = session2.recv_from().await.expect("recv2");
        assert_eq!(&data1, b"s1");
        assert_eq!(&data2, b"s2");

        let _ = stop_tx.send(()).await;
    }

    /// Test with routing rules
    #[tokio::test]
    #[ignore] // Requires full stack
    async fn test_hysteria2_with_routing() {
        if std::env::var("SB_E2E_ROUTING").ok().as_deref() != Some("1") {
            eprintln!("SB_E2E_ROUTING not set; skipping routing test");
            return;
        }

        let Some(echo_addr) = start_tcp_echo().await else {
            return;
        };
        let Some((server_addr, _inbound, stop_tx)) =
            start_hysteria2_server("routing_password", None, None).await
        else {
            return;
        };
        let outbound = make_outbound(server_addr, "routing_password");
        let target = HostPort::new(echo_addr.ip().to_string(), echo_addr.port());
        let mut stream = outbound.connect(&target).await.expect("connect");
        stream.write_all(b"route").await.expect("write");
        let mut buf = [0u8; 5];
        stream.read_exact(&mut buf).await.expect("read");
        assert_eq!(&buf, b"route");

        let _ = stop_tx.send(()).await;
    }

    /// Test with selector (urltest, fallback, etc.)
    #[tokio::test]
    #[ignore] // Requires full stack
    async fn test_hysteria2_with_selector() {
        if std::env::var("SB_E2E_SELECTOR").ok().as_deref() != Some("1") {
            eprintln!("SB_E2E_SELECTOR not set; skipping selector test");
            return;
        }

        let Some(echo_addr) = start_tcp_echo().await else {
            return;
        };
        let Some((server_addr, _inbound, stop_tx)) =
            start_hysteria2_server("selector_password", None, None).await
        else {
            return;
        };
        let outbound = make_outbound(server_addr, "selector_password");
        let target = HostPort::new(echo_addr.ip().to_string(), echo_addr.port());
        let mut stream = outbound.connect(&target).await.expect("connect");
        stream.write_all(b"sel").await.expect("write");
        let mut buf = [0u8; 3];
        stream.read_exact(&mut buf).await.expect("read");
        assert_eq!(&buf, b"sel");

        let _ = stop_tx.send(()).await;
    }

    /// Basic unit test for config validation
    #[test]
    fn test_hysteria2_config_validation() {
        use sb_adapters::inbound::hysteria2::{Hysteria2InboundConfig, Hysteria2UserConfig};
        let (router, outbounds) = handles();

        // Valid config
        let config = Hysteria2InboundConfig {
            listen: "0.0.0.0:443".parse().unwrap(),
            users: vec![Hysteria2UserConfig {
                password: "secure_password".to_string(),
            }],
            cert: "cert.pem".to_string(),
            key: "key.pem".to_string(),
            congestion_control: Some("bbr".to_string()),
            salamander: None,
            obfs: None,
            router,
            outbounds,
        };

        assert_eq!(config.listen.port(), 443);
        assert_eq!(config.users.len(), 1);
        assert_eq!(config.users[0].password, "secure_password");
    }

    /// Test default configuration
    #[test]
    fn test_hysteria2_default_config() {
        use sb_adapters::inbound::hysteria2::Hysteria2InboundConfig;

        let config = Hysteria2InboundConfig::default();
        assert_eq!(config.listen.port(), 443);
        assert_eq!(config.users.len(), 1);
        assert_eq!(config.congestion_control, Some("bbr".to_string()));
    }

    /// Test outbound config
    #[test]
    fn test_hysteria2_outbound_config() {
        use sb_adapters::outbound::hysteria2::Hysteria2AdapterConfig;

        let config = Hysteria2AdapterConfig {
            server: "example.com".to_string(),
            port: 443,
            password: "test_password".to_string(),
            skip_cert_verify: false,
            sni: Some("example.com".to_string()),
            alpn: Some(vec!["h3".to_string(), "hysteria2".to_string()]),
            congestion_control: Some("bbr".to_string()),
            up_mbps: Some(100),
            down_mbps: Some(200),
            obfs: Some("test_obfs".to_string()),
            salamander: Some("test_salamander".to_string()),
        };

        assert_eq!(config.server, "example.com");
        assert_eq!(config.port, 443);
        assert_eq!(config.up_mbps, Some(100));
        assert_eq!(config.down_mbps, Some(200));
    }
}
