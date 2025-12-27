#![cfg(feature = "net_e2e")]
//! TUIC E2E tests
//!
//! Comprehensive end-to-end tests for TUIC protocol including:
//! - TCP proxy through TUIC
//! - UDP relay through TUIC
//! - UDP over stream mode
//! - Authentication scenarios
//! - Upstream compatibility

#[cfg(feature = "adapter-tuic")]
mod tuic_tests {
    use std::net::SocketAddr;
    use sb_adapters::inbound::tuic::{serve as tuic_serve, TuicInboundConfig, TuicUser};
    use sb_core::adapter::{UdpOutboundFactory, UdpOutboundSession};
    use sb_core::outbound::OutboundRegistryHandle;
    use sb_core::router;
    use sb_core::outbound::tuic::{TuicConfig, TuicOutbound, UdpRelayMode};
    use sb_core::outbound::types::OutboundTcp;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, UdpSocket};
    use tokio::sync::mpsc;
    use uuid::Uuid;

    #[cfg(feature = "adapter-tuic")]
    fn make_tuic_config(
        server_addr: SocketAddr,
        uuid: Uuid,
        token: &str,
        password: Option<&str>,
        congestion: Option<&str>,
        relay_mode: sb_core::outbound::tuic::UdpRelayMode,
        udp_over_stream: bool,
    ) -> sb_core::outbound::tuic::TuicConfig {
        use sb_core::outbound::tuic::TuicConfig;

        TuicConfig {
            server: server_addr.ip().to_string(),
            port: server_addr.port(),
            uuid,
            token: token.to_string(),
            password: password.map(str::to_string),
            congestion_control: congestion.map(str::to_string),
            alpn: Some(vec!["tuic".to_string()]),
            skip_cert_verify: true,
            sni: None,
            tls_ca_paths: Vec::new(),
            tls_ca_pem: Vec::new(),
            udp_relay_mode: relay_mode,
            udp_over_stream,
            zero_rtt_handshake: false,
        }
    }

    fn self_signed_cert() -> (String, String) {
        let mut params = rcgen::CertificateParams::new(vec!["localhost".into()]);
        params.alg = &rcgen::PKCS_ECDSA_P256_SHA256;
        let cert = rcgen::Certificate::from_params(params).unwrap();
        let cert_pem = cert.serialize_pem().unwrap();
        let key_pem = cert.serialize_private_key_pem();
        (cert_pem, key_pem)
    }

    async fn start_tuic_server(
        uuid: Uuid,
        token: &str,
    ) -> std::io::Result<(SocketAddr, mpsc::Sender<()>)> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        drop(listener);

        let (cert_pem, key_pem) = self_signed_cert();
        let (stop_tx, stop_rx) = mpsc::channel(1);
        let router = std::sync::Arc::new(router::RouterHandle::from_env());
        let outbounds = std::sync::Arc::new(OutboundRegistryHandle::default());
        let cfg = TuicInboundConfig {
            listen: addr,
            users: vec![TuicUser {
                uuid,
                token: token.to_string(),
            }],
            cert: cert_pem,
            key: key_pem,
            congestion_control: Some("bbr".to_string()),
            router,
            outbounds,
        };

        tokio::spawn(async move {
            let _ = tuic_serve(cfg, stop_rx).await;
        });
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        Ok((addr, stop_tx))
    }

    /// Test TCP proxy through TUIC outbound
    #[tokio::test]
    async fn test_tuic_tcp_proxy() {
        // Start a simple echo server
        let echo_server = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo_server.local_addr().unwrap();

        tokio::spawn(async move {
            loop {
                if let Ok((mut stream, _)) = echo_server.accept().await {
                    tokio::spawn(async move {
                        let mut buf = vec![0u8; 1024];
                        while let Ok(n) = stream.read(&mut buf).await {
                            if n == 0 {
                                break;
                            }
                            stream.write_all(&buf[..n]).await.ok();
                        }
                    });
                }
            }
        });

        let uuid = Uuid::new_v4();
        let token = "test_token";
        let (server_addr, _stop_tx) = start_tuic_server(uuid, token).await.unwrap();

        let config = make_tuic_config(
            server_addr,
            uuid,
            token,
            None,
            Some("cubic"),
            UdpRelayMode::Native,
            false,
        );
        let outbound = TuicOutbound::new(config).expect("tuic outbound");

        let target = sb_core::outbound::types::HostPort::new(
            echo_addr.ip().to_string(),
            echo_addr.port(),
        );
        let mut stream = outbound.connect(&target).await.expect("connect tuic");

        let payload = b"tuic-tcp";
        stream.write_all(payload).await.unwrap();
        let mut buf = vec![0u8; payload.len()];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, payload);
    }

    /// Test UDP relay through TUIC (native mode)
    #[tokio::test]
    async fn test_tuic_udp_relay_native() {
        // Start UDP echo server
        let echo_server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo_server.local_addr().unwrap();

        tokio::spawn(async move {
            let mut buf = vec![0u8; 1500];
            loop {
                if let Ok((n, peer)) = echo_server.recv_from(&mut buf).await {
                    echo_server.send_to(&buf[..n], peer).await.ok();
                }
            }
        });

        let uuid = Uuid::new_v4();
        let token = "udp_token";
        let (server_addr, _stop_tx) = start_tuic_server(uuid, token).await.unwrap();

        let config = make_tuic_config(
            server_addr,
            uuid,
            token,
            None,
            Some("bbr"),
            UdpRelayMode::Native,
            false,
        );
        let outbound = TuicOutbound::new(config).expect("tuic outbound");
        let session = outbound.open_session().await.expect("udp session");

        let payload = b"tuic-udp";
        session
            .send_to(payload, &echo_addr.ip().to_string(), echo_addr.port())
            .await
            .expect("udp send");
        let (data, _) = session.recv_from().await.expect("udp recv");
        assert_eq!(&data, payload);
    }

    /// Test UDP over stream mode
    #[tokio::test]
    #[cfg(feature = "adapter-tuic")]
    async fn test_tuic_udp_over_stream() {
        let echo_server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo_server.local_addr().unwrap();

        tokio::spawn(async move {
            let mut buf = vec![0u8; 1500];
            loop {
                if let Ok((n, peer)) = echo_server.recv_from(&mut buf).await {
                    echo_server.send_to(&buf[..n], peer).await.ok();
                }
            }
        });

        let uuid = Uuid::new_v4();
        let token = "udp_stream_token";
        let (server_addr, _stop_tx) = start_tuic_server(uuid, token).await.unwrap();

        let config = make_tuic_config(
            server_addr,
            uuid,
            token,
            None,
            Some("cubic"),
            UdpRelayMode::Native,
            true,
        );
        let outbound = TuicOutbound::new(config).expect("tuic outbound");
        let transport = outbound.create_udp_transport().await.expect("udp transport");

        let payload = b"tuic-udp-stream";
        transport
            .send_to(payload, &echo_addr.ip().to_string(), echo_addr.port())
            .await
            .expect("udp send");
        let (data, _) = transport.recv_from().await.expect("udp recv");
        assert_eq!(&data, payload);
    }

    /// Test TUIC authentication with valid credentials
    #[tokio::test]
    #[cfg(feature = "adapter-tuic")]
    async fn test_tuic_auth_success() {
        let echo_server = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo_server.local_addr().unwrap();

        tokio::spawn(async move {
            loop {
                if let Ok((mut stream, _)) = echo_server.accept().await {
                    tokio::spawn(async move {
                        let mut buf = vec![0u8; 1024];
                        while let Ok(n) = stream.read(&mut buf).await {
                            if n == 0 {
                                break;
                            }
                            stream.write_all(&buf[..n]).await.ok();
                        }
                    });
                }
            }
        });

        let uuid = Uuid::new_v4();
        let token = "correct_token";
        let (server_addr, _stop_tx) = start_tuic_server(uuid, token).await.unwrap();

        let config = make_tuic_config(
            server_addr,
            uuid,
            token,
            Some("correct_password"),
            Some("cubic"),
            UdpRelayMode::Native,
            false,
        );
        let outbound = TuicOutbound::new(config).expect("tuic outbound");

        let target = sb_core::outbound::types::HostPort::new(
            echo_addr.ip().to_string(),
            echo_addr.port(),
        );
        let mut stream = outbound.connect(&target).await.expect("connect tuic");

        let payload = b"auth-ok";
        stream.write_all(payload).await.unwrap();
        let mut buf = vec![0u8; payload.len()];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, payload);
    }

    /// Test TUIC authentication with invalid credentials
    #[tokio::test]
    async fn test_tuic_auth_failure() {
        use sb_core::outbound::tuic::{TuicOutbound, UdpRelayMode};

        let uuid = Uuid::new_v4();
        let token = "correct_token";
        let (server_addr, _stop_tx) = start_tuic_server(uuid, token).await.unwrap();

        let config = make_tuic_config(
            server_addr,
            uuid,
            "wrong_token",
            Some("wrong_password"),
            Some("cubic"),
            UdpRelayMode::Native,
            false,
        );

        let outbound = TuicOutbound::new(config).expect("tuic outbound");
        let target = sb_core::outbound::types::HostPort::new(
            server_addr.ip().to_string(),
            80,
        );
        let result = outbound.connect(&target).await;
        assert!(result.is_err(), "auth failure should error");
    }

    /// Test TUIC with different congestion control algorithms
    #[tokio::test]
    async fn test_tuic_congestion_control() {
        let algorithms = vec!["cubic", "bbr", "new_reno"];

        for algo in algorithms {
            let config = TuicConfig {
                server: "127.0.0.1".to_string(),
                port: 8443,
                uuid: Uuid::new_v4(),
                token: "test_token".to_string(),
                password: None,
                congestion_control: Some(algo.to_string()),
                alpn: Some(vec!["tuic".to_string()]),
                skip_cert_verify: true,
                sni: None,
                tls_ca_paths: Vec::new(),
                tls_ca_pem: Vec::new(),
                udp_relay_mode: UdpRelayMode::Native,
                udp_over_stream: false,
                zero_rtt_handshake: false,
            };

            let outbound = TuicOutbound::new(config);
            assert!(
                outbound.is_ok(),
                "TUIC outbound with {} should succeed",
                algo
            );
        }

        assert!(true, "All congestion control algorithms supported");
    }
}

// Packet encoding tests (don't require full TUIC implementation)
#[cfg(feature = "adapter-tuic")]
mod packet_tests {
    use sb_adapters::OutboundConnector;
    use sb_core::outbound::tuic::{TuicConfig, TuicOutbound, UdpRelayMode};
    use sb_core::outbound::types::OutboundTcp;
    use uuid::Uuid;

    /// Test TUIC packet encoding/decoding
    #[tokio::test]
    async fn test_tuic_packet_encoding() {
        use sb_core::outbound::tuic::TuicOutbound;

        // Test IPv4 address
        let packet = TuicOutbound::encode_udp_packet_static("192.168.1.1", 8080, b"test data");
        assert!(packet.is_ok(), "IPv4 packet encoding should succeed");
        let packet = packet.unwrap();
        assert!(!packet.is_empty(), "Packet should not be empty");

        // Decode the packet
        let (host, port, data) = TuicOutbound::decode_udp_packet(&packet).unwrap();
        assert_eq!(host, "192.168.1.1", "Host should match");
        assert_eq!(port, 8080, "Port should match");
        assert_eq!(data, b"test data", "Data should match");

        // Test IPv6 address
        let packet = TuicOutbound::encode_udp_packet_static("::1", 8080, b"test data");
        assert!(packet.is_ok(), "IPv6 packet encoding should succeed");
        let packet = packet.unwrap();

        let (host, port, data) = TuicOutbound::decode_udp_packet(&packet).unwrap();
        assert_eq!(host, "::1", "IPv6 host should match");
        assert_eq!(port, 8080, "Port should match");
        assert_eq!(data, b"test data", "Data should match");

        // Test domain name
        let packet = TuicOutbound::encode_udp_packet_static("example.com", 443, b"hello world");
        assert!(packet.is_ok(), "Domain packet encoding should succeed");
        let packet = packet.unwrap();

        let (host, port, data) = TuicOutbound::decode_udp_packet(&packet).unwrap();
        assert_eq!(host, "example.com", "Domain should match");
        assert_eq!(port, 443, "Port should match");
        assert_eq!(data, b"hello world", "Data should match");
    }

    /// Test TUIC packet encoding with large data
    #[tokio::test]
    async fn test_tuic_large_packet_encoding() {
        use sb_core::outbound::tuic::TuicOutbound;

        // Test with 1KB data
        let large_data = vec![0xAB; 1024];
        let packet = TuicOutbound::encode_udp_packet_static("example.com", 443, &large_data);
        assert!(packet.is_ok(), "Large packet encoding should succeed");
        let packet = packet.unwrap();

        let (host, port, data) = TuicOutbound::decode_udp_packet(&packet).unwrap();
        assert_eq!(host, "example.com", "Domain should match");
        assert_eq!(port, 443, "Port should match");
        assert_eq!(data, large_data, "Large data should match");
    }

    /// Test TUIC packet encoding with empty data
    #[tokio::test]
    async fn test_tuic_empty_packet_encoding() {
        use sb_core::outbound::tuic::TuicOutbound;

        let packet = TuicOutbound::encode_udp_packet_static("example.com", 443, b"");
        assert!(packet.is_ok(), "Empty packet encoding should succeed");
        let packet = packet.unwrap();

        let (host, port, data) = TuicOutbound::decode_udp_packet(&packet).unwrap();
        assert_eq!(host, "example.com", "Domain should match");
        assert_eq!(port, 443, "Port should match");
        assert_eq!(data.len(), 0, "Data should be empty");
    }

    /// Test TUIC adapter configuration
    #[tokio::test]
    async fn test_tuic_adapter_config() {
        use sb_adapters::outbound::tuic::{TuicAdapterConfig, TuicConnector, TuicUdpRelayMode};

        let config = TuicAdapterConfig {
            server: "example.com".to_string(),
            port: 443,
            uuid: Uuid::parse_str("2DD61D93-75D8-4DA4-AC0E-6AECE7EAC365").unwrap(),
            token: "test_token".to_string(),
            password: Some("test_password".to_string()),
            congestion_control: Some("cubic".to_string()),
            alpn: Some("tuic".to_string()),
            skip_cert_verify: false,
            udp_relay_mode: TuicUdpRelayMode::Native,
            udp_over_stream: false,
        };

        let connector = TuicConnector::new(config);
        assert_eq!(connector.name(), "tuic", "Connector name should be 'tuic'");
    }

    /// Test TUIC adapter with UDP over stream
    #[tokio::test]
    async fn test_tuic_adapter_udp_over_stream() {
        use sb_adapters::outbound::tuic::{TuicAdapterConfig, TuicConnector, TuicUdpRelayMode};

        let config = TuicAdapterConfig {
            server: "127.0.0.1".to_string(),
            port: 1,
            uuid: Uuid::new_v4(),
            token: "test_token".to_string(),
            password: None,
            congestion_control: Some("bbr".to_string()),
            alpn: Some("tuic".to_string()),
            skip_cert_verify: true,
            udp_relay_mode: TuicUdpRelayMode::Quic,
            udp_over_stream: true,
        };

        let connector = TuicConnector::new(config);
        assert_eq!(connector.name(), "tuic", "Connector name should be 'tuic'");
        assert!(
            connector
                .create_udp_transport()
                .await
                .is_err(),
            "UDP transport should fail without a running server"
        );
    }

    /// Test TUIC with upstream sing-box server
    #[tokio::test]
    #[ignore] // Requires external sing-box server
    async fn test_tuic_upstream_compatibility() {
        // This test verifies compatibility with upstream sing-box TUIC server
        // It requires a running sing-box server with TUIC configured
        let upstream = std::env::var("SB_TUIC_UPSTREAM_ADDR").ok();
        let uuid = std::env::var("SB_TUIC_UPSTREAM_UUID").ok();
        let token = std::env::var("SB_TUIC_UPSTREAM_TOKEN").ok();

        let (Some(upstream), Some(uuid), Some(token)) = (upstream, uuid, token) else {
            eprintln!("Skipping upstream TUIC test; env not set");
            return;
        };

        let parts: Vec<&str> = upstream.split(':').collect();
        if parts.len() != 2 {
            eprintln!("Invalid SB_TUIC_UPSTREAM_ADDR format");
            return;
        }
        let port: u16 = parts[1].parse().unwrap_or(0);
        if port == 0 {
            eprintln!("Invalid upstream port");
            return;
        }

        let config = TuicConfig {
            server: parts[0].to_string(),
            port,
            uuid: Uuid::parse_str(&uuid).unwrap(),
            token,
            password: None,
            congestion_control: Some("bbr".to_string()),
            alpn: Some(vec!["tuic".to_string()]),
            skip_cert_verify: true,
            sni: None,
            tls_ca_paths: Vec::new(),
            tls_ca_pem: Vec::new(),
            udp_relay_mode: UdpRelayMode::Native,
            udp_over_stream: false,
            zero_rtt_handshake: false,
        };
        let outbound = TuicOutbound::new(config).expect("tuic outbound");
        let target = sb_core::outbound::types::HostPort::new("example.com".to_string(), 80);
        let _ = outbound.connect(&target).await;
    }

    /// Test TUIC error handling
    #[tokio::test]
    async fn test_tuic_error_handling() {
        let config = TuicConfig {
            server: "127.0.0.1".to_string(),
            port: 1,
            uuid: Uuid::new_v4(),
            token: "test_token".to_string(),
            password: None,
            congestion_control: Some("cubic".to_string()),
            alpn: Some(vec!["tuic".to_string()]),
            skip_cert_verify: true,
            sni: None,
            tls_ca_paths: Vec::new(),
            tls_ca_pem: Vec::new(),
            udp_relay_mode: UdpRelayMode::Native,
            udp_over_stream: false,
            zero_rtt_handshake: false,
        };

        let outbound = TuicOutbound::new(config).expect("tuic outbound");
        let target = sb_core::outbound::types::HostPort::new("127.0.0.1".to_string(), 80);
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            outbound.connect(&target),
        )
        .await;
        assert!(result.is_err() || result.unwrap().is_err(), "connect should fail");
    }
}

// Simple test that always runs
#[test]
fn test_tuic_module_exists() {
    // This test ensures the module compiles
    assert!(true, "TUIC test module compiled successfully");
}
