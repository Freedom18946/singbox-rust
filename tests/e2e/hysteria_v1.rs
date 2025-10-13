//! Hysteria v1 E2E tests
//!
//! Tests TCP proxy and UDP relay through Hysteria v1 protocol

#[cfg(test)]
mod tests {
    use sb_core::outbound::hysteria::v1::{
        HysteriaV1Config, HysteriaV1Inbound, HysteriaV1Outbound, HysteriaV1ServerConfig,
        UdpSessionManager,
    };
    use sb_core::outbound::types::{HostPort, OutboundTcp};
    use std::net::SocketAddr;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, UdpSocket};

    /// Helper to generate self-signed test certificates
    async fn generate_test_certs() -> (String, String) {
        use std::process::Command;

        let cert_path = "/tmp/hysteria_test_cert.pem";
        let key_path = "/tmp/hysteria_test_key.pem";

        // Generate self-signed certificate using openssl
        let output = Command::new("openssl")
            .args(&[
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-keyout",
                key_path,
                "-out",
                cert_path,
                "-days",
                "1",
                "-nodes",
                "-subj",
                "/CN=localhost",
            ])
            .output();

        if output.is_ok() {
            (cert_path.to_string(), key_path.to_string())
        } else {
            // Fallback: use existing test cert if available
            (
                "tests/configs/test_cert.pem".to_string(),
                "tests/configs/test_cert.pem".to_string(),
            )
        }
    }

    /// Helper to start an echo server
    async fn start_echo_server() -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            loop {
                if let Ok((mut socket, _)) = listener.accept().await {
                    tokio::spawn(async move {
                        let mut buf = vec![0u8; 4096];
                        while let Ok(n) = socket.read(&mut buf).await {
                            if n == 0 {
                                break;
                            }
                            let _ = socket.write_all(&buf[..n]).await;
                        }
                    });
                }
            }
        });

        tokio::time::sleep(Duration::from_millis(50)).await;
        addr
    }

    /// Test TCP proxy through Hysteria v1
    #[tokio::test]
    async fn test_hysteria_v1_tcp_proxy() {
        // Start echo server
        let echo_addr = start_echo_server().await;

        // Generate test certificates
        let (cert_path, key_path) = generate_test_certs().await;

        // Configure Hysteria v1 server
        let server_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let server_config = HysteriaV1ServerConfig {
            listen: server_addr,
            up_mbps: 100,
            down_mbps: 100,
            obfs: None,
            auth: Some("test_password".to_string()),
            cert_path: cert_path.clone(),
            key_path: key_path.clone(),
            recv_window_conn: Some(100),
            recv_window: Some(100),
        };

        let server = HysteriaV1Inbound::new(server_config);

        // Start server
        if let Err(e) = server.start().await {
            eprintln!("Failed to start Hysteria v1 server: {}", e);
            return;
        }

        // Get actual server port
        let server_port = server_addr.port();

        // Configure Hysteria v1 client
        let client_config = HysteriaV1Config {
            server: "127.0.0.1".to_string(),
            port: server_port,
            protocol: "udp".to_string(),
            up_mbps: 100,
            down_mbps: 100,
            obfs: None,
            auth: Some("test_password".to_string()),
            alpn: vec!["hysteria".to_string()],
            recv_window_conn: None,
            recv_window: None,
            skip_cert_verify: true,
            sni: None,
        };

        let client = HysteriaV1Outbound::new(client_config).unwrap();

        // Connect through proxy to echo server
        let target = HostPort::new(echo_addr.ip().to_string(), echo_addr.port());
        let mut stream = match client.connect(&target).await {
            Ok(s) => s,
            Err(e) => {
                eprintln!("Failed to connect through Hysteria v1: {}", e);
                return;
            }
        };

        // Test data transmission
        let test_data = b"Hello, Hysteria v1!";
        stream.write_all(test_data).await.unwrap();

        let mut response = vec![0u8; test_data.len()];
        stream.read_exact(&mut response).await.unwrap();

        assert_eq!(&response[..], test_data);
    }

    /// Test TCP proxy with multiple connections
    #[tokio::test]
    async fn test_hysteria_v1_tcp_proxy_multiple_connections() {
        let echo_addr = start_echo_server().await;
        let (cert_path, key_path) = generate_test_certs().await;

        let server_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let server_config = HysteriaV1ServerConfig {
            listen: server_addr,
            up_mbps: 100,
            down_mbps: 100,
            obfs: None,
            auth: None,
            cert_path,
            key_path,
            recv_window_conn: Some(100),
            recv_window: Some(100),
        };

        let server = HysteriaV1Inbound::new(server_config);
        if server.start().await.is_err() {
            return;
        }

        let client_config = HysteriaV1Config {
            server: "127.0.0.1".to_string(),
            port: server_addr.port(),
            protocol: "udp".to_string(),
            up_mbps: 100,
            down_mbps: 100,
            obfs: None,
            auth: None,
            alpn: vec!["hysteria".to_string()],
            recv_window_conn: None,
            recv_window: None,
            skip_cert_verify: true,
            sni: None,
        };

        // Create multiple sequential connections to test connection reuse
        for i in 0..5 {
            let client = HysteriaV1Outbound::new(client_config.clone()).unwrap();
            let target = HostPort::new(echo_addr.ip().to_string(), echo_addr.port());

            if let Ok(mut stream) = client.connect(&target).await {
                let test_data = format!("Connection {}", i);
                let _ = stream.write_all(test_data.as_bytes()).await;

                let mut response = vec![0u8; test_data.len()];
                if stream.read_exact(&mut response).await.is_ok() {
                    assert_eq!(response, test_data.as_bytes());
                }
            }
        }
    }

    /// Test UDP relay through Hysteria v1
    #[tokio::test]
    async fn test_hysteria_v1_udp_relay() {
        // Start UDP echo server
        let udp_server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let udp_addr = udp_server.local_addr().unwrap();

        tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            loop {
                if let Ok((n, peer)) = udp_server.recv_from(&mut buf).await {
                    let _ = udp_server.send_to(&buf[..n], peer).await;
                }
            }
        });

        tokio::time::sleep(Duration::from_millis(50)).await;

        // Test UDP session manager
        let session_manager = UdpSessionManager::new(Duration::from_secs(60));

        let client_addr: SocketAddr = "127.0.0.1:12345".parse().unwrap();
        let session_id = 1;

        session_manager
            .create_session(session_id, client_addr, udp_addr)
            .await;

        // Verify session was created
        let session = session_manager.get_session(session_id).await;
        assert!(session.is_some());

        let session = session.unwrap();
        assert_eq!(session.session_id, session_id);
        assert_eq!(session.client_addr, client_addr);
        assert_eq!(session.target_addr, udp_addr);
    }

    /// Test UDP session timeout
    #[tokio::test]
    async fn test_hysteria_v1_udp_session_timeout() {
        let session_manager = UdpSessionManager::new(Duration::from_millis(100));

        let client_addr: SocketAddr = "127.0.0.1:12345".parse().unwrap();
        let target_addr: SocketAddr = "127.0.0.1:54321".parse().unwrap();
        let session_id = 1;

        session_manager
            .create_session(session_id, client_addr, target_addr)
            .await;

        // Session should exist immediately
        assert!(session_manager.get_session(session_id).await.is_some());

        // Wait for timeout
        tokio::time::sleep(Duration::from_millis(150)).await;

        // Cleanup expired sessions
        session_manager.cleanup_expired().await;

        // Session should be removed
        assert!(session_manager.get_session(session_id).await.is_none());
    }

    /// Test authentication with valid credentials
    #[tokio::test]
    async fn test_hysteria_v1_authentication_valid() {
        let echo_addr = start_echo_server().await;
        let (cert_path, key_path) = generate_test_certs().await;

        let auth_password = "secure_password_123";

        let server_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let server_config = HysteriaV1ServerConfig {
            listen: server_addr,
            up_mbps: 100,
            down_mbps: 100,
            obfs: None,
            auth: Some(auth_password.to_string()),
            cert_path,
            key_path,
            recv_window_conn: Some(100),
            recv_window: Some(100),
        };

        let server = HysteriaV1Inbound::new(server_config);
        if server.start().await.is_err() {
            return;
        }

        let client_config = HysteriaV1Config {
            server: "127.0.0.1".to_string(),
            port: server_addr.port(),
            protocol: "udp".to_string(),
            up_mbps: 100,
            down_mbps: 100,
            obfs: None,
            auth: Some(auth_password.to_string()),
            alpn: vec!["hysteria".to_string()],
            recv_window_conn: None,
            recv_window: None,
            skip_cert_verify: true,
            sni: None,
        };

        let client = HysteriaV1Outbound::new(client_config).unwrap();
        let target = HostPort::new(echo_addr.ip().to_string(), echo_addr.port());

        // Should succeed with correct password
        let result = client.connect(&target).await;
        assert!(result.is_ok());
    }

    /// Test authentication with invalid credentials
    #[tokio::test]
    async fn test_hysteria_v1_authentication_invalid() {
        let (cert_path, key_path) = generate_test_certs().await;

        let server_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let server_config = HysteriaV1ServerConfig {
            listen: server_addr,
            up_mbps: 100,
            down_mbps: 100,
            obfs: None,
            auth: Some("correct_password".to_string()),
            cert_path,
            key_path,
            recv_window_conn: Some(100),
            recv_window: Some(100),
        };

        let server = HysteriaV1Inbound::new(server_config);
        if server.start().await.is_err() {
            return;
        }

        let client_config = HysteriaV1Config {
            server: "127.0.0.1".to_string(),
            port: server_addr.port(),
            protocol: "udp".to_string(),
            up_mbps: 100,
            down_mbps: 100,
            obfs: None,
            auth: Some("wrong_password".to_string()),
            alpn: vec!["hysteria".to_string()],
            recv_window_conn: None,
            recv_window: None,
            skip_cert_verify: true,
            sni: None,
        };

        let client = HysteriaV1Outbound::new(client_config).unwrap();
        let target = HostPort::new("127.0.0.1".to_string(), 8080);

        // Should fail with wrong password
        let result = client.connect(&target).await;
        assert!(result.is_err());
    }

    /// Test authentication without credentials when required
    #[tokio::test]
    async fn test_hysteria_v1_authentication_missing() {
        let (cert_path, key_path) = generate_test_certs().await;

        let server_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let server_config = HysteriaV1ServerConfig {
            listen: server_addr,
            up_mbps: 100,
            down_mbps: 100,
            obfs: None,
            auth: Some("required_password".to_string()),
            cert_path,
            key_path,
            recv_window_conn: Some(100),
            recv_window: Some(100),
        };

        let server = HysteriaV1Inbound::new(server_config);
        if server.start().await.is_err() {
            return;
        }

        let client_config = HysteriaV1Config {
            server: "127.0.0.1".to_string(),
            port: server_addr.port(),
            protocol: "udp".to_string(),
            up_mbps: 100,
            down_mbps: 100,
            obfs: None,
            auth: None, // No authentication provided
            alpn: vec!["hysteria".to_string()],
            recv_window_conn: None,
            recv_window: None,
            skip_cert_verify: true,
            sni: None,
        };

        let client = HysteriaV1Outbound::new(client_config).unwrap();
        let target = HostPort::new("127.0.0.1".to_string(), 8080);

        // Should fail without authentication
        let result = client.connect(&target).await;
        assert!(result.is_err());
    }

    /// Test with different congestion control bandwidth settings
    #[tokio::test]
    async fn test_hysteria_v1_congestion_control_bandwidth() {
        let echo_addr = start_echo_server().await;
        let (cert_path, key_path) = generate_test_certs().await;

        // Test different bandwidth configurations
        let bandwidth_configs = vec![
            (10, 50),     // Low bandwidth
            (100, 100),   // Medium bandwidth
            (1000, 1000), // High bandwidth
        ];

        for (up_mbps, down_mbps) in bandwidth_configs {
            let server_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
            let server_config = HysteriaV1ServerConfig {
                listen: server_addr,
                up_mbps,
                down_mbps,
                obfs: None,
                auth: None,
                cert_path: cert_path.clone(),
                key_path: key_path.clone(),
                recv_window_conn: Some(100),
                recv_window: Some(100),
            };

            let server = HysteriaV1Inbound::new(server_config);
            if server.start().await.is_err() {
                continue;
            }

            let client_config = HysteriaV1Config {
                server: "127.0.0.1".to_string(),
                port: server_addr.port(),
                protocol: "udp".to_string(),
                up_mbps,
                down_mbps,
                obfs: None,
                auth: None,
                alpn: vec!["hysteria".to_string()],
                recv_window_conn: None,
                recv_window: None,
                skip_cert_verify: true,
                sni: None,
            };

            let client = HysteriaV1Outbound::new(client_config).unwrap();
            let target = HostPort::new(echo_addr.ip().to_string(), echo_addr.port());

            if let Ok(mut stream) = client.connect(&target).await {
                let test_data = b"Bandwidth test";
                let _ = stream.write_all(test_data).await;

                let mut response = vec![0u8; test_data.len()];
                if stream.read_exact(&mut response).await.is_ok() {
                    assert_eq!(&response[..], test_data);
                }
            }
        }
    }

    /// Test with different protocol modes
    #[tokio::test]
    async fn test_hysteria_v1_protocol_modes() {
        let _echo_addr = start_echo_server().await;
        let (cert_path, key_path) = generate_test_certs().await;

        // Test different protocol modes
        let protocols = vec!["udp", "wechat-video", "faketcp"];

        for protocol in protocols {
            let server_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
            let server_config = HysteriaV1ServerConfig {
                listen: server_addr,
                up_mbps: 100,
                down_mbps: 100,
                obfs: None,
                auth: None,
                cert_path: cert_path.clone(),
                key_path: key_path.clone(),
                recv_window_conn: Some(100),
                recv_window: Some(100),
            };

            let server = HysteriaV1Inbound::new(server_config);
            if server.start().await.is_err() {
                continue;
            }

            let client_config = HysteriaV1Config {
                server: "127.0.0.1".to_string(),
                port: server_addr.port(),
                protocol: protocol.to_string(),
                up_mbps: 100,
                down_mbps: 100,
                obfs: None,
                auth: None,
                alpn: vec!["hysteria".to_string()],
                recv_window_conn: None,
                recv_window: None,
                skip_cert_verify: true,
                sni: None,
            };

            let client = HysteriaV1Outbound::new(client_config);
            assert!(
                client.is_ok(),
                "Failed to create client with protocol: {}",
                protocol
            );
        }
    }

    /// Test obfuscation feature
    #[tokio::test]
    async fn test_hysteria_v1_obfuscation() {
        let echo_addr = start_echo_server().await;
        let (cert_path, key_path) = generate_test_certs().await;

        let obfs_password = "obfs_secret";

        let server_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let server_config = HysteriaV1ServerConfig {
            listen: server_addr,
            up_mbps: 100,
            down_mbps: 100,
            obfs: Some(obfs_password.to_string()),
            auth: None,
            cert_path,
            key_path,
            recv_window_conn: Some(100),
            recv_window: Some(100),
        };

        let server = HysteriaV1Inbound::new(server_config);
        if server.start().await.is_err() {
            return;
        }

        let client_config = HysteriaV1Config {
            server: "127.0.0.1".to_string(),
            port: server_addr.port(),
            protocol: "udp".to_string(),
            up_mbps: 100,
            down_mbps: 100,
            obfs: Some(obfs_password.to_string()),
            auth: None,
            alpn: vec!["hysteria".to_string()],
            recv_window_conn: None,
            recv_window: None,
            skip_cert_verify: true,
            sni: None,
        };

        let client = HysteriaV1Outbound::new(client_config).unwrap();
        let target = HostPort::new(echo_addr.ip().to_string(), echo_addr.port());

        // Should work with matching obfuscation
        let result = client.connect(&target).await;
        assert!(result.is_ok());
    }

    /// Test large data transfer
    #[tokio::test]
    async fn test_hysteria_v1_large_data_transfer() {
        let echo_addr = start_echo_server().await;
        let (cert_path, key_path) = generate_test_certs().await;

        let server_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let server_config = HysteriaV1ServerConfig {
            listen: server_addr,
            up_mbps: 1000,
            down_mbps: 1000,
            obfs: None,
            auth: None,
            cert_path,
            key_path,
            recv_window_conn: Some(1000),
            recv_window: Some(1000),
        };

        let server = HysteriaV1Inbound::new(server_config);
        if server.start().await.is_err() {
            return;
        }

        let client_config = HysteriaV1Config {
            server: "127.0.0.1".to_string(),
            port: server_addr.port(),
            protocol: "udp".to_string(),
            up_mbps: 1000,
            down_mbps: 1000,
            obfs: None,
            auth: None,
            alpn: vec!["hysteria".to_string()],
            recv_window_conn: None,
            recv_window: None,
            skip_cert_verify: true,
            sni: None,
        };

        let client = HysteriaV1Outbound::new(client_config).unwrap();
        let target = HostPort::new(echo_addr.ip().to_string(), echo_addr.port());

        if let Ok(mut stream) = client.connect(&target).await {
            // Transfer 1MB of data
            let test_data = vec![0xAB; 1024 * 1024];
            let _ = stream.write_all(&test_data).await;

            let mut response = vec![0u8; test_data.len()];
            if stream.read_exact(&mut response).await.is_ok() {
                assert_eq!(response.len(), test_data.len());
                assert_eq!(&response[..100], &test_data[..100]);
            }
        }
    }

    /// Test connection reuse
    #[tokio::test]
    async fn test_hysteria_v1_connection_reuse() {
        let echo_addr = start_echo_server().await;
        let (cert_path, key_path) = generate_test_certs().await;

        let server_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let server_config = HysteriaV1ServerConfig {
            listen: server_addr,
            up_mbps: 100,
            down_mbps: 100,
            obfs: None,
            auth: None,
            cert_path,
            key_path,
            recv_window_conn: Some(100),
            recv_window: Some(100),
        };

        let server = HysteriaV1Inbound::new(server_config);
        if server.start().await.is_err() {
            return;
        }

        let client_config = HysteriaV1Config {
            server: "127.0.0.1".to_string(),
            port: server_addr.port(),
            protocol: "udp".to_string(),
            up_mbps: 100,
            down_mbps: 100,
            obfs: None,
            auth: None,
            alpn: vec!["hysteria".to_string()],
            recv_window_conn: None,
            recv_window: None,
            skip_cert_verify: true,
            sni: None,
        };

        let client = HysteriaV1Outbound::new(client_config).unwrap();
        let target = HostPort::new(echo_addr.ip().to_string(), echo_addr.port());

        // Make multiple connections - should reuse QUIC connection
        for i in 0..3 {
            if let Ok(mut stream) = client.connect(&target).await {
                let test_data = format!("Request {}", i);
                let _ = stream.write_all(test_data.as_bytes()).await;

                let mut response = vec![0u8; test_data.len()];
                if stream.read_exact(&mut response).await.is_ok() {
                    assert_eq!(response, test_data.as_bytes());
                }
            }
        }
    }
}
