//! E2E test for VMess with Multiplex integration
//!
//! Tests that VMess protocol correctly works with yamux-based multiplexing,
//! allowing multiple concurrent streams over a single TCP connection.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use uuid::Uuid;

// Import VMess adapters
use sb_adapters::outbound::vmess::{VmessConfig, VmessConnector, VmessAuth, VmessTransport, Security};
use sb_adapters::inbound::vmess::VmessInboundConfig;
use sb_adapters::outbound::{OutboundConnector, Target, DialOpts};
use sb_adapters::TransportKind;
use sb_core::router::engine::RouterHandle;
use sb_transport::multiplex::{MultiplexConfig, MultiplexServerConfig};

/// Helper: Start TCP echo server
async fn start_echo_server() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("Failed to bind echo server");
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
    addr
}

/// Helper: Start VMess server with Multiplex support
async fn start_vmess_server(multiplex_enabled: bool) -> (SocketAddr, Uuid, mpsc::Sender<()>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("Failed to bind VMess server");
    let addr = listener.local_addr().unwrap();
    drop(listener); // Release port for server to bind

    let (stop_tx, stop_rx) = mpsc::channel(1);
    let test_uuid = Uuid::new_v4();

    let multiplex_config = if multiplex_enabled {
        Some(MultiplexServerConfig {
            enabled: true,
            protocol: "yamux".to_string(),
            max_connections: 4,
            max_streams: 16,
            padding: false,
            brutal: None,
        })
    } else {
        None
    };

    let config = VmessInboundConfig {
        listen: addr,
        users: vec![VmessAuth {
            uuid: test_uuid,
            alter_id: 0,
            security: Security::Auto,
            additional_data: None,
        }],
        router: Arc::new(RouterHandle::new_mock()),
        multiplex: multiplex_config,
        tls: None,
    };

    tokio::spawn(async move {
        if let Err(e) = sb_adapters::inbound::vmess::serve(config, stop_rx).await {
            eprintln!("VMess server error: {}", e);
        }
    });

    tokio::time::sleep(Duration::from_millis(200)).await;
    (addr, test_uuid, stop_tx)
}

#[tokio::test]
async fn test_vmess_multiplex_single_stream() {
    // Start echo server as upstream target
    let echo_addr = start_echo_server().await;

    // Start VMess server with Multiplex enabled
    let (vmess_addr, test_uuid, _stop_tx) = start_vmess_server(true).await;

    // Create VMess client with Multiplex enabled
    let client_config = VmessConfig {
        server_addr: vmess_addr,
        auth: VmessAuth {
            uuid: test_uuid,
            alter_id: 0,
            security: Security::Auto,
            additional_data: None,
        },
        transport: VmessTransport::default(),
        timeout: Some(Duration::from_secs(10)),
        packet_encoding: false,
        headers: Default::default(),
        multiplex: Some(MultiplexConfig {
            enabled: true,
            protocol: "yamux".to_string(),
            max_connections: 4,
            max_streams: 16,
            padding: false,
            brutal: None,
        }),
        tls: None,
    };

    let connector = VmessConnector::new(client_config);

    // Dial through VMess to echo server
    let target = Target {
        host: echo_addr.ip().to_string(),
        port: echo_addr.port(),
        kind: TransportKind::Tcp,
    };

    let mut stream = connector
        .dial(target, DialOpts::default())
        .await
        .expect("Failed to dial through VMess");

    // Send test data
    let test_data = b"Hello, VMess with Multiplex!";
    stream.write_all(test_data).await.unwrap();

    // Read response
    let mut response = vec![0u8; test_data.len()];
    stream.read_exact(&mut response).await.unwrap();

    assert_eq!(
        response, test_data,
        "Echo response should match sent data"
    );
}

#[tokio::test]
async fn test_vmess_multiplex_concurrent_streams() {
    // Start echo server
    let echo_addr = start_echo_server().await;

    // Start VMess server with Multiplex
    let (vmess_addr, test_uuid, _stop_tx) = start_vmess_server(true).await;

    // Create VMess client with Multiplex
    let client_config = VmessConfig {
        server_addr: vmess_addr,
        auth: VmessAuth {
            uuid: test_uuid,
            alter_id: 0,
            security: Security::Auto,
            additional_data: None,
        },
        transport: VmessTransport::default(),
        timeout: Some(Duration::from_secs(10)),
        packet_encoding: false,
        headers: Default::default(),
        multiplex: Some(MultiplexConfig {
            enabled: true,
            protocol: "yamux".to_string(),
            max_connections: 4,
            max_streams: 16,
            padding: false,
            brutal: None,
        }),
        tls: None,
    };

    let connector = Arc::new(VmessConnector::new(client_config));

    // Open 8 concurrent streams
    let mut handles = vec![];
    for i in 0..8 {
        let connector_clone = Arc::clone(&connector);
        let echo_addr_clone = echo_addr;

        let handle = tokio::spawn(async move {
            let target = Target {
                host: echo_addr_clone.ip().to_string(),
                port: echo_addr_clone.port(),
                kind: TransportKind::Tcp,
            };

            let mut stream = connector_clone
                .dial(target, DialOpts::default())
                .await
                .expect("Failed to dial");

            // Send unique test data
            let test_data = format!("Stream {} test data", i);
            stream.write_all(test_data.as_bytes()).await.unwrap();

            // Read response
            let mut response = vec![0u8; test_data.len()];
            stream.read_exact(&mut response).await.unwrap();

            assert_eq!(
                response,
                test_data.as_bytes(),
                "Stream {} response should match",
                i
            );
        });

        handles.push(handle);
    }

    // Wait for all streams to complete
    for handle in handles {
        handle.await.unwrap();
    }
}

#[tokio::test]
async fn test_vmess_multiplex_data_integrity() {
    // Start echo server
    let echo_addr = start_echo_server().await;

    // Start VMess server with Multiplex
    let (vmess_addr, test_uuid, _stop_tx) = start_vmess_server(true).await;

    // Create VMess client with Multiplex
    let client_config = VmessConfig {
        server_addr: vmess_addr,
        auth: VmessAuth {
            uuid: test_uuid,
            alter_id: 0,
            security: Security::Auto,
            additional_data: None,
        },
        transport: VmessTransport::default(),
        timeout: Some(Duration::from_secs(10)),
        packet_encoding: false,
        headers: Default::default(),
        multiplex: Some(MultiplexConfig {
            enabled: true,
            protocol: "yamux".to_string(),
            max_connections: 4,
            max_streams: 16,
            padding: false,
            brutal: None,
        }),
        tls: None,
    };

    let connector = Arc::new(VmessConnector::new(client_config));

    // Test with large payload (8KB)
    let mut handles = vec![];
    for i in 0..4 {
        let connector_clone = Arc::clone(&connector);
        let echo_addr_clone = echo_addr;

        let handle = tokio::spawn(async move {
            let target = Target {
                host: echo_addr_clone.ip().to_string(),
                port: echo_addr_clone.port(),
                kind: TransportKind::Tcp,
            };

            let mut stream = connector_clone
                .dial(target, DialOpts::default())
                .await
                .expect("Failed to dial");

            // Create large test data (8KB)
            let test_data = vec![((i * 7) % 256) as u8; 8192];
            stream.write_all(&test_data).await.unwrap();

            // Read response
            let mut response = vec![0u8; test_data.len()];
            stream.read_exact(&mut response).await.unwrap();

            assert_eq!(
                response, test_data,
                "Large payload should match for stream {}",
                i
            );
        });

        handles.push(handle);
    }

    // Wait for all streams
    for handle in handles {
        handle.await.unwrap();
    }
}

#[tokio::test]
async fn test_vmess_multiplex_vs_non_multiplex() {
    // Start echo server
    let echo_addr = start_echo_server().await;

    // Start VMess server WITHOUT Multiplex
    let (vmess_addr_no_mux, test_uuid1, _stop_tx1) = start_vmess_server(false).await;

    // Start VMess server WITH Multiplex
    let (vmess_addr_mux, test_uuid2, _stop_tx2) = start_vmess_server(true).await;

    // Test non-multiplex client
    {
        let client_config = VmessConfig {
            server_addr: vmess_addr_no_mux,
            auth: VmessAuth {
                uuid: test_uuid1,
                alter_id: 0,
                security: Security::Auto,
                additional_data: None,
            },
            transport: VmessTransport::default(),
            timeout: Some(Duration::from_secs(10)),
            packet_encoding: false,
            headers: Default::default(),
            multiplex: None, // No multiplex
            tls: None,
        };

        let connector = VmessConnector::new(client_config);

        let target = Target {
            host: echo_addr.ip().to_string(),
            port: echo_addr.port(),
            kind: TransportKind::Tcp,
        };

        let mut stream = connector.dial(target, DialOpts::default()).await.unwrap();

        let test_data = b"Non-multiplex test";
        stream.write_all(test_data).await.unwrap();

        let mut response = vec![0u8; test_data.len()];
        stream.read_exact(&mut response).await.unwrap();

        assert_eq!(response, test_data);
    }

    // Test multiplex client
    {
        let client_config = VmessConfig {
            server_addr: vmess_addr_mux,
            auth: VmessAuth {
                uuid: test_uuid2,
                alter_id: 0,
                security: Security::Auto,
                additional_data: None,
            },
            transport: VmessTransport::default(),
            timeout: Some(Duration::from_secs(10)),
            packet_encoding: false,
            headers: Default::default(),
            multiplex: Some(MultiplexConfig {
                enabled: true,
                protocol: "yamux".to_string(),
                max_connections: 4,
                max_streams: 16,
                padding: false,
                brutal: None,
            }),
            tls: None,
        };

        let connector = VmessConnector::new(client_config);

        let target = Target {
            host: echo_addr.ip().to_string(),
            port: echo_addr.port(),
            kind: TransportKind::Tcp,
        };

        let mut stream = connector.dial(target, DialOpts::default()).await.unwrap();

        let test_data = b"Multiplex test";
        stream.write_all(test_data).await.unwrap();

        let mut response = vec![0u8; test_data.len()];
        stream.read_exact(&mut response).await.unwrap();

        assert_eq!(response, test_data);
    }
}

#[tokio::test]
async fn test_vmess_multiplex_security_levels() {
    // Start echo server
    let echo_addr = start_echo_server().await;

    // Start VMess server with Multiplex
    let (vmess_addr, test_uuid, _stop_tx) = start_vmess_server(true).await;

    // Test with different security levels
    for security in &[Security::Auto, Security::Aes128Gcm, Security::ChaCha20Poly1305] {
        let client_config = VmessConfig {
            server_addr: vmess_addr,
            auth: VmessAuth {
                uuid: test_uuid,
                alter_id: 0,
                security: security.clone(),
                additional_data: None,
            },
            transport: VmessTransport::default(),
            timeout: Some(Duration::from_secs(10)),
            packet_encoding: false,
            headers: Default::default(),
            multiplex: Some(MultiplexConfig {
                enabled: true,
                protocol: "yamux".to_string(),
                max_connections: 4,
                max_streams: 16,
                padding: false,
                brutal: None,
            }),
            tls: None,
        };

        let connector = VmessConnector::new(client_config);

        let target = Target {
            host: echo_addr.ip().to_string(),
            port: echo_addr.port(),
            kind: TransportKind::Tcp,
        };

        let mut stream = connector
            .dial(target, DialOpts::default())
            .await
            .expect(&format!("Failed to dial with {:?}", security));

        let test_data = format!("Security: {:?}", security);
        stream.write_all(test_data.as_bytes()).await.unwrap();

        let mut response = vec![0u8; test_data.len()];
        stream.read_exact(&mut response).await.unwrap();

        assert_eq!(response, test_data.as_bytes());
    }
}

#[tokio::test]
async fn test_vmess_multiplex_alter_id_variations() {
    // Start echo server
    let echo_addr = start_echo_server().await;

    // Start VMess server with Multiplex
    let (vmess_addr, test_uuid, _stop_tx) = start_vmess_server(true).await;

    // Test with different alter_id values
    for alter_id in &[0, 4, 16, 64] {
        let client_config = VmessConfig {
            server_addr: vmess_addr,
            auth: VmessAuth {
                uuid: test_uuid,
                alter_id: *alter_id,
                security: Security::Auto,
                additional_data: None,
            },
            transport: VmessTransport::default(),
            timeout: Some(Duration::from_secs(10)),
            packet_encoding: false,
            headers: Default::default(),
            multiplex: Some(MultiplexConfig {
                enabled: true,
                protocol: "yamux".to_string(),
                max_connections: 4,
                max_streams: 16,
                padding: false,
                brutal: None,
            }),
            tls: None,
        };

        let connector = VmessConnector::new(client_config);

        let target = Target {
            host: echo_addr.ip().to_string(),
            port: echo_addr.port(),
            kind: TransportKind::Tcp,
        };

        let mut stream = connector
            .dial(target, DialOpts::default())
            .await
            .expect(&format!("Failed to dial with alter_id {}", alter_id));

        let test_data = format!("AlterID: {}", alter_id);
        stream.write_all(test_data.as_bytes()).await.unwrap();

        let mut response = vec![0u8; test_data.len()];
        stream.read_exact(&mut response).await.unwrap();

        assert_eq!(response, test_data.as_bytes());
    }
}
