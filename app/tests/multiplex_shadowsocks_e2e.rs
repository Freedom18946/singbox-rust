//! E2E test for Shadowsocks with Multiplex integration
//!
//! Tests that Shadowsocks protocol correctly works with yamux-based multiplexing,
//! allowing multiple concurrent streams over a single TCP connection.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::mpsc;

// Import Shadowsocks adapters
use sb_adapters::inbound::shadowsocks::ShadowsocksInboundConfig;
use sb_adapters::outbound::shadowsocks::{ShadowsocksConfig, ShadowsocksConnector};
use sb_adapters::outbound::{DialOpts, OutboundConnector, Target};
use sb_adapters::TransportKind;
use sb_core::router::engine::RouterHandle;
use sb_transport::multiplex::{MultiplexConfig, MultiplexServerConfig};

fn is_perm(e: &std::io::Error) -> bool {
    e.kind() == std::io::ErrorKind::PermissionDenied
}

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

/// Helper: Start Shadowsocks server with Multiplex support
async fn start_shadowsocks_server(multiplex_enabled: bool) -> (SocketAddr, mpsc::Sender<()>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("Failed to bind Shadowsocks server");
    let addr = listener.local_addr().unwrap();
    drop(listener); // Release port for server to bind

    let (stop_tx, stop_rx) = mpsc::channel(1);

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

    let config = ShadowsocksInboundConfig {
        listen: addr,
        method: "aes-256-gcm".to_string(),
        password: "test-password-123".to_string(),
        router: Arc::new(RouterHandle::new_mock()),
        multiplex: multiplex_config,
    };

    tokio::spawn(async move {
        if let Err(e) = sb_adapters::inbound::shadowsocks::serve(config, stop_rx).await {
            eprintln!("Shadowsocks server error: {}", e);
        }
    });

    tokio::time::sleep(Duration::from_millis(200)).await;
    (addr, stop_tx)
}

#[tokio::test]
async fn test_shadowsocks_multiplex_single_stream() {
    // Start echo server as upstream target
    let echo_addr = start_echo_server().await;

    // Start Shadowsocks server with Multiplex enabled
    let (ss_addr, _stop_tx) = start_shadowsocks_server(true).await;

    // Create Shadowsocks client with Multiplex enabled
    let client_config = ShadowsocksConfig {
        server: ss_addr.to_string(),
        tag: None,
        method: "aes-256-gcm".to_string(),
        password: "test-password-123".to_string(),
        connect_timeout_sec: Some(10),
        multiplex: Some(MultiplexConfig {
            enabled: true,
            protocol: "yamux".to_string(),
            max_connections: 4,
            max_streams: 16,
            padding: false,
            brutal: None,
        }),
    };

    let connector =
        ShadowsocksConnector::new(client_config).expect("Failed to create Shadowsocks connector");

    // Dial through Shadowsocks to echo server
    let target = Target {
        host: echo_addr.ip().to_string(),
        port: echo_addr.port(),
        kind: TransportKind::Tcp,
    };

    let mut stream = connector
        .dial(target, DialOpts::default())
        .await
        .expect("Failed to dial through Shadowsocks");

    // Send test data
    let test_data = b"Hello, Shadowsocks with Multiplex!";
    stream.write_all(test_data).await.unwrap();

    // Read response
    let mut response = vec![0u8; test_data.len()];
    stream.read_exact(&mut response).await.unwrap();

    assert_eq!(response, test_data, "Echo response should match sent data");
}

#[tokio::test]
async fn test_shadowsocks_multiplex_concurrent_streams() {
    // Start echo server
    let echo_addr = start_echo_server().await;

    // Start Shadowsocks server with Multiplex
    let (ss_addr, _stop_tx) = start_shadowsocks_server(true).await;

    // Create Shadowsocks client with Multiplex
    let client_config = ShadowsocksConfig {
        server: ss_addr.to_string(),
        tag: None,
        method: "aes-256-gcm".to_string(),
        password: "test-password-123".to_string(),
        connect_timeout_sec: Some(10),
        multiplex: Some(MultiplexConfig {
            enabled: true,
            protocol: "yamux".to_string(),
            max_connections: 4,
            max_streams: 16,
            padding: false,
            brutal: None,
        }),
    };

    let connector = Arc::new(
        ShadowsocksConnector::new(client_config).expect("Failed to create Shadowsocks connector"),
    );

    // Open 8 concurrent streams
    let mut handles = vec![];
    for i in 0..8 {
        let connector_clone: Arc<ShadowsocksConnector> = Arc::clone(&connector);
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
async fn test_shadowsocks_multiplex_data_integrity() {
    // Start echo server
    let echo_addr = start_echo_server().await;

    // Start Shadowsocks server with Multiplex
    let (ss_addr, _stop_tx) = start_shadowsocks_server(true).await;

    // Create Shadowsocks client with Multiplex
    let client_config = ShadowsocksConfig {
        server: ss_addr.to_string(),
        tag: None,
        method: "aes-256-gcm".to_string(),
        password: "test-password-123".to_string(),
        connect_timeout_sec: Some(10),
        multiplex: Some(MultiplexConfig {
            enabled: true,
            protocol: "yamux".to_string(),
            max_connections: 4,
            max_streams: 16,
            padding: false,
            brutal: None,
        }),
    };

    let connector = Arc::new(
        ShadowsocksConnector::new(client_config).expect("Failed to create Shadowsocks connector"),
    );

    // Test with large payload (8KB)
    let mut handles = vec![];
    for i in 0..4 {
        let connector_clone: Arc<ShadowsocksConnector> = Arc::clone(&connector);
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
async fn test_shadowsocks_multiplex_vs_non_multiplex() {
    // Start echo server
    let echo_addr = start_echo_server().await;

    // Start Shadowsocks server WITHOUT Multiplex
    let (ss_addr_no_mux, _stop_tx1) = start_shadowsocks_server(false).await;

    // Start Shadowsocks server WITH Multiplex
    let (ss_addr_mux, _stop_tx2) = start_shadowsocks_server(true).await;

    // Test non-multiplex client
    {
        let client_config = ShadowsocksConfig {
            server: ss_addr_no_mux.to_string(),
            tag: None,
            method: "aes-256-gcm".to_string(),
            password: "test-password-123".to_string(),
            connect_timeout_sec: Some(10),
            multiplex: None, // No multiplex
        };

        let connector = ShadowsocksConnector::new(client_config).unwrap();

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
        let client_config = ShadowsocksConfig {
            server: ss_addr_mux.to_string(),
            tag: None,
            method: "aes-256-gcm".to_string(),
            password: "test-password-123".to_string(),
            connect_timeout_sec: Some(10),
            multiplex: Some(MultiplexConfig {
                enabled: true,
                protocol: "yamux".to_string(),
                max_connections: 4,
                max_streams: 16,
                padding: false,
                brutal: None,
            }),
        };

        let connector = ShadowsocksConnector::new(client_config).unwrap();

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
async fn test_shadowsocks_multiplex_sequential_and_concurrent() {
    // Start echo server
    let echo_addr = start_echo_server().await;

    // Start Shadowsocks server with Multiplex
    let (ss_addr, _stop_tx) = start_shadowsocks_server(true).await;

    // Create Shadowsocks client with Multiplex
    let client_config = ShadowsocksConfig {
        server: ss_addr.to_string(),
        tag: None,
        method: "aes-256-gcm".to_string(),
        password: "test-password-123".to_string(),
        connect_timeout_sec: Some(10),
        multiplex: Some(MultiplexConfig {
            enabled: true,
            protocol: "yamux".to_string(),
            max_connections: 4,
            max_streams: 16,
            padding: false,
            brutal: None,
        }),
    };

    let connector = Arc::new(ShadowsocksConnector::new(client_config).unwrap());

    // First: Sequential streams (one after another)
    for i in 0..3 {
        let target = Target {
            host: echo_addr.ip().to_string(),
            port: echo_addr.port(),
            kind: TransportKind::Tcp,
        };

        let mut stream = connector.dial(target, DialOpts::default()).await.unwrap();

        let test_data = format!("Sequential stream {}", i);
        stream.write_all(test_data.as_bytes()).await.unwrap();

        let mut response = vec![0u8; test_data.len()];
        stream.read_exact(&mut response).await.unwrap();

        assert_eq!(response, test_data.as_bytes());
    }

    // Then: Concurrent streams
    let mut handles = vec![];
    for i in 0..5 {
        let connector_clone: Arc<ShadowsocksConnector> = Arc::clone(&connector);
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
                .unwrap();

            let test_data = format!("Concurrent stream {}", i);
            stream.write_all(test_data.as_bytes()).await.unwrap();

            let mut response = vec![0u8; test_data.len()];
            stream.read_exact(&mut response).await.unwrap();

            assert_eq!(response, test_data.as_bytes());
        });

        handles.push(handle);
    }

    for handle in handles {
        handle.await.unwrap();
    }
}
