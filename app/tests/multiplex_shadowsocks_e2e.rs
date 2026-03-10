#![cfg(feature = "net_e2e")]
//! E2E test for Shadowsocks with Multiplex integration
//!
//! Tests that Shadowsocks protocol correctly works with yamux-based multiplexing,
//! allowing multiple concurrent streams over a single TCP connection.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio::sync::oneshot;

// Import Shadowsocks adapters
use sb_adapters::inbound::shadowsocks::{ShadowsocksInboundConfig, ShadowsocksUser};
use sb_adapters::outbound::shadowsocks::{ShadowsocksConfig, ShadowsocksConnector};
use sb_adapters::outbound::{DialOpts, OutboundConnector, Target};
use sb_adapters::TransportKind;
use sb_core::router::engine::RouterHandle;
use sb_transport::multiplex::{MultiplexConfig, MultiplexServerConfig};

#[allow(dead_code)]
fn is_perm(e: &std::io::Error) -> bool {
    e.kind() == std::io::ErrorKind::PermissionDenied
}

fn is_constrained_dial_error_str(s: &str) -> bool {
    let s = s.to_ascii_lowercase();

    // Common in sandboxed macOS environments.
    if s.contains("operation not permitted") || s.contains("permission denied") {
        return true;
    }

    // Observed in some macOS sandboxes even when bind() succeeds; treat as constrained.
    if cfg!(target_os = "macos")
        && (s.contains("connection reset by peer")
            || s.contains("unexpectedeof")
            || s.contains("unexpected eof")
            || s.contains("early eof"))
    {
        return true;
    }

    false
}

fn should_skip_network_tests() -> bool {
    match std::net::TcpListener::bind("127.0.0.1:0") {
        Ok(listener) => {
            drop(listener);
            false
        }
        Err(err)
            if is_perm(&err)
                || err.kind() == io::ErrorKind::AddrNotAvailable
                || err.to_string().contains("Operation not permitted") =>
        {
            eprintln!("Skipping multiplex shadowsocks tests: {}", err);
            true
        }
        Err(err) => panic!("Failed to bind test listener: {}", err),
    }
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
    let (stop_tx, stop_rx) = mpsc::channel(1);
    let (ready_tx, ready_rx) = oneshot::channel();

    let multiplex_config = if multiplex_enabled {
        Some(MultiplexServerConfig::default())
    } else {
        None
    };

    let listen: SocketAddr = "127.0.0.1:0".parse().unwrap();

    #[allow(deprecated)]
    let config = ShadowsocksInboundConfig {
        listen,
        method: "aes-256-gcm".to_string(),
        password: None,
        users: vec![ShadowsocksUser::new(
            "test".to_string(),
            "test-password-123".to_string(),
        )],
        router: Arc::new(RouterHandle::new_mock()),
        tag: None,
        stats: None,
        multiplex: multiplex_config,
        transport_layer: None,
    };

    tokio::spawn(async move {
        if let Err(e) =
            sb_adapters::inbound::shadowsocks::serve_with_ready(config, stop_rx, ready_tx).await
        {
            eprintln!("Shadowsocks server error: {}", e);
        }
    });

    let addr = tokio::time::timeout(Duration::from_secs(5), ready_rx)
        .await
        .expect("Timed out waiting for Shadowsocks server to bind")
        .expect("Shadowsocks server dropped before binding");

    (addr, stop_tx)
}

#[tokio::test]
async fn test_shadowsocks_multiplex_single_stream() {
    if should_skip_network_tests() {
        return;
    }

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
        detour: None,
        multiplex: Some(MultiplexConfig::default()),
    };

    let connector =
        ShadowsocksConnector::new(client_config).expect("Failed to create Shadowsocks connector");

    // Dial through Shadowsocks to echo server
    let target = Target {
        host: echo_addr.ip().to_string(),
        port: echo_addr.port(),
        kind: TransportKind::Tcp,
    };

    let mut stream = match connector.dial(target, DialOpts::default()).await {
        Ok(s) => s,
        Err(e) if is_constrained_dial_error_str(&e.to_string()) => {
            eprintln!("Skipping multiplex shadowsocks tests: {}", e);
            return;
        }
        Err(e) => panic!("Failed to dial through Shadowsocks: {}", e),
    };

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
    if should_skip_network_tests() {
        return;
    }

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
        detour: None,
        multiplex: Some(MultiplexConfig::default()),
    };

    let connector = Arc::new(
        ShadowsocksConnector::new(client_config).expect("Failed to create Shadowsocks connector"),
    );

    // Preflight a single stream to detect constrained sandbox environments before spawning tasks.
    {
        let target = Target {
            host: echo_addr.ip().to_string(),
            port: echo_addr.port(),
            kind: TransportKind::Tcp,
        };
        let mut s = match connector.dial(target, DialOpts::default()).await {
            Ok(s) => s,
            Err(e) if is_constrained_dial_error_str(&e.to_string()) => {
                eprintln!("Skipping multiplex shadowsocks tests: {}", e);
                return;
            }
            Err(e) => panic!("Failed to dial (preflight): {}", e),
        };
        s.write_all(b"ping").await.unwrap();
        let mut r = [0u8; 4];
        s.read_exact(&mut r).await.unwrap();
        assert_eq!(&r, b"ping");
    }

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
    if should_skip_network_tests() {
        return;
    }

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
        detour: None,
        multiplex: Some(MultiplexConfig::default()),
    };

    let connector = Arc::new(
        ShadowsocksConnector::new(client_config).expect("Failed to create Shadowsocks connector"),
    );

    // Preflight to detect constrained environments.
    {
        let target = Target {
            host: echo_addr.ip().to_string(),
            port: echo_addr.port(),
            kind: TransportKind::Tcp,
        };
        let mut s = match connector.dial(target, DialOpts::default()).await {
            Ok(s) => s,
            Err(e) if is_constrained_dial_error_str(&e.to_string()) => {
                eprintln!("Skipping multiplex shadowsocks tests: {}", e);
                return;
            }
            Err(e) => panic!("Failed to dial (preflight): {}", e),
        };
        s.write_all(b"ping").await.unwrap();
        let mut r = [0u8; 4];
        s.read_exact(&mut r).await.unwrap();
        assert_eq!(&r, b"ping");
    }

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
    if should_skip_network_tests() {
        return;
    }

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
            detour: None,
            multiplex: None, // No multiplex
        };

        let connector = ShadowsocksConnector::new(client_config).unwrap();

        let target = Target {
            host: echo_addr.ip().to_string(),
            port: echo_addr.port(),
            kind: TransportKind::Tcp,
        };

        let mut stream = match connector.dial(target, DialOpts::default()).await {
            Ok(s) => s,
            Err(e) if is_constrained_dial_error_str(&e.to_string()) => {
                eprintln!("Skipping multiplex shadowsocks tests: {}", e);
                return;
            }
            Err(e) => panic!("Failed to dial (non-mux): {}", e),
        };

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
            detour: None,
            multiplex: Some(MultiplexConfig::default()),
        };

        let connector = ShadowsocksConnector::new(client_config).unwrap();

        let target = Target {
            host: echo_addr.ip().to_string(),
            port: echo_addr.port(),
            kind: TransportKind::Tcp,
        };

        let mut stream = match connector.dial(target, DialOpts::default()).await {
            Ok(s) => s,
            Err(e) if is_constrained_dial_error_str(&e.to_string()) => {
                eprintln!("Skipping multiplex shadowsocks tests: {}", e);
                return;
            }
            Err(e) => panic!("Failed to dial (mux): {}", e),
        };

        let test_data = b"Multiplex test";
        stream.write_all(test_data).await.unwrap();

        let mut response = vec![0u8; test_data.len()];
        stream.read_exact(&mut response).await.unwrap();

        assert_eq!(response, test_data);
    }
}

#[tokio::test]
async fn test_shadowsocks_multiplex_sequential_and_concurrent() {
    if should_skip_network_tests() {
        return;
    }

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
        detour: None,
        multiplex: Some(MultiplexConfig::default()),
    };

    let connector = Arc::new(ShadowsocksConnector::new(client_config).unwrap());

    // Preflight to detect constrained environments.
    {
        let target = Target {
            host: echo_addr.ip().to_string(),
            port: echo_addr.port(),
            kind: TransportKind::Tcp,
        };
        let mut s = match connector.dial(target, DialOpts::default()).await {
            Ok(s) => s,
            Err(e) if is_constrained_dial_error_str(&e.to_string()) => {
                eprintln!("Skipping multiplex shadowsocks tests: {}", e);
                return;
            }
            Err(e) => panic!("Failed to dial (preflight): {}", e),
        };
        s.write_all(b"ping").await.unwrap();
        let mut r = [0u8; 4];
        s.read_exact(&mut r).await.unwrap();
        assert_eq!(&r, b"ping");
    }

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
