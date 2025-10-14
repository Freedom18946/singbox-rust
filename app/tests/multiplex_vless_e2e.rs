//! E2E test for VLESS with Multiplex integration
//!
//! Tests that VLESS protocol correctly works with yamux-based multiplexing,
//! allowing multiple concurrent streams over a single TCP connection.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use uuid::Uuid;

// Import VLESS adapters
use sb_adapters::inbound::vless::VlessInboundConfig;
use sb_adapters::outbound::vless::{Encryption, FlowControl, VlessConfig, VlessConnector};
use sb_adapters::outbound::{DialOpts, OutboundConnector, Target};
use sb_adapters::TransportKind;
use sb_core::router::engine::RouterHandle;
use sb_adapters::transport_config::TransportConfig;
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

/// Helper: Start VLESS server with Multiplex support
async fn start_vless_server(multiplex_enabled: bool) -> (SocketAddr, Uuid, mpsc::Sender<()>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("Failed to bind VLESS server");
    let addr = listener.local_addr().unwrap();
    drop(listener); // Release port for server to bind

    let (stop_tx, stop_rx) = mpsc::channel(1);
    let test_uuid = Uuid::new_v4();

    let multiplex_config = if multiplex_enabled {
        Some(MultiplexServerConfig {
            max_num_streams: 16,
            initial_stream_window: 256 * 1024,
            max_stream_window: 1024 * 1024,
            enable_keepalive: true,
            brutal: None,
        })
    } else {
        None
    };

    let config = VlessInboundConfig {
        listen: addr,
        uuid: test_uuid,
        router: Arc::new(RouterHandle::new_mock()),
        reality: None,
        multiplex: multiplex_config,
        transport_layer: None,
    };

    tokio::spawn(async move {
        if let Err(e) = sb_adapters::inbound::vless::serve(config, stop_rx).await {
            eprintln!("VLESS server error: {}", e);
        }
    });

    tokio::time::sleep(Duration::from_millis(200)).await;
    (addr, test_uuid, stop_tx)
}

#[tokio::test]
async fn test_vless_multiplex_single_stream() {
    // Start echo server as upstream target
    let echo_addr = start_echo_server().await;

    // Start VLESS server with Multiplex enabled
    let (vless_addr, test_uuid, _stop_tx) = start_vless_server(true).await;

    // Create VLESS client with Multiplex enabled
    let client_config = VlessConfig {
        server_addr: vless_addr,
        uuid: test_uuid,
        flow: FlowControl::None,
        encryption: Encryption::None,
        headers: Default::default(),
        timeout: Some(10),
        tcp_fast_open: false,
        transport_layer: TransportConfig::Tcp,
        multiplex: Some(MultiplexConfig {
            max_num_streams: 16,
            initial_stream_window: 256 * 1024,
            max_stream_window: 1024 * 1024,
            enable_keepalive: true,
            keepalive_interval: 30,
            max_connections: 4,
            max_streams_per_connection: 8,
            connection_idle_timeout: 300,
            padding: false,
            brutal: None,
        }),
        reality: None,
        ech: None,
    };

    let connector = VlessConnector::new(client_config);

    // Dial through VLESS to echo server
    let target = Target {
        host: echo_addr.ip().to_string(),
        port: echo_addr.port(),
        kind: TransportKind::Tcp,
    };

    let mut stream = connector
        .dial(target, DialOpts::default())
        .await
        .expect("Failed to dial through VLESS");

    // Send test data
    let test_data = b"Hello, VLESS with Multiplex!";
    stream.write_all(test_data).await.unwrap();

    // Read response
    let mut response = vec![0u8; test_data.len()];
    stream.read_exact(&mut response).await.unwrap();

    assert_eq!(response, test_data, "Echo response should match sent data");
}

#[tokio::test]
async fn test_vless_multiplex_concurrent_streams() {
    // Start echo server
    let echo_addr = start_echo_server().await;

    // Start VLESS server with Multiplex
    let (vless_addr, test_uuid, _stop_tx) = start_vless_server(true).await;

    // Create VLESS client with Multiplex
    let client_config = VlessConfig {
        server_addr: vless_addr,
        uuid: test_uuid,
        flow: FlowControl::None,
        encryption: Encryption::None,
        headers: Default::default(),
        timeout: Some(10),
        tcp_fast_open: false,
        transport_layer: TransportConfig::Tcp,
        multiplex: Some(MultiplexConfig {
            max_num_streams: 16,
            initial_stream_window: 256 * 1024,
            max_stream_window: 1024 * 1024,
            enable_keepalive: true,
            keepalive_interval: 30,
            max_connections: 4,
            max_streams_per_connection: 8,
            connection_idle_timeout: 300,
            padding: false,
            brutal: None,
        }),
        reality: None,
        ech: None,
    };

    let connector = Arc::new(VlessConnector::new(client_config));

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
async fn test_vless_multiplex_data_integrity() {
    // Start echo server
    let echo_addr = start_echo_server().await;

    // Start VLESS server with Multiplex
    let (vless_addr, test_uuid, _stop_tx) = start_vless_server(true).await;

    // Create VLESS client with Multiplex
    let client_config = VlessConfig {
        server_addr: vless_addr,
        uuid: test_uuid,
        flow: FlowControl::None,
        encryption: Encryption::None,
        headers: Default::default(),
        timeout: Some(10),
        tcp_fast_open: false,
        transport_layer: TransportConfig::Tcp,
        multiplex: Some(MultiplexConfig {
            max_num_streams: 16,
            initial_stream_window: 256 * 1024,
            max_stream_window: 1024 * 1024,
            enable_keepalive: true,
            keepalive_interval: 30,
            max_connections: 4,
            max_streams_per_connection: 8,
            connection_idle_timeout: 300,
            padding: false,
            brutal: None,
        }),
        reality: None,
        ech: None,
    };

    let connector = Arc::new(VlessConnector::new(client_config));

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
async fn test_vless_multiplex_vs_non_multiplex() {
    // Start echo server
    let echo_addr = start_echo_server().await;

    // Start VLESS server WITHOUT Multiplex
    let (vless_addr_no_mux, test_uuid1, _stop_tx1) = start_vless_server(false).await;

    // Start VLESS server WITH Multiplex
    let (vless_addr_mux, test_uuid2, _stop_tx2) = start_vless_server(true).await;

    // Test non-multiplex client
    {
        let client_config = VlessConfig {
            server_addr: vless_addr_no_mux,
            uuid: test_uuid1,
            flow: FlowControl::None,
            encryption: Encryption::None,
            headers: Default::default(),
            timeout: Some(10),
            tcp_fast_open: false,
            transport_layer: TransportConfig::Tcp,
            multiplex: None, // No multiplex
            reality: None,
            ech: None,
        };

        let connector = VlessConnector::new(client_config);

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
        let client_config = VlessConfig {
            server_addr: vless_addr_mux,
            uuid: test_uuid2,
            flow: FlowControl::None,
            encryption: Encryption::None,
            headers: Default::default(),
            timeout: Some(10),
            tcp_fast_open: false,
            transport_layer: TransportConfig::Tcp,
            multiplex: Some(MultiplexConfig {
                max_num_streams: 256,
                initial_stream_window: 256 * 1024,
                max_stream_window: 1024 * 1024,
                enable_keepalive: true,
                keepalive_interval: 30,
                max_connections: 4,
                max_streams_per_connection: 16,
                connection_idle_timeout: 300,
                padding: false,
                brutal: None,
            }),
            reality: None,
            ech: None,
        };

        let connector = VlessConnector::new(client_config);

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
async fn test_vless_multiplex_flow_control_modes() {
    // Start echo server
    let echo_addr = start_echo_server().await;

    // Start VLESS server with Multiplex
    let (vless_addr, test_uuid, _stop_tx) = start_vless_server(true).await;

    // Test with FlowControl::None
    {
        let client_config = VlessConfig {
            server_addr: vless_addr,
            uuid: test_uuid,
            flow: FlowControl::None,
            encryption: Encryption::None,
            headers: Default::default(),
            timeout: Some(10),
            tcp_fast_open: false,
            transport_layer: TransportConfig::Tcp,
            multiplex: Some(MultiplexConfig {
                max_num_streams: 256,
                initial_stream_window: 256 * 1024,
                max_stream_window: 1024 * 1024,
                enable_keepalive: true,
                keepalive_interval: 30,
                max_connections: 4,
                max_streams_per_connection: 16,
                connection_idle_timeout: 300,
                padding: false,
                brutal: None,
            }),
            reality: None,
            ech: None,
        };

        let connector = VlessConnector::new(client_config);

        let target = Target {
            host: echo_addr.ip().to_string(),
            port: echo_addr.port(),
            kind: TransportKind::Tcp,
        };

        let mut stream = connector
            .dial(target, DialOpts::default())
            .await
            .expect("Failed to dial with FlowControl::None");

        let test_data = b"FlowControl::None test";
        stream.write_all(test_data).await.unwrap();

        let mut response = vec![0u8; test_data.len()];
        stream.read_exact(&mut response).await.unwrap();

        assert_eq!(response, test_data);
    }
}
