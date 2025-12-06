#![allow(clippy::unwrap_used, clippy::expect_used)]
//! End-to-end integration tests for proxy flow
//!
//! Tests the complete flow: Inbound → Router → Outbound
//!
//! Test scenarios:
//! - SOCKS5 inbound → router → direct outbound
//! - HTTP inbound → router → direct outbound
//! - Mixed inbound → router with rules → selector outbound

#![cfg(all(feature = "http", feature = "socks"))]

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener as StdListener};
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, oneshot};
use tokio::time::timeout;

use sb_adapters::inbound::http::{serve_http, HttpProxyConfig};
use sb_adapters::inbound::socks::{serve_socks, SocksInboundConfig};
use sb_core::outbound::{OutboundImpl, OutboundKind, OutboundRegistry, OutboundRegistryHandle};
use sb_core::router::{Router, RouterHandle};

/// Start a simple echo server for testing
fn start_echo_server() -> SocketAddr {
    let listener = StdListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    thread::spawn(move || {
        for mut s in listener.incoming().flatten() {
            thread::spawn(move || {
                let mut buf = [0u8; 4096];
                loop {
                    match s.read(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            let _ = s.write_all(&buf[..n]);
                        }
                    }
                }
            });
        }
    });

    // Wait for server to be ready
    thread::sleep(Duration::from_millis(50));
    addr
}

/// Build outbound registry and router with direct connection
fn build_direct_proxy() -> (Arc<OutboundRegistryHandle>, Arc<RouterHandle>) {
    let mut map = std::collections::HashMap::new();
    map.insert("direct".to_string(), OutboundImpl::Direct);
    let registry = OutboundRegistry::new(map);

    let router = Router::with_default(OutboundKind::Direct);
    // No rules: default to direct connection

    (
        Arc::new(OutboundRegistryHandle::new(registry)),
        Arc::new(RouterHandle::new(router)),
    )
}

/// Start SOCKS5 inbound server
async fn start_socks5_inbound(
    router: Arc<RouterHandle>,
    outbounds: Arc<OutboundRegistryHandle>,
) -> (SocketAddr, mpsc::Sender<()>) {
    let (stop_tx, stop_rx) = mpsc::channel(1);
    let (ready_tx, ready_rx) = oneshot::channel();

    // Bind to get a free port
    let temp_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = temp_listener.local_addr().unwrap();
    drop(temp_listener); // Release it immediately

    // Wait for OS to release the port
    tokio::time::sleep(Duration::from_millis(200)).await;

    let cfg = SocksInboundConfig {
        listen: addr,
        udp_bind: None,
        router,
        outbounds,
        udp_nat_ttl: Duration::from_secs(60),
        users: None,
    };

    tokio::spawn(async move {
        let _ = serve_socks(cfg, stop_rx, Some(ready_tx)).await;
    });

    // Wait for server to signal it's ready
    ready_rx.await.expect("Server failed to start");

    (addr, stop_tx)
}

/// Start HTTP CONNECT inbound server
async fn start_http_inbound(
    router: Arc<RouterHandle>,
    outbounds: Arc<OutboundRegistryHandle>,
) -> (SocketAddr, mpsc::Sender<()>) {
    let (stop_tx, stop_rx) = mpsc::channel(1);
    let (ready_tx, ready_rx) = oneshot::channel();

    // Bind to get a free port
    let temp_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = temp_listener.local_addr().unwrap();
    drop(temp_listener); // Release it immediately

    // Wait for OS to release the port
    tokio::time::sleep(Duration::from_millis(200)).await;

    let cfg = HttpProxyConfig {
        listen: addr,
        router,
        outbounds: outbounds.clone(),
        tls: None,
        users: None,
    };

    tokio::spawn(async move {
        let _ = serve_http(cfg, stop_rx, Some(ready_tx)).await;
    });

    // Wait for server to signal it's ready
    ready_rx.await.expect("Server failed to start");

    (addr, stop_tx)
}

/// Test SOCKS5 inbound → direct outbound flow
#[tokio::test(flavor = "multi_thread")]
async fn test_e2e_socks5_to_direct() {
    // Setup echo server as upstream target
    let echo_addr = start_echo_server();

    // Build proxy infrastructure
    let (outbounds, router) = build_direct_proxy();

    // Start SOCKS5 inbound
    let (socks_addr, _stop_handle) = start_socks5_inbound(router, outbounds).await;

    // Connect via SOCKS5 client
    let mut stream = TcpStream::connect(socks_addr).await.unwrap();

    // SOCKS5 handshake: NO_AUTH
    // Client greeting: VER (0x05) + NMETHODS (0x01) + METHODS (0x00 = NO_AUTH)
    stream.write_all(&[0x05, 0x01, 0x00]).await.unwrap();

    // Server response: VER (0x05) + METHOD (0x00 = NO_AUTH)
    let mut buf = [0u8; 2];
    timeout(Duration::from_secs(2), stream.read_exact(&mut buf))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(buf, [0x05, 0x00]);

    // SOCKS5 CONNECT request
    // VER (0x05) + CMD (0x01 = CONNECT) + RSV (0x00) + ATYP (0x01 = IPv4)
    let mut req = vec![0x05, 0x01, 0x00, 0x01];
    // IPv4 address (4 bytes)
    match echo_addr.ip() {
        std::net::IpAddr::V4(ip) => req.extend_from_slice(&ip.octets()),
        _ => panic!("Expected IPv4 address"),
    }
    // Port (2 bytes, big-endian)
    req.extend_from_slice(&echo_addr.port().to_be_bytes());

    stream.write_all(&req).await.unwrap();

    // Server response: VER + REP + RSV + ATYP + BIND_ADDR + BIND_PORT
    let mut resp = [0u8; 10];
    timeout(Duration::from_secs(2), stream.read_exact(&mut resp))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(resp[0], 0x05); // VER
    assert_eq!(resp[1], 0x00); // REP = succeeded

    // Test data transmission through the tunnel
    let test_data = b"Hello from SOCKS5 client!";
    stream.write_all(test_data).await.unwrap();

    let mut echo_back = vec![0u8; test_data.len()];
    timeout(Duration::from_secs(2), stream.read_exact(&mut echo_back))
        .await
        .unwrap()
        .unwrap();

    assert_eq!(&echo_back[..], test_data);
}

/// Test HTTP CONNECT inbound → direct outbound flow
#[tokio::test(flavor = "multi_thread")]
async fn test_e2e_http_to_direct() {
    // Setup echo server as upstream target
    let echo_addr = start_echo_server();

    // Build proxy infrastructure
    let (outbounds, router) = build_direct_proxy();

    // Start HTTP inbound
    let (http_addr, _stop_handle) = start_http_inbound(router, outbounds).await;

    // Connect via HTTP CONNECT client
    let mut stream = TcpStream::connect(http_addr).await.unwrap();

    // HTTP CONNECT request
    let request = format!(
        "CONNECT {}:{} HTTP/1.1\r\nHost: {}:{}\r\n\r\n",
        echo_addr.ip(),
        echo_addr.port(),
        echo_addr.ip(),
        echo_addr.port()
    );
    stream.write_all(request.as_bytes()).await.unwrap();

    // Read HTTP response
    let mut resp_buf = vec![0u8; 1024];
    let n = timeout(Duration::from_secs(2), stream.read(&mut resp_buf))
        .await
        .unwrap()
        .unwrap();

    let response = String::from_utf8_lossy(&resp_buf[..n]);
    assert!(
        response.starts_with("HTTP/1.1 200"),
        "Expected 200 OK, got: {}",
        response
    );

    // Test data transmission through the tunnel
    let test_data = b"Hello from HTTP CONNECT client!";
    stream.write_all(test_data).await.unwrap();

    let mut echo_back = vec![0u8; test_data.len()];
    timeout(Duration::from_secs(2), stream.read_exact(&mut echo_back))
        .await
        .unwrap()
        .unwrap();

    assert_eq!(&echo_back[..], test_data);
}

/// Test large data transfer through proxy
#[tokio::test(flavor = "multi_thread")]
async fn test_e2e_large_data_transfer() {
    // Setup echo server
    let echo_addr = start_echo_server();

    // Build proxy
    let (outbounds, router) = build_direct_proxy();

    // Start SOCKS5 inbound
    let (socks_addr, _stop_handle) = start_socks5_inbound(router, outbounds).await;

    // Connect and do SOCKS5 handshake
    let mut stream = TcpStream::connect(socks_addr).await.unwrap();

    // SOCKS5 handshake
    stream.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut buf = [0u8; 2];
    stream.read_exact(&mut buf).await.unwrap();

    // SOCKS5 CONNECT
    let mut req = vec![0x05, 0x01, 0x00, 0x01];
    match echo_addr.ip() {
        std::net::IpAddr::V4(ip) => req.extend_from_slice(&ip.octets()),
        _ => panic!("Expected IPv4"),
    }
    req.extend_from_slice(&echo_addr.port().to_be_bytes());
    stream.write_all(&req).await.unwrap();

    let mut resp = [0u8; 10];
    stream.read_exact(&mut resp).await.unwrap();

    // Test large data transfer (1MB)
    let large_data = vec![0xAB; 1024 * 1024];
    stream.write_all(&large_data).await.unwrap();

    let mut echo_back = vec![0u8; large_data.len()];
    timeout(Duration::from_secs(10), stream.read_exact(&mut echo_back))
        .await
        .unwrap()
        .unwrap();

    assert_eq!(echo_back, large_data);
}

/// Test concurrent connections through proxy
#[tokio::test(flavor = "multi_thread")]
async fn test_e2e_concurrent_connections() {
    // Setup echo server
    let echo_addr = start_echo_server();

    // Build proxy
    let (outbounds, router) = build_direct_proxy();

    // Start SOCKS5 inbound
    let (socks_addr, _stop_handle) = start_socks5_inbound(router, outbounds).await;

    // Create 10 concurrent connections
    let mut handles = vec![];

    for i in 0..10 {
        let handle = tokio::spawn(async move {
            let mut stream = TcpStream::connect(socks_addr).await.unwrap();

            // SOCKS5 handshake
            stream.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
            let mut buf = [0u8; 2];
            stream.read_exact(&mut buf).await.unwrap();

            // SOCKS5 CONNECT
            let mut req = vec![0x05, 0x01, 0x00, 0x01];
            match echo_addr.ip() {
                std::net::IpAddr::V4(ip) => req.extend_from_slice(&ip.octets()),
                _ => panic!("Expected IPv4"),
            }
            req.extend_from_slice(&echo_addr.port().to_be_bytes());
            stream.write_all(&req).await.unwrap();

            let mut resp = [0u8; 10];
            stream.read_exact(&mut resp).await.unwrap();

            // Test unique data for each connection
            let test_data = format!("Connection {}", i);
            stream.write_all(test_data.as_bytes()).await.unwrap();

            let mut echo_back = vec![0u8; test_data.len()];
            stream.read_exact(&mut echo_back).await.unwrap();

            assert_eq!(String::from_utf8_lossy(&echo_back), test_data);
        });

        handles.push(handle);
    }

    // Wait for all connections to complete
    for handle in handles {
        timeout(Duration::from_secs(5), handle)
            .await
            .unwrap()
            .unwrap();
    }
}
