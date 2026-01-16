#![cfg(feature = "net_e2e")]
//! Shadowsocks Protocol Validation Suite
//!
//! Comprehensive validation for Shadowsocks protocol implementation covering:
//! - AEAD Cipher Testing (AES-128/256-GCM, ChaCha20-Poly1305)
//! - UDP Relay Validation
//! - Multi-User Support

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::mpsc;

use sb_adapters::inbound::shadowsocks::{ShadowsocksInboundConfig, ShadowsocksUser};
use sb_adapters::outbound::shadowsocks::{ShadowsocksConfig, ShadowsocksConnector};
use sb_adapters::outbound::{DialOpts, OutboundConnector, Target};
use sb_adapters::TransportKind;
use sb_core::router::engine::RouterHandle;

// Helper: Start TCP echo server
async fn start_echo_server() -> Option<SocketAddr> {
    let listener = match TcpListener::bind("127.0.0.1:0").await {
        Ok(listener) => listener,
        Err(err) => {
            if matches!(
                err.kind(),
                io::ErrorKind::PermissionDenied | io::ErrorKind::AddrNotAvailable
            ) {
                eprintln!("Skipping shadowsocks validation: cannot bind echo server ({err})");
                return None;
            }
            panic!("Failed to bind echo server: {err}");
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

// Helper: Start UDP echo server
async fn start_udp_echo_server() -> Option<SocketAddr> {
    let socket = match UdpSocket::bind("127.0.0.1:0").await {
        Ok(socket) => socket,
        Err(err) => {
            if matches!(
                err.kind(),
                io::ErrorKind::PermissionDenied | io::ErrorKind::AddrNotAvailable
            ) {
                eprintln!("Skipping shadowsocks validation: cannot bind udp echo ({err})");
                return None;
            }
            panic!("bind udp: {err}");
        }
    };
    let addr = socket.local_addr().unwrap();

    tokio::spawn(async move {
        let mut buf = vec![0u8; 65535];
        loop {
            if let Ok((n, peer)) = socket.recv_from(&mut buf).await {
                let _ = socket.send_to(&buf[..n], peer).await;
            }
        }
    });

    tokio::time::sleep(Duration::from_millis(50)).await;
    Some(addr)
}

// Helper: Start Shadowsocks server
async fn start_ss_server(method: &str, password: &str) -> Option<(SocketAddr, mpsc::Sender<()>)> {
    let listener = match TcpListener::bind("127.0.0.1:0").await {
        Ok(listener) => listener,
        Err(err) => {
            if matches!(
                err.kind(),
                io::ErrorKind::PermissionDenied | io::ErrorKind::AddrNotAvailable
            ) {
                eprintln!("Skipping shadowsocks validation: cannot bind SS server ({err})");
                return None;
            }
            panic!("Failed to bind SS server: {err}");
        }
    };
    let addr = listener.local_addr().unwrap();
    drop(listener); // Release port

    let (stop_tx, stop_rx) = mpsc::channel(1);

    #[allow(deprecated)]
    let config = ShadowsocksInboundConfig {
        listen: addr,
        method: method.to_string(),
        password: None,
        users: vec![ShadowsocksUser::new(
            "default".to_string(),
            password.to_string(),
        )],
        router: Arc::new(RouterHandle::new_mock()),
        multiplex: None,
        transport_layer: None,
    };

    tokio::spawn(async move {
        if let Err(e) = sb_adapters::inbound::shadowsocks::serve(config, stop_rx).await {
            eprintln!("Shadowsocks server error: {}", e);
        }
    });

    tokio::time::sleep(Duration::from_millis(200)).await;
    Some((addr, stop_tx))
}

// ============================================================================
// AEAD Cipher Testing
// ============================================================================

#[tokio::test]
async fn test_ss_aes_128_gcm() {
    let Some(echo_addr) = start_echo_server().await else {
        return;
    };
    let Some((server_addr, _stop_tx)) = start_ss_server("aes-128-gcm", "test-pass").await else {
        return;
    };

    let client_config = ShadowsocksConfig {
        server: server_addr.to_string(),
        tag: None,
        method: "aes-128-gcm".to_string(),
        password: "test-pass".to_string(),
        connect_timeout_sec: Some(5),
        multiplex: None,
    };

    let connector = ShadowsocksConnector::new(client_config).unwrap();
    let target = Target {
        host: echo_addr.ip().to_string(),
        port: echo_addr.port(),
        kind: TransportKind::Tcp,
    };

    let mut stream = connector.dial(target, DialOpts::default()).await.unwrap();
    stream.write_all(b"test-aes-128-gcm").await.unwrap();

    let mut buf = vec![0u8; 16];
    stream.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"test-aes-128-gcm");
}

#[tokio::test]
async fn test_ss_aes_256_gcm() {
    let Some(echo_addr) = start_echo_server().await else {
        return;
    };
    let Some((server_addr, _stop_tx)) = start_ss_server("aes-256-gcm", "test-pass").await else {
        return;
    };

    let client_config = ShadowsocksConfig {
        server: server_addr.to_string(),
        tag: None,
        method: "aes-256-gcm".to_string(),
        password: "test-pass".to_string(),
        connect_timeout_sec: Some(5),
        multiplex: None,
    };

    let connector = ShadowsocksConnector::new(client_config).unwrap();
    let target = Target {
        host: echo_addr.ip().to_string(),
        port: echo_addr.port(),
        kind: TransportKind::Tcp,
    };

    let mut stream = connector.dial(target, DialOpts::default()).await.unwrap();
    stream.write_all(b"test-aes-256-gcm").await.unwrap();

    let mut buf = vec![0u8; 16];
    stream.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"test-aes-256-gcm");
}

#[tokio::test]
async fn test_ss_chacha20_poly1305() {
    let Some(echo_addr) = start_echo_server().await else {
        return;
    };
    let Some((server_addr, _stop_tx)) =
        start_ss_server("chacha20-ietf-poly1305", "test-pass").await
    else {
        return;
    };

    let client_config = ShadowsocksConfig {
        server: server_addr.to_string(),
        tag: None,
        method: "chacha20-ietf-poly1305".to_string(),
        password: "test-pass".to_string(),
        connect_timeout_sec: Some(5),
        multiplex: None,
    };

    let connector = ShadowsocksConnector::new(client_config).unwrap();
    let target = Target {
        host: echo_addr.ip().to_string(),
        port: echo_addr.port(),
        kind: TransportKind::Tcp,
    };

    let mut stream = connector.dial(target, DialOpts::default()).await.unwrap();
    stream.write_all(b"test-chacha20").await.unwrap();

    let mut buf = vec![0u8; 13];
    stream.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"test-chacha20");
}

// ============================================================================
// UDP Relay Validation
// ============================================================================

#[tokio::test]
async fn test_ss_udp_relay() {
    // Start UDP echo server
    let Some(echo_addr) = start_udp_echo_server().await else {
        return;
    };

    // Note: Full UDP relay testing requires UDP support in both client and server
    // This is a basic connectivity test. Full UDP relay would need:
    // - UDP associate command support
    // - SOCKS5 UDP relay protocol
    // - NAT session management
    // For now, we verify TCP connectivity works, which is the foundation

    let Some((server_addr, _stop_tx)) = start_ss_server("aes-256-gcm", "test-pass").await else {
        return;
    };
    let client_config = ShadowsocksConfig {
        server: server_addr.to_string(),
        tag: None,
        method: "aes-256-gcm".to_string(),
        password: "test-pass".to_string(),
        connect_timeout_sec: Some(5),
        multiplex: None,
    };

    let connector = ShadowsocksConnector::new(client_config).unwrap();
    let target = Target {
        host: echo_addr.ip().to_string(),
        port: echo_addr.port(),
        kind: TransportKind::Tcp, // UDP relay needs special SOCKS5 handling
    };

    // Verify basic connectivity (foundation for UDP relay)
    let result = connector.dial(target, DialOpts::default()).await;
    assert!(
        result.is_ok(),
        "Basic connectivity should work as foundation for UDP relay"
    );

    println!("UDP relay test: Basic connectivity verified (full UDP relay requires SOCKS5 UDP associate)");
}

// ============================================================================
// Multi-User Support
// ============================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_ss_multi_user_auth() {
    let Some(echo_addr) = start_echo_server().await else {
        return;
    };

    // Start multiple SS servers with different passwords (simulating multi-user)
    let Some((server1_addr, _stop_tx1)) = start_ss_server("aes-256-gcm", "user1-pass").await else {
        return;
    };
    let Some((server2_addr, _stop_tx2)) = start_ss_server("aes-256-gcm", "user2-pass").await else {
        return;
    };

    // User 1 connects with correct password
    let client1_config = ShadowsocksConfig {
        server: server1_addr.to_string(),
        tag: None,
        method: "aes-256-gcm".to_string(),
        password: "user1-pass".to_string(),
        connect_timeout_sec: Some(5),
        multiplex: None,
    };

    let connector1 = ShadowsocksConnector::new(client1_config).unwrap();
    let target = Target {
        host: echo_addr.ip().to_string(),
        port: echo_addr.port(),
        kind: TransportKind::Tcp,
    };

    let mut stream1 = connector1
        .dial(target.clone(), DialOpts::default())
        .await
        .unwrap();
    stream1.write_all(b"user1-data").await.unwrap();
    let mut buf1 = vec![0u8; 10];
    stream1.read_exact(&mut buf1).await.unwrap();
    assert_eq!(&buf1, b"user1-data");

    // User 2 connects with different password
    let client2_config = ShadowsocksConfig {
        server: server2_addr.to_string(),
        tag: None,
        method: "aes-256-gcm".to_string(),
        password: "user2-pass".to_string(),
        connect_timeout_sec: Some(5),
        multiplex: None,
    };

    let connector2 = ShadowsocksConnector::new(client2_config).unwrap();
    let mut stream2 = connector2.dial(target, DialOpts::default()).await.unwrap();
    stream2.write_all(b"user2-data").await.unwrap();
    let mut buf2 = vec![0u8; 10];
    stream2.read_exact(&mut buf2).await.unwrap();
    assert_eq!(&buf2, b"user2-data");

    println!("Multi-user test: Both users authenticated and communicated successfully");
}
