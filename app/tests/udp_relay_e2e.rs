//! E2E test for UDP relay support
//!
//! Tests that Shadowsocks, Trojan, and VLESS protocols correctly support UDP relay,
//! allowing UDP traffic to be proxied through these protocols.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use uuid::Uuid;

// Import adapters
use sb_adapters::inbound::shadowsocks::ShadowsocksInboundConfig;
use sb_adapters::inbound::trojan::TrojanInboundConfig;
use sb_adapters::inbound::vless::VlessInboundConfig;
use sb_adapters::outbound::shadowsocks::{ShadowsocksConfig, ShadowsocksConnector};
use sb_adapters::outbound::trojan::{TrojanConfig, TrojanConnector};
use sb_adapters::outbound::vless::{Encryption, FlowControl, VlessConfig, VlessConnector};
use sb_adapters::traits::{OutboundDatagram, Target, TransportKind};
use sb_core::router::engine::RouterHandle;

/// Helper: Start UDP echo server
async fn start_udp_echo_server() -> SocketAddr {
    let socket = UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("Failed to bind UDP echo server");
    let addr = socket.local_addr().unwrap();

    tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        loop {
            if let Ok((n, peer)) = socket.recv_from(&mut buf).await {
                let _ = socket.send_to(&buf[..n], peer).await;
            }
        }
    });

    tokio::time::sleep(Duration::from_millis(50)).await;
    addr
}

/// Helper: Start Shadowsocks server
async fn start_shadowsocks_server() -> (SocketAddr, mpsc::Sender<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("Failed to bind Shadowsocks server");
    let addr = listener.local_addr().unwrap();
    drop(listener);

    let (stop_tx, stop_rx) = mpsc::channel(1);

    let config = ShadowsocksInboundConfig {
        listen: addr,
        method: "aes-256-gcm".to_string(),
        password: "test-password-udp".to_string(),
        router: Arc::new(RouterHandle::new_mock()),
        multiplex: None,
    };

    tokio::spawn(async move {
        if let Err(e) = sb_adapters::inbound::shadowsocks::serve(config, stop_rx).await {
            eprintln!("Shadowsocks server error: {}", e);
        }
    });

    tokio::time::sleep(Duration::from_millis(200)).await;
    (addr, stop_tx)
}

/// Helper: Start Trojan server
async fn start_trojan_server() -> (SocketAddr, mpsc::Sender<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("Failed to bind Trojan server");
    let addr = listener.local_addr().unwrap();
    drop(listener);

    let (stop_tx, stop_rx) = mpsc::channel(1);

    let config = TrojanInboundConfig {
        listen: addr,
        password: "test-trojan-udp".to_string(),
        router: Arc::new(RouterHandle::new_mock()),
        multiplex: None,
        tls: None,
    };

    tokio::spawn(async move {
        if let Err(e) = sb_adapters::inbound::trojan::serve(config, stop_rx).await {
            eprintln!("Trojan server error: {}", e);
        }
    });

    tokio::time::sleep(Duration::from_millis(200)).await;
    (addr, stop_tx)
}

/// Helper: Start VLESS server
async fn start_vless_server() -> (SocketAddr, Uuid, mpsc::Sender<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("Failed to bind VLESS server");
    let addr = listener.local_addr().unwrap();
    drop(listener);

    let (stop_tx, stop_rx) = mpsc::channel(1);
    let test_uuid = Uuid::new_v4();

    let config = VlessInboundConfig {
        listen: addr,
        users: vec![test_uuid],
        router: Arc::new(RouterHandle::new_mock()),
        multiplex: None,
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
async fn test_shadowsocks_udp_relay() {
    // Start UDP echo server
    let echo_addr = start_udp_echo_server().await;

    // Start Shadowsocks server
    let (ss_addr, _stop_tx) = start_shadowsocks_server().await;

    // Create Shadowsocks connector
    let config = ShadowsocksConfig {
        server: ss_addr.to_string(),
        tag: None,
        method: "aes-256-gcm".to_string(),
        password: "test-password-udp".to_string(),
        connect_timeout_sec: Some(10),
        multiplex: None,
    };

    let connector =
        ShadowsocksConnector::new(config).expect("Failed to create Shadowsocks connector");

    // Create UDP relay
    let target = Target {
        host: echo_addr.ip().to_string(),
        port: echo_addr.port(),
        kind: TransportKind::Udp,
    };

    let udp_socket = connector
        .udp_relay_dial(target.clone())
        .await
        .expect("Failed to create UDP relay");

    // Set target for subsequent operations
    if let Some(ss_udp) = udp_socket
        .as_any()
        .downcast_ref::<sb_adapters::outbound::shadowsocks::ShadowsocksUdpSocket>(
    ) {
        ss_udp.set_target(target).await;
    }

    // Send test data
    let test_data = b"Hello, Shadowsocks UDP!";
    let sent = udp_socket
        .send_to(test_data)
        .await
        .expect("Failed to send UDP data");

    assert_eq!(sent, test_data.len());

    // Receive response
    let mut recv_buf = vec![0u8; 4096];
    let recv_len = udp_socket
        .recv_from(&mut recv_buf)
        .await
        .expect("Failed to receive UDP data");

    assert_eq!(&recv_buf[..recv_len], test_data);
}

#[tokio::test]
async fn test_trojan_udp_relay() {
    // Start UDP echo server
    let echo_addr = start_udp_echo_server().await;

    // Start Trojan server
    let (trojan_addr, _stop_tx) = start_trojan_server().await;

    // Create Trojan connector
    let config = TrojanConfig {
        server: trojan_addr.to_string(),
        tag: None,
        password: "test-trojan-udp".to_string(),
        connect_timeout_sec: Some(10),
        sni: None,
        skip_cert_verify: true,
        #[cfg(feature = "tls_reality")]
        reality: None,
        multiplex: None,
    };

    let connector = TrojanConnector::new(config);

    // Create UDP relay
    let target = Target {
        host: echo_addr.ip().to_string(),
        port: echo_addr.port(),
        kind: TransportKind::Udp,
    };

    let udp_socket = connector
        .udp_relay_dial(target.clone())
        .await
        .expect("Failed to create UDP relay");

    // Set target for subsequent operations
    if let Some(trojan_udp) = udp_socket
        .as_any()
        .downcast_ref::<sb_adapters::outbound::trojan::TrojanUdpSocket>()
    {
        trojan_udp.set_target(target).await;
    }

    // Send test data
    let test_data = b"Hello, Trojan UDP!";
    let sent = udp_socket
        .send_to(test_data)
        .await
        .expect("Failed to send UDP data");

    assert_eq!(sent, test_data.len());

    // Receive response
    let mut recv_buf = vec![0u8; 4096];
    let recv_len = udp_socket
        .recv_from(&mut recv_buf)
        .await
        .expect("Failed to receive UDP data");

    assert_eq!(&recv_buf[..recv_len], test_data);
}

#[tokio::test]
async fn test_vless_udp_relay() {
    // Start UDP echo server
    let echo_addr = start_udp_echo_server().await;

    // Start VLESS server
    let (vless_addr, test_uuid, _stop_tx) = start_vless_server().await;

    // Create VLESS connector
    let config = VlessConfig {
        server_addr: vless_addr,
        uuid: test_uuid,
        flow: FlowControl::None,
        encryption: Encryption::None,
        headers: Default::default(),
        timeout: Some(10),
        tcp_fast_open: false,
        multiplex: None,
        #[cfg(feature = "tls_reality")]
        reality: None,
        #[cfg(feature = "transport_ech")]
        ech: None,
    };

    let connector = VlessConnector::new(config);

    // Create UDP relay
    let target = Target {
        host: echo_addr.ip().to_string(),
        port: echo_addr.port(),
        kind: TransportKind::Udp,
    };

    let udp_socket = connector
        .udp_relay_dial(target.clone())
        .await
        .expect("Failed to create UDP relay");

    // Set target for subsequent operations
    if let Some(vless_udp) = udp_socket
        .as_any()
        .downcast_ref::<sb_adapters::outbound::vless::VlessUdpSocket>()
    {
        vless_udp.set_target(target).await;
    }

    // Send test data
    let test_data = b"Hello, VLESS UDP!";
    let sent = udp_socket
        .send_to(test_data)
        .await
        .expect("Failed to send UDP data");

    assert_eq!(sent, test_data.len());

    // Receive response
    let mut recv_buf = vec![0u8; 4096];
    let recv_len = udp_socket
        .recv_from(&mut recv_buf)
        .await
        .expect("Failed to receive UDP data");

    assert_eq!(&recv_buf[..recv_len], test_data);
}

#[tokio::test]
async fn test_shadowsocks_udp_large_packet() {
    // Start UDP echo server
    let echo_addr = start_udp_echo_server().await;

    // Start Shadowsocks server
    let (ss_addr, _stop_tx) = start_shadowsocks_server().await;

    // Create Shadowsocks connector
    let config = ShadowsocksConfig {
        server: ss_addr.to_string(),
        tag: None,
        method: "chacha20-poly1305".to_string(),
        password: "test-password-udp".to_string(),
        connect_timeout_sec: Some(10),
        multiplex: None,
    };

    let connector =
        ShadowsocksConnector::new(config).expect("Failed to create Shadowsocks connector");

    // Create UDP relay
    let target = Target {
        host: echo_addr.ip().to_string(),
        port: echo_addr.port(),
        kind: TransportKind::Udp,
    };

    let udp_socket = connector
        .udp_relay_dial(target.clone())
        .await
        .expect("Failed to create UDP relay");

    if let Some(ss_udp) = udp_socket
        .as_any()
        .downcast_ref::<sb_adapters::outbound::shadowsocks::ShadowsocksUdpSocket>(
    ) {
        ss_udp.set_target(target).await;
    }

    // Test with large packet (1400 bytes, typical UDP MTU)
    let test_data = vec![0xAB as u8; 1400];
    let sent = udp_socket
        .send_to(&test_data)
        .await
        .expect("Failed to send large UDP packet");

    assert_eq!(sent, test_data.len());

    // Receive response
    let mut recv_buf = vec![0u8; 4096];
    let recv_len = udp_socket
        .recv_from(&mut recv_buf)
        .await
        .expect("Failed to receive large UDP packet");

    assert_eq!(&recv_buf[..recv_len], &test_data[..]);
}

#[tokio::test]
async fn test_udp_relay_multiple_packets() {
    // Start UDP echo server
    let echo_addr = start_udp_echo_server().await;

    // Start Shadowsocks server
    let (ss_addr, _stop_tx) = start_shadowsocks_server().await;

    // Create Shadowsocks connector
    let config = ShadowsocksConfig {
        server: ss_addr.to_string(),
        tag: None,
        method: "aes-256-gcm".to_string(),
        password: "test-password-udp".to_string(),
        connect_timeout_sec: Some(10),
        multiplex: None,
    };

    let connector =
        ShadowsocksConnector::new(config).expect("Failed to create Shadowsocks connector");

    // Create UDP relay
    let target = Target {
        host: echo_addr.ip().to_string(),
        port: echo_addr.port(),
        kind: TransportKind::Udp,
    };

    let udp_socket = connector
        .udp_relay_dial(target.clone())
        .await
        .expect("Failed to create UDP relay");

    if let Some(ss_udp) = udp_socket
        .as_any()
        .downcast_ref::<sb_adapters::outbound::shadowsocks::ShadowsocksUdpSocket>(
    ) {
        ss_udp.set_target(target).await;
    }

    // Send multiple packets
    for i in 0..10 {
        let test_data = format!("Packet {}", i);
        let _ = udp_socket
            .send_to(test_data.as_bytes())
            .await
            .expect("Failed to send UDP packet");

        let mut recv_buf = vec![0u8; 4096];
        let recv_len = udp_socket
            .recv_from(&mut recv_buf)
            .await
            .expect("Failed to receive UDP packet");

        assert_eq!(&recv_buf[..recv_len], test_data.as_bytes());
    }
}

#[tokio::test]
async fn test_udp_relay_concurrent_operations() {
    // Start UDP echo server
    let echo_addr = start_udp_echo_server().await;

    // Start Shadowsocks server
    let (ss_addr, _stop_tx) = start_shadowsocks_server().await;

    // Create multiple UDP relays concurrently
    let mut handles = vec![];
    for i in 0..5 {
        let ss_addr_clone = ss_addr;
        let echo_addr_clone = echo_addr;

        let handle = tokio::spawn(async move {
            let config = ShadowsocksConfig {
                server: ss_addr_clone.to_string(),
                tag: None,
                method: "aes-256-gcm".to_string(),
                password: "test-password-udp".to_string(),
                connect_timeout_sec: Some(10),
                multiplex: None,
            };

            let connector = ShadowsocksConnector::new(config).unwrap();

            let target = Target {
                host: echo_addr_clone.ip().to_string(),
                port: echo_addr_clone.port(),
                kind: TransportKind::Udp,
            };

            let udp_socket = connector.udp_relay_dial(target.clone()).await.unwrap();

            if let Some(ss_udp) = udp_socket
                .as_any()
                .downcast_ref::<sb_adapters::outbound::shadowsocks::ShadowsocksUdpSocket>(
            ) {
                ss_udp.set_target(target).await;
            }

            let test_data = format!("Concurrent {}", i);
            udp_socket.send_to(test_data.as_bytes()).await.unwrap();

            let mut recv_buf = vec![0u8; 4096];
            let recv_len = udp_socket.recv_from(&mut recv_buf).await.unwrap();

            assert_eq!(&recv_buf[..recv_len], test_data.as_bytes());
        });

        handles.push(handle);
    }

    // Wait for all concurrent operations
    for handle in handles {
        handle.await.unwrap();
    }
}
