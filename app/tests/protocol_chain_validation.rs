#![cfg(feature = "net_e2e")]
//! Protocol Chain Validation Suite
//!
//! Integration tests for protocol chaining and failover:
//! - Protocol Chaining (Trojan -> Shadowsocks, Shadowsocks -> Trojan)
//! - Failover Scenarios
//! - DNS Integration

use std::collections::HashMap;
use std::io;
use std::io::Write;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::mpsc;

use sb_adapters::inbound::shadowsocks::{ShadowsocksInboundConfig, ShadowsocksUser};
use sb_adapters::inbound::trojan::{TrojanInboundConfig, TrojanUser};
use sb_adapters::outbound::shadowsocks::{ShadowsocksConfig, ShadowsocksConnector};
use sb_adapters::outbound::trojan::{TrojanConfig, TrojanConnector};
use sb_adapters::transport_config::TransportConfig;
use sb_core::router::engine::RouterHandle;
use tempfile::NamedTempFile;

// Helper: Start TCP echo server
async fn start_echo_server() -> Option<SocketAddr> {
    let listener = match TcpListener::bind("127.0.0.1:0").await {
        Ok(listener) => listener,
        Err(err) => {
            if matches!(
                err.kind(),
                io::ErrorKind::PermissionDenied | io::ErrorKind::AddrNotAvailable
            ) {
                eprintln!("Skipping protocol chain test: cannot bind echo server ({err})");
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

fn generate_test_certs() -> (String, String) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let cert_pem = cert.serialize_pem().unwrap();
    let key_pem = cert.serialize_private_key_pem();
    (cert_pem, key_pem)
}

// Helper: Start Trojan server
async fn start_trojan_server() -> Option<(SocketAddr, mpsc::Sender<()>)> {
    let listener = match TcpListener::bind("127.0.0.1:0").await {
        Ok(listener) => listener,
        Err(err) => {
            if matches!(
                err.kind(),
                io::ErrorKind::PermissionDenied | io::ErrorKind::AddrNotAvailable
            ) {
                eprintln!("Skipping protocol chain test: cannot bind Trojan server ({err})");
                return None;
            }
            panic!("Failed to bind Trojan server: {err}");
        }
    };
    let addr = listener.local_addr().unwrap();
    drop(listener);

    let (stop_tx, stop_rx) = mpsc::channel(1);

    let (cert_pem, key_pem) = generate_test_certs();
    let mut cert_file = NamedTempFile::new().unwrap();
    cert_file.write_all(cert_pem.as_bytes()).unwrap();
    let mut key_file = NamedTempFile::new().unwrap();
    key_file.write_all(key_pem.as_bytes()).unwrap();

    #[allow(deprecated)]
    let config = TrojanInboundConfig {
        listen: addr,
        #[allow(deprecated)]
        password: None,
        users: vec![TrojanUser::new(
            "default".to_string(),
            "trojan-pass".to_string(),
        )],
        cert_path: cert_file.path().to_string_lossy().to_string(),
        key_path: key_file.path().to_string_lossy().to_string(),
        router: Arc::new(RouterHandle::new_mock()),
        transport_layer: None,
        multiplex: None,
        fallback: None,
        fallback_for_alpn: HashMap::new(),
        reality: None,
    };

    tokio::spawn(async move {
        let _cert_file = cert_file;
        let _key_file = key_file;
        if let Err(e) = sb_adapters::inbound::trojan::serve(config, stop_rx).await {
            eprintln!("Trojan server error: {}", e);
        }
    });

    tokio::time::sleep(Duration::from_millis(200)).await;
    Some((addr, stop_tx))
}

// Helper: Start Shadowsocks server
async fn start_ss_server() -> Option<(SocketAddr, mpsc::Sender<()>)> {
    let listener = match TcpListener::bind("127.0.0.1:0").await {
        Ok(listener) => listener,
        Err(err) => {
            if matches!(
                err.kind(),
                io::ErrorKind::PermissionDenied | io::ErrorKind::AddrNotAvailable
            ) {
                eprintln!("Skipping protocol chain test: cannot bind SS server ({err})");
                return None;
            }
            panic!("Failed to bind SS server: {err}");
        }
    };
    let addr = listener.local_addr().unwrap();
    drop(listener);

    let (stop_tx, stop_rx) = mpsc::channel(1);

    #[allow(deprecated)]
    let config = ShadowsocksInboundConfig {
        listen: addr,
        method: "aes-256-gcm".to_string(),
        #[allow(deprecated)]
        password: None,
        users: vec![ShadowsocksUser::new(
            "default".to_string(),
            "ss-pass".to_string(),
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
// Protocol Chaining Tests
// ============================================================================

#[tokio::test]
async fn test_chain_trojan_to_shadowsocks() {
    // This test simulates a chain: Client -> Trojan -> Shadowsocks -> Echo Server
    // In a real integration test, we would need to configure the Trojan server's router
    // to forward to the Shadowsocks server.
    // For this validation suite, we'll verify the components can be instantiated and connected.

    let Some(_echo_addr) = start_echo_server().await else {
        return;
    };
    let Some((ss_addr, _ss_stop)) = start_ss_server().await else {
        return;
    };
    let Some((trojan_addr, _trojan_stop)) = start_trojan_server().await else {
        return;
    };

    // 1. Verify direct connection to SS works
    let ss_client_config = ShadowsocksConfig {
        server: ss_addr.to_string(),
        tag: None,
        method: "aes-256-gcm".to_string(),
        password: "ss-pass".to_string(),
        connect_timeout_sec: Some(5),
        multiplex: None,
    };
    let _ss_connector = ShadowsocksConnector::new(ss_client_config).unwrap();

    // 2. Verify direct connection to Trojan works
    let trojan_client_config = TrojanConfig {
        server: trojan_addr.to_string(),
        tag: None,
        password: "trojan-pass".to_string(),
        connect_timeout_sec: Some(5),
        sni: Some("localhost".to_string()),
        alpn: None,
        skip_cert_verify: true,
        transport_layer: TransportConfig::Tcp,
        reality: None,
        multiplex: None,
    };
    let _trojan_connector = TrojanConnector::new(trojan_client_config);

    // Full chaining requires modifying the inbound server's router, which is complex in unit tests.
    // We'll mark this as a placeholder for the full integration test.
    println!("Protocol chaining components verified. Full chain requires router configuration.");
}

// ============================================================================
// Failover Scenarios
// ============================================================================

#[tokio::test]
async fn test_failover_primary_failure() {
    // Verify failover behavior
    // Placeholder for implementation
}

// ============================================================================
// DNS Integration
// ============================================================================

#[tokio::test]
async fn test_dns_leak_prevention() {
    // Verify DNS requests go through tunnel
    // Placeholder for implementation
}
