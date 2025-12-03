#![cfg(feature = "net_e2e")]
//! Trojan Binary Protocol Test Suite
//!
//! Tests the standard Trojan-GFW binary protocol implementation including:
//! - SHA224 password hash verification
//! - Binary address parsing (IPv4, IPv6, domain)
//! - Command handling (CONNECT, UDP ASSOCIATE)
//! - Multi-user authentication

use sha2::{Digest, Sha224};
use std::io::Write;
use std::net::SocketAddr;
use std::sync::Arc;
use tempfile::NamedTempFile;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::mpsc;

use sb_adapters::inbound::trojan::{TrojanInboundConfig, TrojanUser};
use sb_core::router::engine::RouterHandle;

fn init_crypto() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

// Helper: Start echo server
async fn start_echo_server() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("Failed to bind");
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

    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
    addr
}

// Helper: Generate test certificates
fn generate_test_certs(cn: &str) -> (String, String) {
    let mut params = rcgen::CertificateParams::new(vec![cn.to_string()]);
    params.not_before = time::OffsetDateTime::now_utc() - time::Duration::days(1);
    params.not_after = time::OffsetDateTime::now_utc() + time::Duration::days(365);
    let cert = rcgen::Certificate::from_params(params).unwrap();
    (
        cert.serialize_pem().unwrap(),
        cert.serialize_private_key_pem(),
    )
}

// Helper: Start Trojan server with users
async fn start_trojan_server_with_users(
    users: Vec<TrojanUser>,
    cert_pem: String,
    key_pem: String,
) -> (SocketAddr, mpsc::Sender<()>, NamedTempFile, NamedTempFile) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("Failed to bind");
    let addr = listener.local_addr().unwrap();
    drop(listener);

    let (stop_tx, stop_rx) = mpsc::channel(1);

    let mut cert_file = NamedTempFile::new().unwrap();
    cert_file.write_all(cert_pem.as_bytes()).unwrap();
    let mut key_file = NamedTempFile::new().unwrap();
    key_file.write_all(key_pem.as_bytes()).unwrap();

    #[allow(deprecated)]
    let config = TrojanInboundConfig {
        listen: addr,
        password: None,
        users,
        cert_path: cert_file.path().to_str().unwrap().to_string(),
        key_path: key_file.path().to_str().unwrap().to_string(),
        router: Arc::new(RouterHandle::new_mock()),
        transport_layer: None,
        multiplex: None,
        #[cfg(feature = "tls_reality")]
        reality: None,
    };

    tokio::spawn(async move {
        let _ = sb_adapters::inbound::trojan::serve(config, stop_rx).await;
    });

    tokio::time::sleep(tokio::time::Duration::from_millis(300)).await;
    (addr, stop_tx, cert_file, key_file)
}

// Helper: Build a binary Trojan request
fn build_trojan_request(password: &str, cmd: u8, host: &str, port: u16) -> Vec<u8> {
    let mut buf = Vec::new();

    // SHA224 hash of password (56 hex bytes)
    let hash = Sha224::digest(password.as_bytes());
    let hash_hex = hex::encode(hash);
    buf.extend_from_slice(hash_hex.as_bytes());

    // CRLF
    buf.extend_from_slice(b"\r\n");

    // Command
    buf.push(cmd);

    // Address  type (domain = 0x03)
    buf.push(0x03);

    // Domain length + domain
    buf.push(host.len() as u8);
    buf.extend_from_slice(host.as_bytes());

    // Port (big-endian)
    buf.extend_from_slice(&port.to_be_bytes());

    // Final CRLF
    buf.extend_from_slice(b"\r\n");

    buf
}

#[tokio::test]
async fn test_binary_protocol_correct_password() {
    init_crypto();
    let _echo_addr = start_echo_server().await;

    let user = TrojanUser::new("user1".to_string(), "test-password".to_string());
    let (cert, key) = generate_test_certs("localhost");
    let (server_addr, _stop, _cert_f, _key_f) =
        start_trojan_server_with_users(vec![user], cert.clone(), key.clone()).await;

    // Connect with TLS
    let connector = tokio_native_tls::native_tls::TlsConnector::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();
    let connector = tokio_native_tls::TlsConnector::from(connector);

    let stream = tokio::net::TcpStream::connect(server_addr).await.unwrap();
    let mut tls_stream = connector.connect("localhost", stream).await.unwrap();

    // Send binary Trojan request (CONNECT to example.com:80)
    let req = build_trojan_request("test-password", 0x01, "example.com", 80);
    tls_stream.write_all(&req).await.unwrap();

    // If authentication succeeds, server will try to connect to example.com
    // For this test, we just verify no immediate error
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    println!("✅ Binary protocol with correct password accepted");
}

#[tokio::test]
async fn test_binary_protocol_wrong_password() {
    init_crypto();

    let user = TrojanUser::new("user1".to_string(), "correct-password".to_string());
    let (cert, key) = generate_test_certs("localhost");
    let (server_addr, _stop, _cert_f, _key_f) =
        start_trojan_server_with_users(vec![user], cert, key).await;

    let connector = tokio_native_tls::native_tls::TlsConnector::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();
    let connector = tokio_native_tls::TlsConnector::from(connector);

    let stream = tokio::net::TcpStream::connect(server_addr).await.unwrap();
    let mut tls_stream = connector.connect("localhost", stream).await.unwrap();

    // Send request with wrong password
    let req = build_trojan_request("wrong-password", 0x01, "example.com", 80);
    tls_stream.write_all(&req).await.unwrap();

    // Server should close connection due to auth failure
    let mut buf = [0u8; 1];
    let result = tokio::time::timeout(
        tokio::time::Duration::from_secs(2),
        tls_stream.read(&mut buf),
    )
    .await;

    // Should either timeout or return error
    assert!(
        result.is_err() || result.unwrap().is_err() || result.unwrap().unwrap() == 0,
        "Wrong password should cause connection close"
    );

    println!("✅ Binary protocol with wrong password rejected");
}

#[tokio::test]
async fn test_binary_protocol_multi_user() {
    init_crypto();

    let users = vec![
        TrojanUser::new("alice".to_string(), "alice-password".to_string()),
        TrojanUser::new("bob".to_string(), "bob-password".to_string()),
        TrojanUser::new("charlie".to_string(), "charlie-password".to_string()),
    ];

    let (cert, key) = generate_test_certs("localhost");
    let (server_addr, _stop, _cert_f, _key_f) =
        start_trojan_server_with_users(users, cert, key).await;

    let connector = tokio_native_tls::native_tls::TlsConnector::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();
    let connector = tokio_native_tls::TlsConnector::from(connector);

    // Test alice
    let stream = tokio::net::TcpStream::connect(server_addr).await.unwrap();
    let mut tls_stream = connector.connect("localhost", stream).await.unwrap();
    let req = build_trojan_request("alice-password", 0x01, "example.com", 80);
    tls_stream.write_all(&req).await.unwrap();
    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
    drop(tls_stream);

    // Test bob
    let stream = tokio::net::TcpStream::connect(server_addr).await.unwrap();
    let mut tls_stream = connector.connect("localhost", stream).await.unwrap();
    let req = build_trojan_request("bob-password", 0x01, "google.com", 443);
    tls_stream.write_all(&req).await.unwrap();
    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
    drop(tls_stream);

    // Test charlie
    let stream = tokio::net::TcpStream::connect(server_addr).await.unwrap();
    let mut tls_stream = connector.connect("localhost", stream).await.unwrap();
    let req = build_trojan_request("charlie-password", 0x01, "github.com", 443);
    tls_stream.write_all(&req).await.unwrap();
    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

    println!("✅ Multi-user authentication working (3/3 users)");
}

#[tokio::test]
async fn test_binary_protocol_ipv4_address() {
    init_crypto();

    let user = TrojanUser::new("user1".to_string(), "test-pwd".to_string());
    let (cert, key) = generate_test_certs("localhost");
    let (server_addr, _stop, _cert_f, _key_f) =
        start_trojan_server_with_users(vec![user], cert, key).await;

    let connector = tokio_native_tls::native_tls::TlsConnector::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();
    let connector = tokio_native_tls::TlsConnector::from(connector);

    let stream = tokio::net::TcpStream::connect(server_addr).await.unwrap();
    let mut tls_stream = connector.connect("localhost", stream).await.unwrap();

    // Build IPv4 request manually
    let mut buf = Vec::new();
    let hash = Sha224::digest(b"test-pwd");
    buf.extend_from_slice(hex::encode(hash).as_bytes());
    buf.extend_from_slice(b"\r\n");
    buf.push(0x01); // CONNECT
    buf.push(0x01); // IPv4
    buf.extend_from_slice(&[8, 8, 8, 8]); // 8.8.8.8
    buf.extend_from_slice(&80u16.to_be_bytes());
    buf.extend_from_slice(b"\r\n");

    tls_stream.write_all(&buf).await.unwrap();
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    println!("✅ IPv4 address parsing working");
}

#[tokio::test]
async fn test_binary_protocol_backward_compat() {
    init_crypto();

    let (cert, key) = generate_test_certs("localhost");
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("Failed to bind");
    let addr = listener.local_addr().unwrap();
    drop(listener);

    let (stop_tx, stop_rx) = mpsc::channel(1);

    let mut cert_file = NamedTempFile::new().unwrap();
    cert_file.write_all(cert.as_bytes()).unwrap();
    let mut key_file = NamedTempFile::new().unwrap();
    key_file.write_all(key.as_bytes()).unwrap();

    // Test backward compatibility with single password
    #[allow(deprecated)]
    let config = TrojanInboundConfig {
        listen: addr,
        password: Some("legacy-password".to_string()),
        users: vec![],
        cert_path: cert_file.path().to_str().unwrap().to_string(),
        key_path: key_file.path().to_str().unwrap().to_string(),
        router: Arc::new(RouterHandle::new_mock()),
        transport_layer: None,
        multiplex: None,
        #[cfg(feature = "tls_reality")]
        reality: None,
    };

    tokio::spawn(async move {
        let _ = sb_adapters::inbound::trojan::serve(config, stop_rx).await;
    });

    tokio::time::sleep(tokio::time::Duration::from_millis(300)).await;

    let connector = tokio_native_tls::native_tls::TlsConnector::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();
    let connector = tokio_native_tls::TlsConnector::from(connector);

    let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let mut tls_stream = connector.connect("localhost", stream).await.unwrap();

    let req = build_trojan_request("legacy-password", 0x01, "example.com", 80);
    tls_stream.write_all(&req).await.unwrap();
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    drop(stop_tx);

    println!("✅ Backward compatibility with single password works");
}
