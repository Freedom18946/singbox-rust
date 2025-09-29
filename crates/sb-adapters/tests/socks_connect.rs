#![cfg(feature = "adapter-socks")]
//! SOCKS5 E2E tests with mock servers
//!
//! These tests create mock SOCKS5 servers to verify that the connector
//! can successfully establish connections using the SOCKS5 protocol.

use sb_adapters::outbound::prelude::*;
use sb_adapters::outbound::socks5::Socks5Connector;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

#[tokio::test]
async fn test_socks5_no_auth_connect() {
    // Start mock SOCKS5 server
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_addr = listener.local_addr().unwrap();

    // Spawn mock server
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();

        // Handle SOCKS5 handshake
        let mut buf = [0u8; 3];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(buf[0], 0x05); // SOCKS version
        assert_eq!(buf[1], 0x01); // Number of methods
        assert_eq!(buf[2], 0x00); // No auth method

        // Respond: no auth required
        stream.write_all(&[0x05, 0x00]).await.unwrap();

        // Read CONNECT request
        let mut buf = [0u8; 4];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(buf[0], 0x05); // SOCKS version
        assert_eq!(buf[1], 0x01); // CONNECT command
        assert_eq!(buf[2], 0x00); // Reserved
        assert_eq!(buf[3], 0x03); // Domain name type

        // Read domain name length
        let mut len = [0u8; 1];
        stream.read_exact(&mut len).await.unwrap();
        let domain_len = len[0] as usize;

        // Read domain name
        let mut domain = vec![0u8; domain_len];
        stream.read_exact(&mut domain).await.unwrap();
        assert_eq!(std::str::from_utf8(&domain).unwrap(), "example.com");

        // Read port
        let mut port_buf = [0u8; 2];
        stream.read_exact(&mut port_buf).await.unwrap();
        let port = u16::from_be_bytes(port_buf);
        assert_eq!(port, 80);

        // Respond: success
        stream
            .write_all(&[
                0x05, 0x00, 0x00, 0x01, // VER, REP=success, RSV, ATYP=IPv4
                127, 0, 0, 1, // Bound IP
                0x00, 0x50, // Bound port (80)
            ])
            .await
            .unwrap();

        // Keep connection alive for the test
        tokio::time::sleep(Duration::from_millis(100)).await;
    });

    // Wait a moment for server to start
    tokio::time::sleep(Duration::from_millis(10)).await;

    // Create connector and test
    let connector = Socks5Connector::no_auth(server_addr.to_string());
    let target = Target::tcp("example.com", 80);
    let opts = DialOpts::new().with_connect_timeout(Duration::from_secs(5));

    let result = connector.dial(target, opts).await;
    assert!(
        result.is_ok(),
        "SOCKS5 connection should succeed: {:?}",
        result.err()
    );

    let _stream = result.unwrap();
    // Stream should be usable (this is verified by the mock server protocol exchange)
}

#[tokio::test]
async fn test_socks5_with_auth_connect() {
    // Start mock SOCKS5 server with auth
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();

        // Handle SOCKS5 handshake
        let mut buf = [0u8; 3];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(buf[0], 0x05); // SOCKS version
        assert_eq!(buf[1], 0x01); // Number of methods
        assert_eq!(buf[2], 0x02); // Username/password auth method

        // Respond: username/password auth required
        stream.write_all(&[0x05, 0x02]).await.unwrap();

        // Read auth request
        let mut version = [0u8; 1];
        stream.read_exact(&mut version).await.unwrap();
        assert_eq!(version[0], 0x01); // Auth version

        // Read username length and username
        let mut ulen = [0u8; 1];
        stream.read_exact(&mut ulen).await.unwrap();
        let mut username = vec![0u8; ulen[0] as usize];
        stream.read_exact(&mut username).await.unwrap();
        assert_eq!(std::str::from_utf8(&username).unwrap(), "testuser");

        // Read password length and password
        let mut plen = [0u8; 1];
        stream.read_exact(&mut plen).await.unwrap();
        let mut password = vec![0u8; plen[0] as usize];
        stream.read_exact(&mut password).await.unwrap();
        assert_eq!(std::str::from_utf8(&password).unwrap(), "testpass");

        // Respond: auth success
        stream.write_all(&[0x01, 0x00]).await.unwrap();

        // Read CONNECT request (same as no-auth test)
        let mut buf = [0u8; 4];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(buf[0], 0x05); // SOCKS version
        assert_eq!(buf[1], 0x01); // CONNECT command

        // Skip reading the full request for brevity - just respond success
        let mut remaining = [0u8; 100];
        let n = stream.read(&mut remaining).await.unwrap();
        assert!(n > 0); // Should have read the rest of the CONNECT request

        // Respond: success
        stream
            .write_all(&[
                0x05, 0x00, 0x00, 0x01, // VER, REP=success, RSV, ATYP=IPv4
                127, 0, 0, 1, // Bound IP
                0x00, 0x50, // Bound port (80)
            ])
            .await
            .unwrap();

        tokio::time::sleep(Duration::from_millis(100)).await;
    });

    tokio::time::sleep(Duration::from_millis(10)).await;

    // Create connector with auth and test
    let connector = Socks5Connector::with_auth(server_addr.to_string(), "testuser", "testpass");
    let target = Target::tcp("example.com", 80);
    let opts = DialOpts::new().with_connect_timeout(Duration::from_secs(5));

    let result = connector.dial(target, opts).await;
    assert!(
        result.is_ok(),
        "SOCKS5 auth connection should succeed: {:?}",
        result.err()
    );

    let _stream = result.unwrap();
}

#[tokio::test]
async fn test_socks5_connect_failure() {
    // Start mock SOCKS5 server that returns connection refused
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();

        // Handle handshake normally
        let mut buf = [0u8; 3];
        stream.read_exact(&mut buf).await.unwrap();
        stream.write_all(&[0x05, 0x00]).await.unwrap(); // No auth

        // Read CONNECT request
        let mut buf = [0u8; 100];
        let _n = stream.read(&mut buf).await.unwrap();

        // Respond with connection refused
        stream
            .write_all(&[
                0x05, 0x05, 0x00, 0x01, // VER, REP=connection refused, RSV, ATYP=IPv4
                0, 0, 0, 0, // Bound IP
                0x00, 0x00, // Bound port
            ])
            .await
            .unwrap();
    });

    tokio::time::sleep(Duration::from_millis(10)).await;

    let connector = Socks5Connector::no_auth(server_addr.to_string());
    let target = Target::tcp("example.com", 80);
    let opts = DialOpts::new().with_connect_timeout(Duration::from_secs(5));

    let result = connector.dial(target, opts).await;
    assert!(result.is_err(), "SOCKS5 connection should fail");

    if let Err(AdapterError::Protocol(msg)) = result {
        assert!(
            msg.contains("Connection refused"),
            "Should indicate connection refused: {}",
            msg
        );
    } else {
        panic!("Expected Protocol error with connection refused message");
    }
}
