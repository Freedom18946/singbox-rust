#![cfg(feature = "adapter-http")]
//! HTTP CONNECT E2E tests with mock servers
//!
//! These tests create mock HTTP CONNECT proxy servers to verify that the connector
//! can successfully establish connections using the HTTP CONNECT method.

use base64::Engine;
use sb_adapters::outbound::http::HttpProxyConnector;
use sb_adapters::outbound::prelude::*;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;

#[tokio::test]
async fn test_http_connect_no_auth() {
    // Start mock HTTP proxy server
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut reader = BufReader::new(&mut stream);

        // Read HTTP CONNECT request line
        let mut request_line = String::new();
        reader.read_line(&mut request_line).await.unwrap();
        assert!(request_line.starts_with("CONNECT example.com:443 HTTP/1.1\r\n"));

        // Read headers until empty line
        loop {
            let mut header = String::new();
            reader.read_line(&mut header).await.unwrap();
            if header == "\r\n" {
                break; // End of headers
            }
            // Verify we have Host header
            if header.starts_with("Host:") {
                assert!(header.contains("example.com:443"));
            }
        }

        // Send HTTP 200 response
        let response = "HTTP/1.1 200 Connection Established\r\n\r\n";
        stream.write_all(response.as_bytes()).await.unwrap();

        // Keep connection alive for the test
        tokio::time::sleep(Duration::from_millis(100)).await;
    });

    tokio::time::sleep(Duration::from_millis(10)).await;

    // Create connector and test
    let connector = HttpProxyConnector::no_auth(server_addr.to_string());
    let target = Target::tcp("example.com", 443);
    let opts = DialOpts::new().with_connect_timeout(Duration::from_secs(5));

    let result = connector.dial(target, opts).await;
    assert!(
        result.is_ok(),
        "HTTP CONNECT should succeed: {:?}",
        result.err()
    );

    let _stream = result.unwrap();
}

#[tokio::test]
async fn test_http_connect_with_auth() {
    // Start mock HTTP proxy server with auth
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut reader = BufReader::new(&mut stream);

        // Read HTTP CONNECT request line
        let mut request_line = String::new();
        reader.read_line(&mut request_line).await.unwrap();
        assert!(request_line.starts_with("CONNECT example.com:443 HTTP/1.1\r\n"));

        let mut found_auth = false;
        // Read headers until empty line
        loop {
            let mut header = String::new();
            reader.read_line(&mut header).await.unwrap();
            if header == "\r\n" {
                break; // End of headers
            }
            if header.starts_with("Proxy-Authorization: Basic ") {
                found_auth = true;
                // Verify the base64 encoded credentials
                let auth_part = header
                    .trim()
                    .strip_prefix("Proxy-Authorization: Basic ")
                    .unwrap();
                // testuser:testpass in base64
                let expected_auth = base64::prelude::BASE64_STANDARD.encode(b"testuser:testpass");
                assert_eq!(auth_part, expected_auth);
            }
        }

        assert!(found_auth, "Should have found Proxy-Authorization header");

        // Send HTTP 200 response
        let response = "HTTP/1.1 200 Connection Established\r\n\r\n";
        stream.write_all(response.as_bytes()).await.unwrap();

        tokio::time::sleep(Duration::from_millis(100)).await;
    });

    tokio::time::sleep(Duration::from_millis(10)).await;

    // Create connector with auth and test
    let connector = HttpProxyConnector::with_auth(server_addr.to_string(), "testuser", "testpass");
    let target = Target::tcp("example.com", 443);
    let opts = DialOpts::new().with_connect_timeout(Duration::from_secs(5));

    let result = connector.dial(target, opts).await;
    assert!(
        result.is_ok(),
        "HTTP CONNECT with auth should succeed: {:?}",
        result.err()
    );

    let _stream = result.unwrap();
}

#[tokio::test]
async fn test_http_connect_failure() {
    // Start mock HTTP proxy server that returns error
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut reader = BufReader::new(&mut stream);

        // Read request (don't need to parse fully)
        loop {
            let mut line = String::new();
            reader.read_line(&mut line).await.unwrap();
            if line == "\r\n" {
                break;
            }
        }

        // Send HTTP 407 Proxy Authentication Required
        let response = "HTTP/1.1 407 Proxy Authentication Required\r\n\r\n";
        stream.write_all(response.as_bytes()).await.unwrap();
    });

    tokio::time::sleep(Duration::from_millis(10)).await;

    let connector = HttpProxyConnector::no_auth(server_addr.to_string());
    let target = Target::tcp("example.com", 443);
    let opts = DialOpts::new().with_connect_timeout(Duration::from_secs(5));

    let result = connector.dial(target, opts).await;
    assert!(result.is_err(), "HTTP CONNECT should fail");

    if let Err(AdapterError::Protocol(msg)) = result {
        assert!(msg.contains("407"), "Should indicate 407 error: {}", msg);
    } else {
        panic!("Expected Protocol error with 407 message");
    }
}

#[tokio::test]
async fn test_http_connect_bad_response() {
    // Start mock server that sends malformed response
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut reader = BufReader::new(&mut stream);

        // Read request
        loop {
            let mut line = String::new();
            reader.read_line(&mut line).await.unwrap();
            if line == "\r\n" {
                break;
            }
        }

        // Send malformed HTTP response
        let response = "NOT A VALID HTTP RESPONSE\r\n";
        stream.write_all(response.as_bytes()).await.unwrap();
    });

    tokio::time::sleep(Duration::from_millis(10)).await;

    let connector = HttpProxyConnector::no_auth(server_addr.to_string());
    let target = Target::tcp("example.com", 443);
    let opts = DialOpts::new().with_connect_timeout(Duration::from_secs(5));

    let result = connector.dial(target, opts).await;
    assert!(
        result.is_err(),
        "HTTP CONNECT should fail with bad response"
    );

    if let Err(AdapterError::Protocol(msg)) = result {
        assert!(
            msg.contains("Invalid HTTP response") || msg.contains("HTTP CONNECT failed"),
            "Should indicate invalid response: {}",
            msg
        );
    } else {
        panic!("Expected Protocol error");
    }
}
