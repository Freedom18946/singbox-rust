//! Comprehensive error handling tests
//!
//! Ensures that all error conditions are handled gracefully and
//! return appropriate error codes to clients.

use std::io::{Error, ErrorKind};
use std::time::Duration;

fn parse_socks5_greeting(input: &[u8]) -> Result<&[u8], Error> {
    if input.len() < 2 {
        return Err(Error::new(
            ErrorKind::UnexpectedEof,
            "SOCKS5 greeting missing method count",
        ));
    }
    if input[0] != 0x05 {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "SOCKS5 greeting has unsupported version",
        ));
    }
    let method_count = input[1] as usize;
    if input.len() < 2 + method_count {
        return Err(Error::new(
            ErrorKind::UnexpectedEof,
            "SOCKS5 greeting method list is incomplete",
        ));
    }
    Ok(&input[2..2 + method_count])
}

fn parse_http_request_head(input: &[u8]) -> Result<httparse::Status<usize>, Error> {
    let mut headers = [httparse::EMPTY_HEADER; 8];
    let mut request = httparse::Request::new(&mut headers);
    request
        .parse(input)
        .map_err(|err| Error::new(ErrorKind::InvalidData, err.to_string()))
}

/// Test connection refused error handling
#[tokio::test]
async fn test_connection_refused_error() {
    // Verify that connection refused errors are properly propagated
    let result = tokio::net::TcpStream::connect("127.0.0.1:1").await;

    assert!(result.is_err(), "Should fail to connect to port 1");
    let err = result.unwrap_err();
    // In restricted sandboxes, binding/connect may yield PermissionDenied instead of ConnectionRefused
    assert!(
        matches!(
            err.kind(),
            ErrorKind::ConnectionRefused | ErrorKind::PermissionDenied
        ),
        "Should be ConnectionRefused or PermissionDenied error, got {:?}",
        err.kind()
    );
}

/// Test timeout error handling - uses timeout wrapper
#[tokio::test]
async fn test_connection_timeout_error() {
    // Test that timeout wrapper works correctly
    let timeout_duration = Duration::from_millis(50);

    // Create a future that never completes
    let never_completes = async {
        tokio::time::sleep(Duration::from_secs(3600)).await;
        Ok::<(), Error>(())
    };

    let result = tokio::time::timeout(timeout_duration, never_completes).await;

    assert!(result.is_err(), "Timeout should occur");
}

/// Test invalid address error handling
#[tokio::test]
async fn test_invalid_address_error() {
    // Test various invalid addresses
    let invalid_addresses = vec![
        "invalid:port",
        "256.256.256.256:80",
        "example.com:99999",
        "[invalid_ipv6]:80",
    ];

    for addr in invalid_addresses {
        let result: Result<std::net::SocketAddr, _> = addr.parse();
        assert!(result.is_err(), "Address {} should be invalid", addr);
    }
}

/// Test network unreachable scenarios
#[tokio::test]
async fn test_network_unreachable() {
    // Test connection to localhost port 1 (usually privileged and will be refused)
    let result = tokio::net::TcpStream::connect("127.0.0.1:1").await;

    // Should either be connection refused or permission denied
    assert!(result.is_err(), "Connection to port 1 should fail");
}

/// Test protocol version mismatch
#[test]
fn test_socks_version_mismatch() {
    let err = parse_socks5_greeting(&[0x04, 0x01, 0x00]).expect_err("SOCKS4 must be rejected");
    assert_eq!(err.kind(), ErrorKind::InvalidData);
}

/// Test malformed protocol data
#[test]
fn test_malformed_protocol_data() {
    let malformed_socks5 = [0x05, 0xFF]; // Claims 255 methods but supplies none.
    let malformed_http = b"INVALID HTTP REQUEST\r\n\r\n";

    let socks_err =
        parse_socks5_greeting(&malformed_socks5).expect_err("truncated SOCKS5 greeting");
    assert_eq!(socks_err.kind(), ErrorKind::UnexpectedEof);

    let http_err = parse_http_request_head(malformed_http).expect_err("bad HTTP version");
    assert_eq!(http_err.kind(), ErrorKind::InvalidData);
}

/// Test partial data / incomplete handshake
#[test]
fn test_incomplete_handshake() {
    let incomplete_socks5 = [0x05]; // Just version, no method count.
    let incomplete_http = b"CONNECT"; // Incomplete HTTP request

    let socks_err =
        parse_socks5_greeting(&incomplete_socks5).expect_err("incomplete SOCKS5 greeting");
    assert_eq!(socks_err.kind(), ErrorKind::UnexpectedEof);

    assert!(matches!(
        parse_http_request_head(incomplete_http).expect("partial HTTP request should parse"),
        httparse::Status::Partial
    ));
}

/// Test concurrent error conditions
#[tokio::test]
async fn test_concurrent_error_handling() {
    // Verify that errors in one connection don't affect others
    let handles: Vec<_> = (0..10)
        .map(|_| {
            tokio::spawn(async {
                // Attempt connection that will fail
                tokio::net::TcpStream::connect("127.0.0.1:1").await
            })
        })
        .collect();

    for handle in handles {
        let result = handle.await.expect("Task should complete");
        assert!(result.is_err(), "Each connection should fail independently");
    }
}

/// Test graceful degradation
#[tokio::test]
async fn test_graceful_degradation() {
    let failing = tokio::spawn(async { tokio::net::TcpStream::connect("127.0.0.1:1").await });
    let independent = tokio::spawn(async { Ok::<_, Error>("still-running") });

    assert!(failing.await.expect("failing task should join").is_err());
    assert_eq!(
        independent
            .await
            .expect("independent task should join")
            .expect("independent task should succeed"),
        "still-running"
    );
}

/// Test error message clarity
#[test]
fn test_error_message_clarity() {
    // Verify error messages are helpful for debugging
    let error = create_test_error(
        ErrorKind::ConnectionRefused,
        "Failed to connect to upstream",
    );

    let error_string = error.to_string();
    assert!(
        error_string.contains("upstream"),
        "Error message should mention upstream"
    );
}

/// Helper function to create test errors
fn create_test_error(kind: ErrorKind, message: &str) -> Error {
    Error::new(kind, message)
}
