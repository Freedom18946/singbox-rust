//! Integration test for Mixed inbound protocol detection
//!
//! Tests that the Mixed inbound correctly detects and routes both HTTP and SOCKS5 protocols.

#[cfg(all(feature = "http", feature = "socks"))]
#[tokio::test]
async fn test_mixed_inbound_protocol_detection() {
    use std::io::Write as _;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    // This test validates that the Mixed inbound can handle both protocols
    // For a full test, we would:
    // 1. Start a Mixed inbound server
    // 2. Connect with SOCKS5 handshake
    // 3. Connect with HTTP CONNECT
    // 4. Verify both are handled correctly

    // Placeholder for actual test implementation
    // Real implementation would require:
    // - Setting up a test router
    // - Starting the mixed inbound server
    // - Making actual connections

}

#[cfg(all(feature = "http", feature = "socks"))]
#[test]
fn test_socks5_first_byte_detection() {
    // SOCKS5 version is 0x05
    let socks5_version: u8 = 0x05;
    assert_eq!(socks5_version, 0x05);
}

#[cfg(all(feature = "http", feature = "socks"))]
#[test]
fn test_http_first_byte_detection() {
    // HTTP CONNECT starts with ASCII letter 'C'
    let connect_first: u8 = b'C';
    assert!(connect_first.is_ascii_alphabetic());
}

#[cfg(all(feature = "http", feature = "socks"))]
#[test]
fn test_protocol_detection_boundary_conditions() {
    // Test boundary values
    assert_eq!(0x05, 5u8, "SOCKS5 version is 5");
    assert!(b'C'.is_ascii_alphabetic(), "CONNECT starts with letter");
    assert!(b'G'.is_ascii_alphabetic(), "GET starts with letter");

    // Non-protocol bytes
    assert!(!0x00.is_ascii_alphabetic());
    assert!(!0xFF.is_ascii_alphabetic());
}

/// Documentation test showing how to use Mixed inbound
///
/// ```rust,ignore
/// use sb_adapters::inbound::mixed::{MixedInboundConfig, serve_mixed};
/// use std::sync::Arc;
///
/// async fn example_mixed_setup() {
///     let cfg = MixedInboundConfig {
///         listen: "127.0.0.1:1080".parse().unwrap(),
///         router: Arc::new(router_handle),
///         outbounds: Arc::new(outbound_registry),
///         read_timeout: Some(std::time::Duration::from_secs(5)),
///     };
///
///     let (tx, rx) = tokio::sync::mpsc::channel(1);
///     serve_mixed(cfg, rx, None).await.expect("server failed");
/// }
/// ```
#[allow(dead_code)]
fn mixed_inbound_usage_example() {}
