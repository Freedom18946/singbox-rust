//! Happy Eyeballs (RFC 8305) dual-stack connection tests
//!
//! Tests the Happy Eyeballs implementation with various scenarios:
//! - IPv4-only connections
//! - IPv6-only connections
//! - Dual-stack with fast/slow combinations
//! - Disable switch functionality

use sb_transport::dialer::{Dialer, TcpDialer};
use std::env;
use std::net::TcpListener;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::time::{sleep, timeout};

#[tokio::test]
async fn test_happy_eyeballs_ipv4_only() {
    // Set up IPv4-only server
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();

    // Accept connections in background
    let accept_task = tokio::spawn(async move {
        if let Ok((stream, _)) = listener.accept() {
            drop(stream);
        }
    });

    // Test IPv4-only connection
    env::remove_var("SB_HE_DISABLE");
    let dialer = TcpDialer::default();
    let result = timeout(Duration::from_secs(5), dialer.connect("127.0.0.1", port)).await;

    assert!(result.is_ok(), "IPv4-only connection should succeed");
    assert!(result.unwrap().is_ok(), "Connection result should be Ok");

    accept_task.await.ok();
}

#[tokio::test]
async fn test_happy_eyeballs_ipv6_only() {
    // Set up IPv6-only server
    let listener = TcpListener::bind("[::1]:0").unwrap();
    let port = listener.local_addr().unwrap().port();

    // Accept connections in background
    let accept_task = tokio::spawn(async move {
        if let Ok((stream, _)) = listener.accept() {
            drop(stream);
        }
    });

    // Test IPv6-only connection
    env::remove_var("SB_HE_DISABLE");
    let dialer = TcpDialer::default();
    let result = timeout(Duration::from_secs(5), dialer.connect("::1", port)).await;

    assert!(result.is_ok(), "IPv6-only connection should succeed");
    assert!(result.unwrap().is_ok(), "Connection result should be Ok");

    accept_task.await.ok();
}

#[tokio::test]
#[ignore]
async fn test_happy_eyeballs_dual_stack_ipv6_fast() {
    // Set up dual-stack servers with IPv6 responding faster
    let ipv4_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = ipv4_listener.local_addr().unwrap().port();

    // Try to bind IPv6 to same port (may fail in some environments)
    let ipv6_result = TcpListener::bind(format!("[::1]:{}", port));
    if ipv6_result.is_err() {
        // Skip test if IPv6 not available
        return;
    }
    let ipv6_listener = ipv6_result.unwrap();

    let ipv6_ready = Arc::new(AtomicBool::new(false));
    let ipv4_ready = Arc::new(AtomicBool::new(false));

    // IPv6 server accepts immediately
    let ipv6_ready_clone = ipv6_ready.clone();
    let ipv6_task = tokio::spawn(async move {
        ipv6_ready_clone.store(true, Ordering::Relaxed);
        if let Ok((stream, _)) = ipv6_listener.accept() {
            drop(stream);
        }
    });

    // IPv4 server accepts after delay
    let ipv4_ready_clone = ipv4_ready.clone();
    let ipv4_task = tokio::spawn(async move {
        sleep(Duration::from_millis(200)).await;
        ipv4_ready_clone.store(true, Ordering::Relaxed);
        if let Ok((stream, _)) = ipv4_listener.accept() {
            drop(stream);
        }
    });

    // Wait for servers to be ready
    let start_wait = std::time::Instant::now();
    while !ipv6_ready.load(Ordering::Relaxed) || !ipv4_ready.load(Ordering::Relaxed) {
        if start_wait.elapsed() > Duration::from_secs(2) {
            panic!("Timed out waiting for servers to start");
        }
        sleep(Duration::from_millis(10)).await;
    }

    // Test dual-stack connection with short IPv4 delay
    env::set_var("SB_HE_DELAY_MS", "50");
    env::remove_var("SB_HE_DISABLE");

    let dialer = TcpDialer::default();
    let start = std::time::Instant::now();
    let result = timeout(Duration::from_secs(5), dialer.connect("localhost", port)).await;
    let elapsed = start.elapsed();

    assert!(result.is_ok(), "Dual-stack connection should succeed");
    assert!(result.unwrap().is_ok(), "Connection result should be Ok");

    // Should complete relatively quickly since IPv6 is faster
    assert!(
        elapsed < Duration::from_secs(2),
        "Connection should be fast when IPv6 responds quickly"
    );

    ipv6_task.abort();
    ipv4_task.abort();
}

#[tokio::test]
async fn test_happy_eyeballs_disabled() {
    // Set up IPv4 server
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();

    let accept_task = tokio::spawn(async move {
        if let Ok((stream, _)) = listener.accept() {
            drop(stream);
        }
    });

    // Disable Happy Eyeballs
    env::set_var("SB_HE_DISABLE", "1");

    let dialer = TcpDialer::default();
    let result = timeout(Duration::from_secs(5), dialer.connect("127.0.0.1", port)).await;

    assert!(
        result.is_ok(),
        "Connection with Happy Eyeballs disabled should succeed"
    );
    assert!(result.unwrap().is_ok(), "Connection result should be Ok");

    // Clean up environment
    env::remove_var("SB_HE_DISABLE");

    accept_task.await.ok();
}

#[tokio::test]
async fn test_happy_eyeballs_custom_delay() {
    // Test custom delay configuration
    env::set_var("SB_HE_DELAY_MS", "100");
    env::remove_var("SB_HE_DISABLE");

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();

    let accept_task = tokio::spawn(async move {
        if let Ok((stream, _)) = listener.accept() {
            drop(stream);
        }
    });

    let dialer = TcpDialer::default();
    let result = timeout(Duration::from_secs(5), dialer.connect("127.0.0.1", port)).await;

    assert!(
        result.is_ok(),
        "Connection with custom delay should succeed"
    );
    assert!(result.unwrap().is_ok(), "Connection result should be Ok");

    // Clean up
    env::remove_var("SB_HE_DELAY_MS");

    accept_task.await.ok();
}

#[tokio::test]
async fn test_happy_eyeballs_no_address_resolution() {
    // Test with invalid hostname that should fail DNS resolution
    env::remove_var("SB_HE_DISABLE");

    let dialer = TcpDialer::default();
    let result = dialer
        .connect("invalid.nonexistent.example.invalid", 80)
        .await;

    assert!(
        result.is_err(),
        "Connection to invalid hostname should fail"
    );
}

#[tokio::test]
async fn test_happy_eyeballs_connection_refused() {
    // Test connection to a port that's not listening
    env::remove_var("SB_HE_DISABLE");

    let dialer = TcpDialer::default();
    let result = timeout(
        Duration::from_secs(5),
        dialer.connect("127.0.0.1", 1), // Port 1 should be closed
    )
    .await;

    assert!(result.is_ok(), "Timeout should not occur");
    assert!(
        result.unwrap().is_err(),
        "Connection to closed port should fail"
    );
}
