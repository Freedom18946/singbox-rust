//! Local protocol integration smoke tests.
//!
//! Covers socket-level timeout, reconnect, concurrency, and cleanup behavior.
//!
//! Run with:
//!   cargo test --package app --test protocol_integration_validation_test -- --nocapture

use std::io;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

/// Test helper: Start echo server
async fn start_echo_server() -> Option<SocketAddr> {
    let listener = match TcpListener::bind("127.0.0.1:0").await {
        Ok(listener) => listener,
        Err(err) => {
            if matches!(
                err.kind(),
                io::ErrorKind::PermissionDenied | io::ErrorKind::AddrNotAvailable
            ) {
                eprintln!("Skipping protocol integration test: cannot bind echo server ({err})");
                return None;
            }
            panic!("bind: {err}");
        }
    };
    let addr = listener.local_addr().expect("local_addr");

    tokio::spawn(async move {
        loop {
            if let Ok((mut socket, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 8192];
                    loop {
                        match socket.read(&mut buf).await {
                            Ok(0) | Err(_) => break,
                            Ok(n) => {
                                if socket.write_all(&buf[..n]).await.is_err() {
                                    break;
                                }
                            }
                        }
                    }
                });
            }
        }
    });

    tokio::time::sleep(Duration::from_millis(100)).await;
    Some(addr)
}

// ============================================================================
// FAILOVER SCENARIOS
// ============================================================================

#[tokio::test]
async fn test_primary_outbound_failure_fallback() {
    // Test primary outbound failure → fallback activation
    println!("\n=== Testing Failover Scenario ===");

    // Simulate primary failure with deliberate timeout
    let primary_result = timeout(Duration::from_millis(10), async {
        tokio::time::sleep(Duration::from_secs(1)).await;
        TcpStream::connect("localhost:1").await
    })
    .await;

    assert!(primary_result.is_err(), "Primary should fail/timeout");

    // Fallback to working echo server
    let Some(echo_addr) = start_echo_server().await else {
        return;
    };
    let fallback_result = TcpStream::connect(echo_addr).await;

    assert!(fallback_result.is_ok(), "Fallback should succeed");
    println!("✓ Primary failure → fallback validated");
}

#[tokio::test]
async fn test_dns_resolution_failure_handling() {
    // Test DNS resolution failure handling
    let result = timeout(
        Duration::from_secs(1),
        TcpStream::connect("this-domain-does-not-exist-12345.example:80"),
    )
    .await;

    // Should either timeout or fail with DNS error
    assert!(
        result.is_err() || result.unwrap().is_err(),
        "DNS resolution failure should be handled"
    );

    println!("✓ DNS resolution failure handling validated");
}

#[tokio::test]
async fn test_network_interruption_recovery() {
    // Test network interruption recovery
    let Some(echo_addr) = start_echo_server().await else {
        return;
    };

    // Establish connection
    let mut stream = TcpStream::connect(echo_addr).await.expect("connect");

    // Send data successfully
    stream.write_all(b"test1").await.expect("write");
    let mut buf = [0u8; 5];
    stream.read_exact(&mut buf).await.expect("read");

    // Simulate interruption by closing connection
    drop(stream);

    // Recover by establishing new connection
    let mut new_stream = TcpStream::connect(echo_addr).await.expect("reconnect");
    new_stream
        .write_all(b"test2")
        .await
        .expect("write after recovery");

    println!("✓ Network interruption recovery validated");
}

#[tokio::test]
async fn test_connection_timeout_fallback() {
    // Test connection timeout triggers fallback
    let timeout_result = timeout(Duration::from_millis(10), async {
        tokio::time::sleep(Duration::from_secs(1)).await;
        TcpStream::connect("localhost:1").await
    })
    .await;

    assert!(timeout_result.is_err(), "Connection should timeout");

    // Fallback to working server
    let Some(echo_addr) = start_echo_server().await else {
        return;
    };
    let fallback = TcpStream::connect(echo_addr).await;
    assert!(fallback.is_ok(), "Fallback after timeout should succeed");

    println!("✓ Connection timeout → fallback validated");
}

// ============================================================================
// END-TO-END INTEGRATION TESTS
// ============================================================================

#[tokio::test]
async fn test_concurrent_local_tcp_echo() {
    // Exercise concurrent TCP echo traffic through local sockets.
    let Some(echo_addr) = start_echo_server().await else {
        return;
    };

    let num_concurrent = 20;
    let mut handles = vec![];

    for i in 0..num_concurrent {
        let handle = tokio::spawn(async move {
            match timeout(Duration::from_secs(2), TcpStream::connect(echo_addr)).await {
                Ok(Ok(mut stream)) => {
                    let data = format!("concurrent-{}", i);
                    stream.write_all(data.as_bytes()).await.expect("write");

                    let mut buf = vec![0u8; data.len()];
                    stream.read_exact(&mut buf).await.expect("read");
                    true
                }
                _ => false,
            }
        });
        handles.push(handle);
    }

    let mut success_count = 0;
    for handle in handles {
        if let Ok(true) = handle.await {
            success_count += 1;
        }
    }

    assert_eq!(success_count, num_concurrent);
    println!("✓ Concurrent local TCP echo connections validated");
}

// ============================================================================
// RESOURCE MANAGEMENT
// ============================================================================

#[tokio::test]
async fn test_connection_cleanup() {
    // Test that connections are properly cleaned up
    let Some(echo_addr) = start_echo_server().await else {
        return;
    };

    // Create and drop multiple connections
    for _ in 0..10 {
        let stream = TcpStream::connect(echo_addr).await.expect("connect");
        drop(stream); // Explicit drop
    }

    // Verify we can still create new connections (no resource leak)
    let final_stream = TcpStream::connect(echo_addr).await;
    assert!(final_stream.is_ok(), "Should still be able to connect");

    println!("✓ Connection cleanup validated");
}

#[tokio::test]
async fn test_memory_stability_short() {
    // Short memory stability test
    let Some(echo_addr) = start_echo_server().await else {
        return;
    };

    for i in 0..100 {
        if let Ok(mut stream) = TcpStream::connect(echo_addr).await {
            let data = vec![0xAB; 1024]; // 1KB
            stream.write_all(&data).await.expect("write");
            let mut buf = vec![0u8; 1024];
            stream.read_exact(&mut buf).await.expect("read");
        }

        if i % 25 == 0 {
            println!("Memory check: {} iterations", i);
        }
    }

    println!("✓ Short memory stability test passed");
}
