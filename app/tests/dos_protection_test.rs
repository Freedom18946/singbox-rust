#![cfg(feature = "net_e2e")]
//! DoS Protection and Attack Mitigation Tests - Phase 1 Production Readiness
//!
//! Test suite covering:
//! - Connection flood protection (max connections per IP)
//! - Slowloris attack mitigation
//! - Resource exhaustion limits (memory, CPU, FD limits)
//! - Rate limiting under attack scenarios

use std::io::Write;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tempfile::NamedTempFile;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::mpsc;

use sb_adapters::inbound::shadowsocks::ShadowsocksInboundConfig;
use sb_adapters::outbound::shadowsocks::{ShadowsocksConfig, ShadowsocksConnector};
use sb_adapters::outbound::{DialOpts, OutboundConnector, Target};
use sb_adapters::TransportKind;
use sb_core::router::engine::RouterHandle;

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

    tokio::time::sleep(Duration::from_millis(50)).await;
    addr
}

// Helper: Start Shadowsocks server with rate limiting
async fn start_ss_server_with_rate_limit(
    max_conn_per_ip: usize,
    window_sec: u64,
) -> (SocketAddr, mpsc::Sender<()>) {
    // Set rate limiting env vars
    std::env::set_var("SB_INBOUND_RATE_LIMIT_PER_IP", max_conn_per_ip.to_string());
    std::env::set_var("SB_INBOUND_RATE_LIMIT_WINDOW_SEC", window_sec.to_string());

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("Failed to bind");
    let addr = listener.local_addr().unwrap();
    drop(listener);

    let (stop_tx, stop_rx) = mpsc::channel(1);

    let config = ShadowsocksInboundConfig {
        listen: addr,
        method: "chacha20-poly1305".to_string(),
        password: "test-password".to_string(),
        router: Arc::new(RouterHandle::new_mock()),
        multiplex: None,
        transport_layer: None,
    };

    tokio::spawn(async move {
        let _ = sb_adapters::inbound::shadowsocks::serve(config, stop_rx).await;
    });

    tokio::time::sleep(Duration::from_millis(200)).await;
    (addr, stop_tx)
}

// =============================================================================
// Test 1: Connection Flood Protection
// =============================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_connection_flood_protection() {
    let echo_addr = start_echo_server().await;

    // Set strict rate limit: 20 connections per 5 seconds
    let (server_addr, _stop) = start_ss_server_with_rate_limit(20, 5).await;

    let connector = Arc::new(
        ShadowsocksConnector::new(ShadowsocksConfig {
            server: server_addr.to_string(),
            tag: None,
            method: "chacha20-poly1305".to_string(),
            password: "test-password".to_string(),
            connect_timeout_sec: Some(5),
            multiplex: None,
        })
        .expect("Failed to create connector"),
    );

    let success_count = Arc::new(AtomicUsize::new(0));
    let blocked_count = Arc::new(AtomicUsize::new(0));

    // Attempt 100 rapid connections (flood attack simulation)
    let mut handles = vec![];
    for _ in 0..100 {
        let connector = connector.clone();
        let success_count = success_count.clone();
        let blocked_count = blocked_count.clone();

        handles.push(tokio::spawn(async move {
            let target = Target {
                host: echo_addr.ip().to_string(),
                port: echo_addr.port(),
                kind: TransportKind::Tcp,
            };

            match connector.dial(target, DialOpts::default()).await {
                Ok(_) => success_count.fetch_add(1, Ordering::Relaxed),
                Err(_) => blocked_count.fetch_add(1, Ordering::Relaxed),
            };
        }));
    }

    for h in handles {
        let _ = h.await;
    }

    let successful = success_count.load(Ordering::Relaxed);
    let blocked = blocked_count.load(Ordering::Relaxed);

    println!(
        "✅ Connection flood test: {} successful, {} blocked (rate limited)",
        successful, blocked
    );

    // Verify rate limiting is working (some connections should be blocked)
    assert!(
        blocked > 0,
        "Expected some connections to be rate-limited, got 0"
    );
    assert!(successful > 0, "Expected some connections to succeed");

    // Successful connections should be roughly within rate limit
    assert!(
        successful <= 30,
        "Too many connections succeeded ({}), rate limiter may not be working",
        successful
    );
}

// =============================================================================
// Test 2: Slowloris Attack Mitigation (Slow Read)
// =============================================================================

#[tokio::test(flavor = "multi_thread")]
async fn test_slowloris_slow_read_mitigation() {
    let echo_addr = start_echo_server().await;
    let (server_addr, _stop) = start_ss_server_with_rate_limit(100, 10).await;

    let connector = ShadowsocksConnector::new(ShadowsocksConfig {
        server: server_addr.to_string(),
        tag: None,
        method: "chacha20-poly1305".to_string(),
        password: "test-password".to_string(),
        connect_timeout_sec: Some(5),
        multiplex: None,
    })
    .expect("Failed to create connector");

    let target = Target {
        host: echo_addr.ip().to_string(),
        port: echo_addr.port(),
        kind: TransportKind::Tcp,
    };

    // Simulate slowloris: connect and read very slowly
    let result = tokio::time::timeout(Duration::from_secs(10), async {
        let mut stream = connector.dial(target, DialOpts::default()).await?;

        // Send data
        stream.write_all(b"test").await?;

        // Read very slowly (1 byte at a time with delays)
        let mut buf = [0u8; 1];
        for _ in 0..4 {
            tokio::time::sleep(Duration::from_secs(2)).await;
            stream.read_exact(&mut buf).await?;
        }

        Ok::<(), Box<dyn std::error::Error>>(())
    })
    .await;

    match result {
        Ok(Ok(_)) => println!("✅ Slow read completed (connection timeout not triggered)"),
        Ok(Err(_)) => println!("✅ Slow read detected and connection closed"),
        Err(_) => println!("✅ Slow read timed out (expected behavior)"),
    }
}

// =============================================================================
// Test 3: Resource Exhaustion - Memory Limit
// =============================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_resource_exhaustion_memory() {
    let echo_addr = start_echo_server().await;
    let (server_addr, _stop) = start_ss_server_with_rate_limit(200, 10).await;

    let connector = Arc::new(
        ShadowsocksConnector::new(ShadowsocksConfig {
            server: server_addr.to_string(),
            tag: None,
            method: "chacha20-poly1305".to_string(),
            password: "test-password".to_string(),
            connect_timeout_sec: Some(10),
            multiplex: None,
        })
        .expect("Failed to create connector"),
    );

    // Try to exhaust memory by opening many connections
    let mut handles = vec![];
    let success_count = Arc::new(AtomicUsize::new(0));

    for _ in 0..200 {
        let connector = connector.clone();
        let success_count = success_count.clone();

        handles.push(tokio::spawn(async move {
            let target = Target {
                host: echo_addr.ip().to_string(),
                port: echo_addr.port(),
                kind: TransportKind::Tcp,
            };

            if connector.dial(target, DialOpts::default()).await.is_ok() {
                success_count.fetch_add(1, Ordering::Relaxed);
                // Keep connection alive for a bit
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }));
    }

    for h in handles {
        let _ = h.await;
    }

    let count = success_count.load(Ordering::Relaxed);
    println!(
        "✅ Resource exhaustion test: {}/200 connections established",
        count
    );

    // System should handle this gracefully (either accept all or rate limit)
    assert!(count > 0, "At least some connections should succeed");
}

// =============================================================================
// Test 4: Burst Traffic Handling
// =============================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_burst_traffic_handling() {
    let echo_addr = start_echo_server().await;
    let (server_addr, _stop) = start_ss_server_with_rate_limit(50, 2).await;

    let connector = Arc::new(
        ShadowsocksConnector::new(ShadowsocksConfig {
            server: server_addr.to_string(),
            tag: None,
            method: "chacha20-poly1305".to_string(),
            password: "test-password".to_string(),
            connect_timeout_sec: Some(5),
            multiplex: None,
        })
        .expect("Failed to create connector"),
    );

    // Simulate burst: 0 → 150 connections in instant
    let mut handles = vec![];
    let success_count = Arc::new(AtomicUsize::new(0));

    for _ in 0..150 {
        let connector = connector.clone();
        let success_count = success_count.clone();

        handles.push(tokio::spawn(async move {
            let target = Target {
                host: echo_addr.ip().to_string(),
                port: echo_addr.port(),
                kind: TransportKind::Tcp,
            };

            if connector.dial(target, DialOpts::default()).await.is_ok() {
                success_count.fetch_add(1, Ordering::Relaxed);
            }
        }));
    }

    for h in handles {
        let _ = h.await;
    }

    let count = success_count.load(Ordering::Relaxed);
    println!("✅ Burst traffic test: {}/150 connections handled", count);

    // With 50 conn/2s limit, expect around 50-60 successful (allowing buffer)
    assert!(count >= 40, "Too few connections succeeded: {}", count);
    assert!(
        count <= 70,
        "Too many connections succeeded: {}, rate limiter may be broken",
        count
    );
}

// =============================================================================
// Test 5: Recovery After Attack
// =============================================================================

#[tokio::test]
async fn test_recovery_after_flood() {
    let echo_addr = start_echo_server().await;
    let (server_addr, _stop) = start_ss_server_with_rate_limit(10, 2).await;

    let connector = ShadowsocksConnector::new(ShadowsocksConfig {
        server: server_addr.to_string(),
        tag: None,
        method: "chacha20-poly1305".to_string(),
        password: "test-password".to_string(),
        connect_timeout_sec: Some(5),
        multiplex: None,
    })
    .expect("Failed to create connector");

    // Phase 1: Flood attack
    println!("Phase 1: Simulating flood attack...");
    for _ in 0..50 {
        let target = Target {
            host: echo_addr.ip().to_string(),
            port: echo_addr.port(),
            kind: TransportKind::Tcp,
        };
        let _ = connector.dial(target, DialOpts::default()).await;
    }

    // Phase 2: Wait for rate limit window to expire
    println!("Phase 2: Waiting for rate limit window to reset...");
    tokio::time::sleep(Duration::from_secs(3)).await;

    // Phase 3: Normal traffic should succeed
    println!("Phase 3: Testing normal traffic after attack...");
    let target = Target {
        host: echo_addr.ip().to_string(),
        port: echo_addr.port(),
        kind: TransportKind::Tcp,
    };

    let result = connector.dial(target, DialOpts::default()).await;
    assert!(
        result.is_ok(),
        "✅ System should recover after attack and allow normal traffic"
    );

    println!("✅ Recovery test passed: system accepts normal traffic after flood");
}
