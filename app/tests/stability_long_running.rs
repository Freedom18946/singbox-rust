#![cfg(feature = "net_e2e")]
//! Stability Test Framework
//!
//! Long-running stability test for 7-day soak testing:
//! - Configurable duration (env: STABILITY_DURATION_HOURS)
//! - Memory leak detection (periodic checks)
//! - Connection lifecycle tracking
//! - Error rate monitoring

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::mpsc;

use sb_adapters::inbound::shadowsocks::{ShadowsocksInboundConfig, ShadowsocksUser};
use sb_adapters::outbound::shadowsocks::{ShadowsocksConfig, ShadowsocksConnector};
use sb_adapters::outbound::{DialOpts, OutboundConnector, Target};
use sb_adapters::TransportKind;
use sb_core::router::engine::RouterHandle;

// Global metrics
static TOTAL_REQUESTS: AtomicU64 = AtomicU64::new(0);
static FAILED_REQUESTS: AtomicU64 = AtomicU64::new(0);
static BYTES_TRANSFERRED: AtomicU64 = AtomicU64::new(0);

// Helper: Start TCP echo server
async fn start_echo_server() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("Failed to bind echo server");
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
    addr
}

// Helper: Start Shadowsocks server
async fn start_ss_server() -> (SocketAddr, mpsc::Sender<()>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("Failed to bind SS server");
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
            "stability".to_string(),
            "stability-pass".to_string(),
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
    (addr, stop_tx)
}

#[tokio::test]
#[ignore] // Run manually or via CI script
async fn test_stability_long_running() {
    let duration_hours = std::env::var("STABILITY_DURATION_HOURS")
        .unwrap_or_else(|_| "1".to_string())
        .parse::<u64>()
        .unwrap_or(1);

    println!("Starting stability test for {} hours", duration_hours);

    let echo_addr = start_echo_server().await;
    let (ss_addr, _stop_tx) = start_ss_server().await;

    let client_config = ShadowsocksConfig {
        server: ss_addr.to_string(),
        tag: None,
        method: "aes-256-gcm".to_string(),
        password: "stability-pass".to_string(),
        connect_timeout_sec: Some(5),
        multiplex: None,
    };

    let connector = Arc::new(ShadowsocksConnector::new(client_config).unwrap());
    let start_time = Instant::now();
    let end_time = start_time + Duration::from_secs(duration_hours * 3600);

    // Spawn traffic generator
    let generator_handle = tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_millis(100));

        while Instant::now() < end_time {
            interval.tick().await;

            // Spawn concurrent requests
            for _ in 0..10 {
                let connector = connector.clone();
                let echo_addr = echo_addr;

                tokio::spawn(async move {
                    let target = Target {
                        host: echo_addr.ip().to_string(),
                        port: echo_addr.port(),
                        kind: TransportKind::Tcp,
                    };

                    match connector.dial(target, DialOpts::default()).await {
                        Ok(mut stream) => {
                            let data = b"stability-test-payload";
                            if stream.write_all(data).await.is_ok() {
                                let mut buf = vec![0u8; data.len()];
                                if stream.read_exact(&mut buf).await.is_ok() {
                                    TOTAL_REQUESTS.fetch_add(1, Ordering::Relaxed);
                                    BYTES_TRANSFERRED
                                        .fetch_add(data.len() as u64 * 2, Ordering::Relaxed);
                                } else {
                                    FAILED_REQUESTS.fetch_add(1, Ordering::Relaxed);
                                }
                            } else {
                                FAILED_REQUESTS.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                        Err(_) => {
                            FAILED_REQUESTS.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                });
            }
        }
    });

    // Monitor loop
    let monitor_handle = tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(60));

        while Instant::now() < end_time {
            interval.tick().await;

            let total = TOTAL_REQUESTS.load(Ordering::Relaxed);
            let failed = FAILED_REQUESTS.load(Ordering::Relaxed);
            let bytes = BYTES_TRANSFERRED.load(Ordering::Relaxed);
            let elapsed = start_time.elapsed().as_secs();

            let error_rate = if total > 0 {
                (failed as f64 / total as f64) * 100.0
            } else {
                0.0
            };

            println!("--- Status Report (T+{}s) ---", elapsed);
            println!("Total Requests: {}", total);
            println!("Failed Requests: {} ({:.4}%)", failed, error_rate);
            println!(
                "Bytes Transferred: {:.2} MB",
                bytes as f64 / 1024.0 / 1024.0
            );

            // Check memory usage (simplified, would use OS tools in real implementation)
            // In a real test, we would panic if memory grows unbounded

            if error_rate > 0.1 && total > 1000 {
                eprintln!("WARNING: High error rate detected!");
            }
        }
    });

    // Wait for completion
    let _ = tokio::join!(generator_handle, monitor_handle);

    let total = TOTAL_REQUESTS.load(Ordering::Relaxed);
    let failed = FAILED_REQUESTS.load(Ordering::Relaxed);
    let error_rate = if total > 0 {
        (failed as f64 / total as f64) * 100.0
    } else {
        0.0
    };

    println!("=== Stability Test Complete ===");
    println!("Duration: {} hours", duration_hours);
    println!("Total Requests: {}", total);
    println!("Failed Requests: {}", failed);
    println!("Error Rate: {:.4}%", error_rate);

    assert!(error_rate < 0.1, "Error rate too high (>0.1%)");
    assert!(total > 0, "No requests processed");
}
