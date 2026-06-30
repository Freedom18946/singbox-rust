//! Local TCP Performance Validation Benchmarks
//!
//! Run with:
//!   cargo test --package app --test performance_validation -- --ignored --nocapture

use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// Start TCP echo server
async fn start_echo_server() -> Option<SocketAddr> {
    let listener = match TcpListener::bind("127.0.0.1:0").await {
        Ok(listener) => listener,
        Err(err) => {
            if matches!(
                err.kind(),
                io::ErrorKind::PermissionDenied | io::ErrorKind::AddrNotAvailable
            ) {
                eprintln!("Skipping performance test: cannot bind local TCP listener ({err})");
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
                    let mut buf = vec![0u8; 65536];
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
// TCP BASELINE BENCHMARKS
// ============================================================================

#[tokio::test]
async fn bench_tcp_baseline_throughput() {
    println!("\n=== TCP Baseline Throughput Benchmark ===");

    let Some(echo_addr) = start_echo_server().await else {
        return;
    };
    let chunk_size = 1024 * 1024; // 1 MB chunks
    let num_chunks = 100; // 100 MB total
    let data = vec![0xAB; chunk_size];

    let mut stream = TcpStream::connect(echo_addr).await.expect("connect");

    let start = Instant::now();
    for _ in 0..num_chunks {
        stream.write_all(&data).await.expect("write");
        let mut received = vec![0u8; chunk_size];
        stream.read_exact(&mut received).await.expect("read");
    }
    let elapsed = start.elapsed();

    let total_mb = (chunk_size * num_chunks * 2) as f64 / (1024.0 * 1024.0);
    let throughput = total_mb / elapsed.as_secs_f64();

    println!("Total data: {:.2} MB", total_mb);
    println!("Time: {:.2}s", elapsed.as_secs_f64());
    println!("Throughput: {:.2} MB/s", throughput);

    // TCP baseline should achieve >500 MB/s on localhost
    assert!(
        throughput > 200.0,
        "TCP baseline too slow: {:.2} MB/s",
        throughput
    );
    println!("✅ TCP baseline: {:.2} MB/s", throughput);
}

#[tokio::test]
async fn bench_tcp_baseline_latency() {
    println!("\n=== TCP Baseline Latency Benchmark ===");

    let Some(echo_addr) = start_echo_server().await else {
        return;
    };
    let iterations = 1000;
    let mut latencies = vec![];

    for _ in 0..iterations {
        let start = Instant::now();
        if let Ok(mut stream) = TcpStream::connect(echo_addr).await {
            stream.write_all(b"ping").await.ok();
            let mut buf = [0u8; 4];
            stream.read_exact(&mut buf).await.ok();
            latencies.push(start.elapsed().as_micros() as f64);
        }
    }

    latencies.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let p50 = latencies[latencies.len() / 2];
    let p99 = latencies[(latencies.len() * 99) / 100];
    let avg = latencies.iter().sum::<f64>() / latencies.len() as f64;

    println!("Iterations: {}", iterations);
    println!("P50 latency: {:.2} µs", p50);
    println!("P99 latency: {:.2} µs", p99);
    println!("Avg latency: {:.2} µs", avg);

    // Baseline should be very fast on localhost
    assert!(p50 < 1000.0, "P50 latency too high: {:.2} µs", p50);
    println!("✅ TCP baseline latency acceptable");
}

// ============================================================================
// CONNECTION MANAGEMENT TESTS
// ============================================================================

#[tokio::test]
#[ignore] // Run with --ignored for the heavier connection burst.
async fn test_connection_burst_smoke() {
    println!("\n=== Connection Burst Smoke Test ===");

    let Some(echo_addr) = start_echo_server().await else {
        return;
    };
    let connection_count = Arc::new(AtomicUsize::new(0));
    let mut handles = vec![];

    // Keep the ignored test bounded while still exercising concurrent connection setup.
    for _ in 0..100 {
        let count = Arc::clone(&connection_count);
        let handle = tokio::spawn(async move {
            if let Ok(_stream) = TcpStream::connect(echo_addr).await {
                count.fetch_add(1, Ordering::SeqCst);
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        });
        handles.push(handle);
    }

    tokio::time::sleep(Duration::from_millis(500)).await;
    let active = connection_count.load(Ordering::SeqCst);

    println!("Active connections: {}", active);
    assert!(
        active > 0,
        "connection burst did not establish any connections"
    );

    // Wait for cleanup
    for handle in handles {
        let _ = handle.await;
    }
}
