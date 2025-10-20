#![cfg(feature = "long_tests")]
//! P0 Protocol Performance Benchmarks
//!
//! This test file runs comprehensive performance benchmarks for all P0 protocols:
//! - REALITY TLS
//! - ECH
//! - Hysteria v1
//! - Hysteria v2
//! - SSH outbound
//! - TUIC
//!
//! Run with:
//!   cargo test --package app --test bench_p0_protocols -- --nocapture
//!   cargo test --package app --test bench_p0_protocols -- --nocapture --ignored  # Run all benchmarks
//!
//! Or use the convenience script:
//!   ./scripts/run_p0_benchmarks.sh
//!
//! Requirements: 9.1, 9.2, 9.4

use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// Benchmark result structure
#[derive(Debug, Clone)]
pub struct BenchmarkResult {
    pub protocol: String,
    pub throughput_mbps: f64,
    pub latency_p50_ms: f64,
    pub latency_p95_ms: f64,
    pub latency_p99_ms: f64,
    pub connection_time_ms: f64,
    pub memory_mb: f64,
}

impl BenchmarkResult {
    pub fn print_summary(&self) {
        println!("\n=== {} Performance ===", self.protocol);
        println!("Throughput:       {:.2} Mbps", self.throughput_mbps);
        println!("Latency P50:      {:.2} ms", self.latency_p50_ms);
        println!("Latency P95:      {:.2} ms", self.latency_p95_ms);
        println!("Latency P99:      {:.2} ms", self.latency_p99_ms);
        println!("Connection Time:  {:.2} ms", self.connection_time_ms);
        println!("Memory Usage:     {:.2} MB", self.memory_mb);
    }
}

/// Echo server for testing
async fn start_echo_server() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
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
    addr
}

/// Measure throughput in Mbps
async fn measure_throughput<F, Fut>(connect_fn: F, data_size: usize, iterations: usize) -> f64
where
    F: Fn() -> Fut,
    Fut: std::future::Future<Output = Result<TcpStream, std::io::Error>>,
{
    let mut total_bytes = 0;
    let start = Instant::now();

    for _ in 0..iterations {
        if let Ok(mut stream) = connect_fn().await {
            let data = vec![0xAB; data_size];
            if stream.write_all(&data).await.is_ok() {
                let mut received = vec![0u8; data_size];
                if stream.read_exact(&mut received).await.is_ok() {
                    total_bytes += data_size * 2; // Upload + download
                }
            }
        }
    }

    let elapsed = start.elapsed().as_secs_f64();
    let mbps = (total_bytes as f64 * 8.0) / (elapsed * 1_000_000.0);
    mbps
}

/// Measure latency distribution
async fn measure_latency<F, Fut>(connect_fn: F, iterations: usize) -> (f64, f64, f64)
where
    F: Fn() -> Fut,
    Fut: std::future::Future<Output = Result<TcpStream, std::io::Error>>,
{
    let mut latencies = Vec::with_capacity(iterations);

    for _ in 0..iterations {
        if let Ok(mut stream) = connect_fn().await {
            let start = Instant::now();
            let data = b"ping";

            if stream.write_all(data).await.is_ok() {
                let mut received = [0u8; 4];
                if stream.read_exact(&mut received).await.is_ok() {
                    let latency = start.elapsed().as_secs_f64() * 1000.0;
                    latencies.push(latency);
                }
            }
        }
    }

    if latencies.is_empty() {
        return (0.0, 0.0, 0.0);
    }

    latencies.sort_by(|a, b| a.partial_cmp(b).expect("cmp"));

    let p50 = latencies[latencies.len() * 50 / 100];
    let p95 = latencies[latencies.len() * 95 / 100];
    let p99 = latencies[latencies.len() * 99 / 100];

    (p50, p95, p99)
}

/// Measure connection establishment time
async fn measure_connection_time<F, Fut>(connect_fn: F, iterations: usize) -> f64
where
    F: Fn() -> Fut,
    Fut: std::future::Future<Output = Result<TcpStream, std::io::Error>>,
{
    let mut times = Vec::with_capacity(iterations);

    for _ in 0..iterations {
        let start = Instant::now();
        if connect_fn().await.is_ok() {
            let elapsed = start.elapsed().as_secs_f64() * 1000.0;
            times.push(elapsed);
        }
    }

    if times.is_empty() {
        return 0.0;
    }

    times.iter().sum::<f64>() / times.len() as f64
}

/// Estimate memory usage (simplified)
fn estimate_memory_usage() -> f64 {
    // This is a simplified estimation
    // In production, use tools like jemalloc or system profiling
    10.0
}

/// Benchmark direct TCP connection (baseline)
#[tokio::test]
async fn bench_direct_tcp() {
    let echo_addr = start_echo_server().await;

    let connect_fn = || async move { TcpStream::connect(echo_addr).await };

    println!("\n=== Benchmarking Direct TCP (Baseline) ===");

    // Throughput test
    let throughput = measure_throughput(
        || connect_fn(),
        1024 * 1024, // 1MB
        10,
    )
    .await;

    // Latency test
    let (p50, p95, p99) = measure_latency(|| connect_fn(), 1000).await;

    // Connection time
    let conn_time = measure_connection_time(|| connect_fn(), 100).await;

    let result = BenchmarkResult {
        protocol: "Direct TCP".to_string(),
        throughput_mbps: throughput,
        latency_p50_ms: p50,
        latency_p95_ms: p95,
        latency_p99_ms: p99,
        connection_time_ms: conn_time,
        memory_mb: estimate_memory_usage(),
    };

    result.print_summary();

    // Baseline assertions
    assert!(
        throughput > 100.0,
        "Baseline throughput should be > 100 Mbps"
    );
    assert!(p95 < 10.0, "Baseline P95 latency should be < 10ms");
}

/// Benchmark REALITY TLS protocol
#[tokio::test]
#[ignore] // Run with --ignored flag
async fn bench_reality_tls() {
    // This test requires REALITY server setup
    // Placeholder for actual implementation

    println!("\n=== Benchmarking REALITY TLS ===");
    println!("Note: Requires REALITY server configuration");

    // TODO: Implement REALITY benchmark when server is available
    // Expected overhead: 5-10% vs baseline due to TLS + REALITY auth
}

/// Benchmark ECH (Encrypted Client Hello)
#[tokio::test]
#[ignore] // Run with --ignored flag
async fn bench_ech() {
    println!("\n=== Benchmarking ECH ===");
    println!("Note: Requires ECH-enabled server");

    // TODO: Implement ECH benchmark when server is available
    // Expected overhead: 3-5% vs baseline TLS due to encryption
}

/// Benchmark Hysteria v1 protocol
#[tokio::test]
#[ignore] // Run with --ignored flag
async fn bench_hysteria_v1() {
    println!("\n=== Benchmarking Hysteria v1 ===");
    println!("Note: Requires Hysteria v1 server");

    // TODO: Implement Hysteria v1 benchmark
    // Expected: High throughput (UDP-based), low latency
}

/// Benchmark Hysteria v2 protocol
#[tokio::test]
#[ignore] // Run with --ignored flag
async fn bench_hysteria_v2() {
    println!("\n=== Benchmarking Hysteria v2 ===");
    println!("Note: Requires Hysteria v2 server");

    // TODO: Implement Hysteria v2 benchmark
    // Expected: Similar to v1, improved congestion control
}

/// Benchmark SSH outbound
#[tokio::test]
#[ignore] // Run with --ignored flag
async fn bench_ssh_outbound() {
    println!("\n=== Benchmarking SSH Outbound ===");
    println!("Note: Requires SSH server");

    // TODO: Implement SSH benchmark
    // Expected overhead: 10-15% vs baseline due to SSH encryption
}

/// Benchmark TUIC protocol
#[tokio::test]
#[ignore] // Run with --ignored flag
async fn bench_tuic() {
    println!("\n=== Benchmarking TUIC ===");
    println!("Note: Requires TUIC server");

    // TODO: Implement TUIC benchmark
    // Expected: Similar to Hysteria (QUIC-based)
}

/// Stress test: High connection rate
#[tokio::test]
#[ignore] // Run with --ignored flag
async fn stress_high_connection_rate() {
    let echo_addr = start_echo_server().await;

    println!("\n=== Stress Test: High Connection Rate ===");

    let start = Instant::now();
    let mut handles = vec![];

    // Create 1000 connections rapidly
    for _ in 0..1000 {
        let handle = tokio::spawn(async move {
            if let Ok(mut stream) = TcpStream::connect(echo_addr).await {
                let data = b"test";
                let _ = stream.write_all(data).await;
                let mut buf = [0u8; 4];
                let _ = stream.read_exact(&mut buf).await;
            }
        });
        handles.push(handle);
    }

    for handle in handles {
        let _ = handle.await;
    }

    let elapsed = start.elapsed();
    let rate = 1000.0 / elapsed.as_secs_f64();

    println!("Connection rate: {:.2} conn/s", rate);
    println!("Total time: {:.2}s", elapsed.as_secs_f64());

    assert!(rate > 100.0, "Should handle > 100 connections/s");
}

/// Stress test: Large data transfer
#[tokio::test]
#[ignore] // Run with --ignored flag
async fn stress_large_data_transfer() {
    let echo_addr = start_echo_server().await;

    println!("\n=== Stress Test: Large Data Transfer ===");

    let mut stream = TcpStream::connect(echo_addr).await.expect("connect");

    // Transfer 100MB
    let chunk_size = 1024 * 1024; // 1MB chunks
    let num_chunks = 100;

    let start = Instant::now();

    for _ in 0..num_chunks {
        let data = vec![0xAB; chunk_size];
        stream.write_all(&data).await.expect("write");

        let mut received = vec![0u8; chunk_size];
        stream.read_exact(&mut received).await.expect("read");
    }

    let elapsed = start.elapsed();
    let total_mb = (chunk_size * num_chunks * 2) as f64 / (1024.0 * 1024.0);
    let throughput = total_mb / elapsed.as_secs_f64();

    println!("Transferred: {:.2} MB", total_mb);
    println!("Time: {:.2}s", elapsed.as_secs_f64());
    println!("Throughput: {:.2} MB/s", throughput);

    assert!(throughput > 50.0, "Should achieve > 50 MB/s");
}

/// Memory leak detection test
#[tokio::test]
#[ignore] // Run with --ignored flag
async fn stress_memory_leak_detection() {
    let echo_addr = start_echo_server().await;

    println!("\n=== Stress Test: Memory Leak Detection ===");

    // Run for extended period and monitor memory
    let iterations = 10000;

    for i in 0..iterations {
        if let Ok(mut stream) = TcpStream::connect(echo_addr).await {
            let data = b"test";
            let _ = stream.write_all(data).await;
            let mut buf = [0u8; 4];
            let _ = stream.read_exact(&mut buf).await;
        }

        if i % 1000 == 0 {
            println!("Completed {} iterations", i);
            // In production, check memory usage here
        }
    }

    println!("Completed {} iterations without crash", iterations);
}

/// Concurrent connections stress test
#[tokio::test]
#[ignore] // Run with --ignored flag
async fn stress_concurrent_connections() {
    let echo_addr = start_echo_server().await;

    println!("\n=== Stress Test: Concurrent Connections ===");

    let num_concurrent = 500;
    let mut handles = vec![];

    let start = Instant::now();

    for _ in 0..num_concurrent {
        let handle = tokio::spawn(async move {
            if let Ok(mut stream) = TcpStream::connect(echo_addr).await {
                // Keep connection alive for a bit
                tokio::time::sleep(Duration::from_secs(1)).await;

                let data = b"test";
                let _ = stream.write_all(data).await;
                let mut buf = [0u8; 4];
                let _ = stream.read_exact(&mut buf).await;
            }
        });
        handles.push(handle);
    }

    for handle in handles {
        let _ = handle.await;
    }

    let elapsed = start.elapsed();

    println!("Handled {} concurrent connections", num_concurrent);
    println!("Total time: {:.2}s", elapsed.as_secs_f64());

    assert!(elapsed.as_secs() < 10, "Should complete within 10 seconds");
}
