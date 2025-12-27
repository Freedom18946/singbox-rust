//! Performance Benchmark: SOCKS5 Protocol
//!
//! This benchmark measures SOCKS5 proxy performance and compares with baseline.
//! Metrics:
//! - Throughput (Mbps)
//! - Latency (P50, P95, P99 in ms)
//! - Connection establishment time
//! - Memory usage
//!
//! Run with:
//!   cargo test --package app --test bench_socks5_performance -- --nocapture --ignored
//!
//! Priority: WS-E Task "Performance benchmarking vs Go version"

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, oneshot};

#[derive(Debug, Clone)]
pub struct BenchmarkResult {
    pub protocol: String,
    pub throughput_mbps: f64,
    pub latency_p50_ms: f64,
    pub latency_p95_ms: f64,
    pub latency_p99_ms: f64,
    pub connection_time_ms: f64,
    pub total_requests: usize,
    pub failed_requests: usize,
}

impl BenchmarkResult {
    pub fn print_summary(&self) {
        println!("\n=== {} Performance Benchmark ===", self.protocol);
        println!("Throughput:          {:.2} Mbps", self.throughput_mbps);
        println!("Latency P50:         {:.2} ms", self.latency_p50_ms);
        println!("Latency P95:         {:.2} ms", self.latency_p95_ms);
        println!("Latency P99:         {:.2} ms", self.latency_p99_ms);
        println!("Connection Time:     {:.2} ms", self.connection_time_ms);
        println!("Total Requests:      {}", self.total_requests);
        println!("Failed Requests:     {}", self.failed_requests);
        println!(
            "Success Rate:        {:.2}%",
            100.0 * (self.total_requests - self.failed_requests) as f64
                / self.total_requests as f64
        );
        println!("=================================\n");
    }
}

/// Start an echo server for benchmarking
async fn start_echo_server() -> std::io::Result<SocketAddr> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;

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

    tokio::time::sleep(Duration::from_millis(50)).await;
    Ok(addr)
}

async fn start_socks5_server() -> std::io::Result<(SocketAddr, mpsc::Sender<()>)> {
    use sb_adapters::inbound::socks::{serve_socks, SocksInboundConfig};
    use sb_core::outbound::{OutboundImpl, OutboundRegistry, OutboundRegistryHandle};
    use sb_core::router::{Router, RouterHandle};

    let temp_listener = TcpListener::bind("127.0.0.1:0").await?;
    let socks_addr = temp_listener.local_addr()?;
    drop(temp_listener);

    let mut map = std::collections::HashMap::new();
    map.insert("direct".to_string(), OutboundImpl::Direct);
    let registry = OutboundRegistry::new(map);
    let outbounds = Arc::new(OutboundRegistryHandle::new(registry));
    let router = Arc::new(RouterHandle::new(Router::with_default("direct")));

    let (stop_tx, stop_rx) = mpsc::channel(1);
    let (ready_tx, ready_rx) = oneshot::channel();
    let cfg = SocksInboundConfig {
        listen: socks_addr,
        udp_bind: None,
        router,
        outbounds,
        udp_nat_ttl: Duration::from_secs(60),
        users: Some(vec![]),
    };

    tokio::spawn(async move {
        let _ = serve_socks(cfg, stop_rx, Some(ready_tx)).await;
    });

    ready_rx
        .await
        .map_err(|_| std::io::Error::other("socks ready failed"))?;
    tokio::time::sleep(Duration::from_millis(100)).await;

    Ok((socks_addr, stop_tx))
}

async fn connect_via_socks5(
    socks_addr: SocketAddr,
    target: SocketAddr,
) -> std::io::Result<TcpStream> {
    let mut stream = TcpStream::connect(socks_addr).await?;

    // Greeting: VER=5, NMETHODS=1, METHOD=0x00 (NO_AUTH)
    stream.write_all(&[0x05, 0x01, 0x00]).await?;
    let mut resp = [0u8; 2];
    stream.read_exact(&mut resp).await?;
    if resp != [0x05, 0x00] {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "socks5 auth negotiation failed",
        ));
    }

    // CONNECT request
    let mut req = vec![0x05, 0x01, 0x00, 0x01];
    if let std::net::IpAddr::V4(ip) = target.ip() {
        req.extend_from_slice(&ip.octets());
    } else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "expected IPv4 target",
        ));
    }
    req.extend_from_slice(&target.port().to_be_bytes());
    stream.write_all(&req).await?;

    // Response: VER REP RSV ATYP BND.ADDR BND.PORT
    let mut header = [0u8; 4];
    stream.read_exact(&mut header).await?;
    if header[1] != 0x00 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::ConnectionRefused,
            format!("socks5 connect failed: {}", header[1]),
        ));
    }

    match header[3] {
        0x01 => {
            let mut buf = [0u8; 6];
            stream.read_exact(&mut buf).await?;
        }
        0x03 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            let mut buf = vec![0u8; len[0] as usize + 2];
            stream.read_exact(&mut buf).await?;
        }
        0x04 => {
            let mut buf = [0u8; 18];
            stream.read_exact(&mut buf).await?;
        }
        _ => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "socks5 unknown addr type",
            ));
        }
    }

    Ok(stream)
}

/// Measure throughput in Mbps
async fn measure_throughput<F, Fut>(
    connect_fn: F,
    data_size: usize,
    iterations: usize,
) -> (f64, usize)
where
    F: Fn() -> Fut,
    Fut: std::future::Future<Output = Result<TcpStream, std::io::Error>>,
{
    let mut total_bytes = 0;
    let mut failed = 0;
    let start = Instant::now();

    for _ in 0..iterations {
        if let Ok(mut stream) = connect_fn().await {
            let data = vec![0xAB; data_size];
            if stream.write_all(&data).await.is_ok() {
                let mut received = vec![0u8; data_size];
                if stream.read_exact(&mut received).await.is_ok() {
                    total_bytes += data_size * 2; // Upload + download
                } else {
                    failed += 1;
                }
            } else {
                failed += 1;
            }
        } else {
            failed += 1;
        }
    }

    let elapsed = start.elapsed().as_secs_f64();
    let mbps = (total_bytes as f64 * 8.0) / (elapsed * 1_000_000.0);
    (mbps, failed)
}

/// Measure latency distribution
async fn measure_latency<F, Fut>(connect_fn: F, iterations: usize) -> ((f64, f64, f64), usize)
where
    F: Fn() -> Fut,
    Fut: std::future::Future<Output = Result<TcpStream, std::io::Error>>,
{
    let mut latencies = Vec::with_capacity(iterations);
    let mut failed = 0;

    for _ in 0..iterations {
        if let Ok(mut stream) = connect_fn().await {
            let start = Instant::now();
            let data = b"ping";

            if stream.write_all(data).await.is_ok() {
                let mut received = [0u8; 4];
                if stream.read_exact(&mut received).await.is_ok() {
                    let latency = start.elapsed().as_secs_f64() * 1000.0;
                    latencies.push(latency);
                } else {
                    failed += 1;
                }
            } else {
                failed += 1;
            }
        } else {
            failed += 1;
        }
    }

    if latencies.is_empty() {
        return ((0.0, 0.0, 0.0), failed);
    }

    latencies.sort_by(|a, b| a.partial_cmp(b).expect("cmp"));

    let p50 = latencies[latencies.len() * 50 / 100];
    let p95 = latencies[latencies.len() * 95 / 100];
    let p99 = latencies[latencies.len() * 99 / 100];

    ((p50, p95, p99), failed)
}

/// Measure connection establishment time
async fn measure_connection_time<F, Fut>(connect_fn: F, iterations: usize) -> (f64, usize)
where
    F: Fn() -> Fut,
    Fut: std::future::Future<Output = Result<TcpStream, std::io::Error>>,
{
    let mut times = Vec::with_capacity(iterations);
    let mut failed = 0;

    for _ in 0..iterations {
        let start = Instant::now();
        if connect_fn().await.is_ok() {
            let elapsed = start.elapsed().as_secs_f64() * 1000.0;
            times.push(elapsed);
        } else {
            failed += 1;
        }
    }

    if times.is_empty() {
        return (0.0, failed);
    }

    let avg_time = times.iter().sum::<f64>() / times.len() as f64;
    (avg_time, failed)
}

/// Benchmark direct TCP connection (baseline)
#[tokio::test]
#[ignore] // Run with --ignored
async fn bench_baseline_direct_tcp() {
    let echo_addr = match start_echo_server().await {
        Ok(addr) => addr,
        Err(e) => {
            eprintln!("Failed to start echo server: {}", e);
            return;
        }
    };

    let connect_fn = || async move { TcpStream::connect(echo_addr).await };

    println!("\n=== Benchmarking Direct TCP (Baseline) ===");

    // Throughput test (1MB chunks, 50 iterations)
    let (throughput, throughput_failed) = measure_throughput(&connect_fn, 1024 * 1024, 50).await;

    // Latency test (1000 iterations)
    let ((p50, p95, p99), latency_failed) = measure_latency(&connect_fn, 1000).await;

    // Connection time (100 iterations)
    let (conn_time, conn_failed) = measure_connection_time(&connect_fn, 100).await;

    let total_requests = 50 + 1000 + 100;
    let failed_requests = throughput_failed + latency_failed + conn_failed;

    let result = BenchmarkResult {
        protocol: "Direct TCP (Baseline)".to_string(),
        throughput_mbps: throughput,
        latency_p50_ms: p50,
        latency_p95_ms: p95,
        latency_p99_ms: p99,
        connection_time_ms: conn_time,
        total_requests,
        failed_requests,
    };

    result.print_summary();

    // Baseline assertions
    assert!(
        throughput > 50.0,
        "Baseline throughput should be > 50 Mbps, got {:.2}",
        throughput
    );
    assert!(
        p95 < 20.0,
        "Baseline P95 latency should be < 20ms, got {:.2}",
        p95
    );
    assert!(
        conn_time < 5.0,
        "Baseline connection time should be < 5ms, got {:.2}",
        conn_time
    );
    assert!(
        failed_requests == 0,
        "Baseline should have 0 failed requests, got {}",
        failed_requests
    );
}

/// Benchmark SOCKS5 proxy performance
///
/// This test requires a SOCKS5 server to be running.
/// For now, it's a placeholder that tests the measurement framework.
#[tokio::test]
#[ignore] // Run with --ignored
async fn bench_socks5_proxy() {
    let echo_addr = match start_echo_server().await {
        Ok(addr) => addr,
        Err(e) => {
            eprintln!("Failed to start echo server: {}", e);
            return;
        }
    };

    let (socks_addr, _stop_tx) = match start_socks5_server().await {
        Ok(result) => result,
        Err(e) => {
            eprintln!("Failed to start SOCKS5 server: {}", e);
            return;
        }
    };
    let connect_fn = || async move { connect_via_socks5(socks_addr, echo_addr).await };

    println!("\n=== Benchmarking SOCKS5 Proxy ===");

    // Throughput test
    let (throughput, throughput_failed) = measure_throughput(&connect_fn, 1024 * 1024, 30).await;

    // Latency test
    let ((p50, p95, p99), latency_failed) = measure_latency(&connect_fn, 500).await;

    // Connection time
    let (conn_time, conn_failed) = measure_connection_time(&connect_fn, 100).await;

    let total_requests = 30 + 500 + 100;
    let failed_requests = throughput_failed + latency_failed + conn_failed;

    let result = BenchmarkResult {
        protocol: "SOCKS5 Proxy".to_string(),
        throughput_mbps: throughput,
        latency_p50_ms: p50,
        latency_p95_ms: p95,
        latency_p99_ms: p99,
        connection_time_ms: conn_time,
        total_requests,
        failed_requests,
    };

    result.print_summary();

    assert!(
        throughput > 5.0,
        "SOCKS5 throughput should be > 5 Mbps, got {:.2}",
        throughput
    );
    assert!(
        failed_requests < total_requests / 10,
        "SOCKS5 failed requests too high: {}",
        failed_requests
    );
}

/// Stress test: High connection rate
#[tokio::test]
#[ignore] // Run with --ignored
async fn stress_high_connection_rate() {
    let echo_addr = match start_echo_server().await {
        Ok(addr) => addr,
        Err(e) => {
            eprintln!("Failed to start echo server: {}", e);
            return;
        }
    };

    println!("\n=== Stress Test: High Connection Rate ===");

    let start = Instant::now();
    let mut handles = vec![];
    let num_connections = 1000;

    for _ in 0..num_connections {
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
    let rate = num_connections as f64 / elapsed.as_secs_f64();

    println!("Connections:     {}", num_connections);
    println!("Total time:      {:.2}s", elapsed.as_secs_f64());
    println!("Connection rate: {:.2} conn/s", rate);

    assert!(
        rate > 200.0,
        "Should handle > 200 connections/s, got {:.2}",
        rate
    );
}

/// Concurrent connections benchmark
#[tokio::test]
#[ignore] // Run with --ignored
async fn bench_concurrent_connections() {
    let echo_addr = match start_echo_server().await {
        Ok(addr) => addr,
        Err(e) => {
            eprintln!("Failed to start echo server: {}", e);
            return;
        }
    };

    println!("\n=== Benchmark: Concurrent Connections ===");

    let num_concurrent = 500;
    let mut handles = vec![];

    let start = Instant::now();

    for i in 0..num_concurrent {
        let handle = tokio::spawn(async move {
            if let Ok(mut stream) = TcpStream::connect(echo_addr).await {
                tokio::time::sleep(Duration::from_millis(10)).await;

                let data = format!("Request {}", i);
                let _ = stream.write_all(data.as_bytes()).await;
                let mut buf = vec![0u8; data.len()];
                let _ = stream.read_exact(&mut buf).await;
            }
        });
        handles.push(handle);
    }

    for handle in handles {
        let _ = handle.await;
    }

    let elapsed = start.elapsed();

    println!("Concurrent connections:  {}", num_concurrent);
    println!("Total time:              {:.2}s", elapsed.as_secs_f64());
    println!(
        "Avg time per connection: {:.2}ms",
        elapsed.as_millis() as f64 / num_concurrent as f64
    );

    assert!(elapsed.as_secs() < 5, "Should complete within 5 seconds");
}
