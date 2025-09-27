//! Connection benchmarks for sb-adapters
//!
//! Measures SOCKS5 and HTTP CONNECT performance with mock proxies
//! to establish baseline performance metrics for adapter implementations.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use anyhow;
use sb_adapters::{
    outbound::{http::HttpProxyConnector, socks5::Socks5Connector},
    traits::{DialOpts, OutboundConnector, Target, ResolveMode, RetryPolicy},
    Result,
};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::runtime::Runtime;

/// Mock SOCKS5 proxy server for benchmarking
struct MockSocksProxy {
    listener: TcpListener,
}

impl MockSocksProxy {
    async fn new() -> Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        Ok(Self { listener })
    }

    fn addr(&self) -> String {
        self.listener.local_addr().unwrap().to_string()
    }

    /// Handle SOCKS5 connections with minimal overhead
    async fn run(&self) -> Result<()> {
        loop {
            let (mut stream, _) = self.listener.accept().await?;

            tokio::spawn(async move {
                // Fast SOCKS5 handshake without full validation
                let mut buf = [0u8; 512];

                // Read auth methods
                if stream.read(&mut buf).await.unwrap_or(0) < 2 {
                    return;
                }

                // Send no auth
                let _ = stream.write_all(&[0x05, 0x00]).await;

                // Read CONNECT request
                if stream.read(&mut buf).await.unwrap_or(0) < 4 {
                    return;
                }

                // Send success response (IPv4 0.0.0.0:0)
                let response = [0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
                let _ = stream.write_all(&response).await;

                // Keep connection alive briefly
                tokio::time::sleep(Duration::from_millis(1)).await;
            });
        }
    }
}

/// Mock HTTP proxy server for benchmarking
struct MockHttpProxy {
    listener: TcpListener,
}

impl MockHttpProxy {
    async fn new() -> Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        Ok(Self { listener })
    }

    fn addr(&self) -> String {
        self.listener.local_addr().unwrap().to_string()
    }

    /// Handle HTTP CONNECT with minimal overhead
    async fn run(&self) -> Result<()> {
        loop {
            let (mut stream, _) = self.listener.accept().await?;

            tokio::spawn(async move {
                let mut buf = vec![0u8; 1024];

                // Read HTTP request
                if stream.read(&mut buf).await.unwrap_or(0) == 0 {
                    return;
                }

                // Send 200 Connection established
                let response = "HTTP/1.1 200 Connection established\r\n\r\n";
                let _ = stream.write_all(response.as_bytes()).await;

                // Keep connection alive briefly
                tokio::time::sleep(Duration::from_millis(1)).await;
            });
        }
    }
}

/// Benchmark SOCKS5 CONNECT performance
async fn bench_socks_connect(proxy_addr: &str, concurrency: usize) -> Result<()> {
    let connector = Socks5Connector::no_auth(proxy_addr.to_string());
    let target = Target::tcp("example.com", 80);
    let opts = DialOpts {
        connect_timeout: Duration::from_secs(5),
        read_timeout: Duration::from_secs(5),
        retry_policy: RetryPolicy::new().with_max_retries(0), // No retries for clean benchmarks
        resolve_mode: ResolveMode::Remote,
    };

    if concurrency == 1 {
        // Sequential benchmark
        let _stream = connector.dial(target, opts).await?;
    } else {
        // Concurrent benchmark
        let mut handles = Vec::with_capacity(concurrency);

        for _ in 0..concurrency {
            let connector = connector.clone();
            let target = target.clone();
            let opts = opts.clone();

            let handle = tokio::spawn(async move {
                connector.dial(target, opts).await
            });
            handles.push(handle);
        }

        // Wait for all connections
        for handle in handles {
            let _ = handle.await.map_err(anyhow::Error::from)??;
        }
    }

    Ok(())
}

/// Benchmark HTTP CONNECT performance
async fn bench_http_connect(proxy_addr: &str, concurrency: usize) -> Result<()> {
    let connector = HttpProxyConnector::no_auth(proxy_addr.to_string());
    let target = Target::tcp("example.com", 80);
    let opts = DialOpts {
        connect_timeout: Duration::from_secs(5),
        read_timeout: Duration::from_secs(5),
        retry_policy: RetryPolicy::new().with_max_retries(0),
        resolve_mode: ResolveMode::Remote,
    };

    if concurrency == 1 {
        // Sequential benchmark
        let _stream = connector.dial(target, opts).await?;
    } else {
        // Concurrent benchmark
        let mut handles = Vec::with_capacity(concurrency);

        for _ in 0..concurrency {
            let connector = connector.clone();
            let target = target.clone();
            let opts = opts.clone();

            let handle = tokio::spawn(async move {
                connector.dial(target, opts).await
            });
            handles.push(handle);
        }

        // Wait for all connections
        for handle in handles {
            let _ = handle.await.map_err(anyhow::Error::from)??;
        }
    }

    Ok(())
}

/// Criterion benchmark for SOCKS5 connections
fn socks_connect_bench(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    // Start mock SOCKS proxy
    let proxy = rt.block_on(async { MockSocksProxy::new().await }).unwrap();
    let proxy_addr = proxy.addr();

    let proxy_arc = Arc::new(proxy);
    let proxy_clone = proxy_arc.clone();
    rt.spawn(async move {
        let _ = proxy_clone.run().await;
    });

    // Give proxy time to start
    std::thread::sleep(Duration::from_millis(10));

    let mut group = c.benchmark_group("socks_connect");
    group.throughput(Throughput::Elements(1));

    // Sequential benchmark
    group.bench_with_input(
        BenchmarkId::new("sequential", 1),
        &1usize,
        |b, &concurrency| {
            b.to_async(&rt).iter(|| async {
                let result = bench_socks_connect(&proxy_addr, concurrency).await;
                black_box(result)
            });
        },
    );

    // Concurrent benchmarks
    for &concurrency in [32, 64].iter() {
        group.bench_with_input(
            BenchmarkId::new("concurrent", concurrency),
            &concurrency,
            |b, &concurrency| {
                b.to_async(&rt).iter(|| async {
                    let result = bench_socks_connect(&proxy_addr, concurrency).await;
                    black_box(result)
                });
            },
        );
    }

    group.finish();
}

/// Criterion benchmark for HTTP connections
fn http_connect_bench(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    // Start mock HTTP proxy
    let proxy = rt.block_on(async { MockHttpProxy::new().await }).unwrap();
    let proxy_addr = proxy.addr();

    let proxy_arc = Arc::new(proxy);
    let proxy_clone = proxy_arc.clone();
    rt.spawn(async move {
        let _ = proxy_clone.run().await;
    });

    // Give proxy time to start
    std::thread::sleep(Duration::from_millis(10));

    let mut group = c.benchmark_group("http_connect");
    group.throughput(Throughput::Elements(1));

    // Sequential benchmark
    group.bench_with_input(
        BenchmarkId::new("sequential", 1),
        &1usize,
        |b, &concurrency| {
            b.to_async(&rt).iter(|| async {
                let result = bench_http_connect(&proxy_addr, concurrency).await;
                black_box(result)
            });
        },
    );

    // Concurrent benchmarks
    for &concurrency in [32, 64].iter() {
        group.bench_with_input(
            BenchmarkId::new("concurrent", concurrency),
            &concurrency,
            |b, &concurrency| {
                b.to_async(&rt).iter(|| async {
                    let result = bench_http_connect(&proxy_addr, concurrency).await;
                    black_box(result)
                });
            },
        );
    }

    group.finish();
}

/// Performance comparison benchmark
fn adapter_comparison_bench(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    // Start both mock servers
    let socks_proxy = rt.block_on(async { MockSocksProxy::new().await }).unwrap();
    let socks_addr = socks_proxy.addr();
    let socks_arc = Arc::new(socks_proxy);
    let socks_clone = socks_arc.clone();
    rt.spawn(async move {
        let _ = socks_clone.run().await;
    });

    let http_proxy = rt.block_on(async { MockHttpProxy::new().await }).unwrap();
    let http_addr = http_proxy.addr();
    let http_arc = Arc::new(http_proxy);
    let http_clone = http_arc.clone();
    rt.spawn(async move {
        let _ = http_clone.run().await;
    });

    std::thread::sleep(Duration::from_millis(20));

    let mut group = c.benchmark_group("adapter_comparison");
    group.throughput(Throughput::Elements(1));

    // Compare SOCKS vs HTTP sequential performance
    group.bench_function("socks5_single", |b| {
        b.to_async(&rt).iter(|| async {
            let result = bench_socks_connect(&socks_addr, 1).await;
            black_box(result)
        });
    });

    group.bench_function("http_single", |b| {
        b.to_async(&rt).iter(|| async {
            let result = bench_http_connect(&http_addr, 1).await;
            black_box(result)
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    socks_connect_bench,
    http_connect_bench,
    adapter_comparison_bench
);
criterion_main!(benches);