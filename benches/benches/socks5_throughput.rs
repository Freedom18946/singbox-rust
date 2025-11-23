use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use sb_benches::{generate_random_bytes, setup_tracing};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// Benchmark SOCKS5 protocol handshake
async fn bench_socks5_handshake() -> anyhow::Result<()> {
    // Create a simple SOCKS5 server
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;

    // Spawn server task
    tokio::spawn(async move {
        if let Ok((mut socket, _)) = listener.accept().await {
            // SOCKS5 greeting
            let mut buf = [0u8; 2];
            let _ = socket.read_exact(&mut buf).await;
            // Response: version 5, no auth
            let _ = socket.write_all(&[5, 0]).await;

            // SOCKS5 request
            let mut buf = [0u8; 10];
            let _ = socket.read(&mut buf).await;
            // Response: succeeded
            let response = [5, 0, 0, 1, 0, 0, 0, 0, 0, 0];
            let _ = socket.write_all(&response).await;
        }
    });

    // Client handshake
    let mut stream = TcpStream::connect(addr).await?;

    // Send greeting
    stream.write_all(&[5, 1, 0]).await?;

    // Read response
    let mut buf = [0u8; 2];
    stream.read_exact(&mut buf).await?;

    // Send CONNECT request
    let request = [5, 1, 0, 1, 127, 0, 0, 1, 0, 80];
    stream.write_all(&request).await?;

    // Read response
    let mut buf = [0u8; 10];
    stream.read_exact(&mut buf).await?;

    Ok(())
}

/// Benchmark SOCKS5 data throughput
async fn bench_socks5_throughput(data_size: usize) -> anyhow::Result<Duration> {
    let data = generate_random_bytes(data_size);

    // Simple echo server
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;

    tokio::spawn(async move {
        if let Ok((mut socket, _)) = listener.accept().await {
            let mut buf = vec![0u8; 65536];
            while let Ok(n) = socket.read(&mut buf).await {
                if n == 0 {
                    break;
                }
                let _ = socket.write_all(&buf[..n]).await;
            }
        }
    });

    let mut stream = TcpStream::connect(addr).await?;

    let start = std::time::Instant::now();
    stream.write_all(&data).await?;

    let mut received = vec![0u8; data_size];
    stream.read_exact(&mut received).await?;

    Ok(start.elapsed())
}

fn socks5_handshake(c: &mut Criterion) {
    setup_tracing();

    let rt = tokio::runtime::Runtime::new().unwrap();

    c.bench_function("socks5_handshake", |b| {
        b.to_async(&rt)
            .iter(|| async { black_box(bench_socks5_handshake().await) });
    });
}

fn socks5_throughput(c: &mut Criterion) {
    setup_tracing();

    let rt = tokio::runtime::Runtime::new().unwrap();
    let mut group = c.benchmark_group("socks5_throughput");

    // Test different payload sizes
    for size in [1024, 65536, 1_048_576] {
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, &size| {
            b.to_async(&rt)
                .iter(|| async move { black_box(bench_socks5_throughput(size).await) });
        });
    }

    group.finish();
}

criterion_group!(
    name = benches;
    config = Criterion::default()
        .measurement_time(Duration::from_secs(10))
        .sample_size(50);
    targets = socks5_handshake, socks5_throughput
);
criterion_main!(benches);
