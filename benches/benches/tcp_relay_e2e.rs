use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use sb_benches::{generate_random_data, setup_tracing};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;

/// Relay pump: single-direction copy with a fixed buffer (mirrors metered.rs pump)
async fn pump<R, W>(mut r: R, mut w: W, buf_size: usize) -> u64
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; buf_size];
    let mut total = 0u64;
    loop {
        let n = r.read(&mut buf).await.unwrap();
        if n == 0 {
            let _ = w.flush().await;
            let _ = tokio::io::AsyncWriteExt::shutdown(&mut w).await;
            break;
        }
        w.write_all(&buf[..n]).await.unwrap();
        total += n as u64;
    }
    total
}

/// Benchmark: client → relay → echo server → relay → client
async fn bench_relay_throughput(payload: &[u8], relay_buf_size: usize) {
    // Echo server
    let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_addr = echo.local_addr().unwrap();

    // Relay listener (client connects here)
    let relay_in = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let relay_addr = relay_in.local_addr().unwrap();

    let payload_len = payload.len();

    // Spawn echo server
    tokio::spawn(async move {
        let (mut sock, _) = echo.accept().await.unwrap();
        let mut buf = vec![0u8; 65536];
        let mut remaining = payload_len;
        while remaining > 0 {
            let n = sock.read(&mut buf).await.unwrap();
            if n == 0 {
                break;
            }
            sock.write_all(&buf[..n]).await.unwrap();
            remaining -= n;
        }
    });

    // Spawn relay: accept from client, connect to echo, bidirectional copy
    tokio::spawn(async move {
        let (client_stream, _) = relay_in.accept().await.unwrap();
        let echo_stream = tokio::net::TcpStream::connect(echo_addr).await.unwrap();

        let (cr, cw) = tokio::io::split(client_stream);
        let (er, ew) = tokio::io::split(echo_stream);

        // Bidirectional pump (mirrors real relay)
        tokio::join!(pump(cr, ew, relay_buf_size), pump(er, cw, relay_buf_size),);
    });

    // Client: send payload, receive echo
    let mut client = tokio::net::TcpStream::connect(relay_addr).await.unwrap();
    client.write_all(payload).await.unwrap();
    client.shutdown().await.unwrap();

    let mut received = vec![0u8; payload_len];
    client.read_exact(&mut received).await.unwrap();
}

fn tcp_relay_throughput(c: &mut Criterion) {
    setup_tracing();
    let rt = tokio::runtime::Runtime::new().unwrap();

    let mut group = c.benchmark_group("tcp_relay_e2e");
    group.measurement_time(Duration::from_secs(10));
    group.sample_size(30);

    // Buffer size matches metered.rs pump (16KB)
    let relay_buf = 16 * 1024;

    for size in [1024usize, 64 * 1024, 1024 * 1024] {
        let payload = Arc::new(generate_random_data(size));
        group.throughput(Throughput::Bytes(size as u64 * 2)); // round-trip
        group.bench_with_input(BenchmarkId::new("buf_16k", size), &size, |b, _| {
            let data = payload.clone();
            b.to_async(&rt).iter(|| {
                let d = data.clone();
                async move {
                    bench_relay_throughput(&d, relay_buf).await;
                    black_box(())
                }
            });
        });
    }

    // Also test with 64KB buffer to show buffer size impact
    for size in [64 * 1024usize, 1024 * 1024] {
        let payload = Arc::new(generate_random_data(size));
        group.throughput(Throughput::Bytes(size as u64 * 2));
        group.bench_with_input(BenchmarkId::new("buf_64k", size), &size, |b, _| {
            let data = payload.clone();
            b.to_async(&rt).iter(|| {
                let d = data.clone();
                async move {
                    bench_relay_throughput(&d, 64 * 1024).await;
                    black_box(())
                }
            });
        });
    }

    group.finish();
}

criterion_group!(benches, tcp_relay_throughput);
criterion_main!(benches);
