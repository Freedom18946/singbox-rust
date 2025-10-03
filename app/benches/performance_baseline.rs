//! Performance benchmark framework for singbox-rust
//!
//! Establishes baseline performance metrics for:
//! - Throughput (TCP/UDP)
//! - Latency (P50/P90/P95/P99)
//! - Memory usage
//! - Concurrent connections
//!
//! Comparison target: Go sing-box
//! Goal: ≥90% throughput, ≤110% latency P95

use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::Duration;

/// Benchmark TCP throughput: direct connection (baseline)
fn bench_tcp_direct_throughput(c: &mut Criterion) {
    let mut group = c.benchmark_group("tcp_throughput");
    group.throughput(Throughput::Bytes(1024 * 1024)); // 1MB

    // Start echo server
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    thread::spawn(move || {
        for stream in listener.incoming() {
            if let Ok(mut s) = stream {
                thread::spawn(move || {
                    let mut buf = [0u8; 8192];
                    loop {
                        match s.read(&mut buf) {
                            Ok(0) | Err(_) => break,
                            Ok(n) => {
                                let _ = s.write_all(&buf[..n]);
                            }
                        }
                    }
                });
            }
        }
    });

    thread::sleep(Duration::from_millis(100));

    group.bench_function("direct_1mb", |b| {
        b.iter(|| {
            let mut stream = TcpStream::connect(addr).unwrap();
            let data = vec![0xAB; 1024 * 1024]; // 1MB

            stream.write_all(&data).unwrap();

            let mut received = vec![0u8; data.len()];
            stream.read_exact(&mut received).unwrap();

            black_box(received);
        });
    });

    group.finish();
}

/// Benchmark latency: simple request-response
fn bench_latency_echo(c: &mut Criterion) {
    let mut group = c.benchmark_group("latency");
    group.sample_size(1000);

    // Start echo server
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    thread::spawn(move || {
        for stream in listener.incoming() {
            if let Ok(mut s) = stream {
                thread::spawn(move || {
                    let mut buf = [0u8; 128];
                    loop {
                        match s.read(&mut buf) {
                            Ok(0) | Err(_) => break,
                            Ok(n) => {
                                let _ = s.write_all(&buf[..n]);
                            }
                        }
                    }
                });
            }
        }
    });

    thread::sleep(Duration::from_millis(100));

    group.bench_function("echo_small_payload", |b| {
        b.iter(|| {
            let mut stream = TcpStream::connect(addr).unwrap();
            let data = b"Hello, World!"; // 13 bytes

            stream.write_all(data).unwrap();

            let mut received = [0u8; 13];
            stream.read_exact(&mut received).unwrap();

            black_box(received);
        });
    });

    group.finish();
}

/// Benchmark concurrent connections
fn bench_concurrent_connections(c: &mut Criterion) {
    let mut group = c.benchmark_group("concurrent");
    group.sample_size(10);

    // Start echo server
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    thread::spawn(move || {
        for stream in listener.incoming() {
            if let Ok(mut s) = stream {
                thread::spawn(move || {
                    let mut buf = [0u8; 1024];
                    loop {
                        match s.read(&mut buf) {
                            Ok(0) | Err(_) => break,
                            Ok(n) => {
                                let _ = s.write_all(&buf[..n]);
                            }
                        }
                    }
                });
            }
        }
    });

    thread::sleep(Duration::from_millis(100));

    group.bench_function("100_connections", |b| {
        b.iter(|| {
            let handles: Vec<_> = (0..100)
                .map(|_| {
                    let addr = addr;
                    thread::spawn(move || {
                        let mut stream = TcpStream::connect(addr).unwrap();
                        let data = b"test";
                        stream.write_all(data).unwrap();
                        let mut received = [0u8; 4];
                        stream.read_exact(&mut received).unwrap();
                        black_box(received);
                    })
                })
                .collect();

            for handle in handles {
                handle.join().unwrap();
            }
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_tcp_direct_throughput,
    bench_latency_echo,
    bench_concurrent_connections
);
criterion_main!(benches);
