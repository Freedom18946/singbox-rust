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
    let listener = match TcpListener::bind("127.0.0.1:0") {
        Ok(l) => l,
        Err(_) => return,
    };
    let addr = match listener.local_addr() {
        Ok(a) => a,
        Err(_) => return,
    };

    thread::spawn(move || {
        for mut s in listener.incoming().flatten() {
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
    });

    thread::sleep(Duration::from_millis(100));

    group.bench_function("direct_1mb", |b| {
        b.iter(|| {
            let Ok(mut stream) = TcpStream::connect(addr) else {
                return;
            };
            let data = vec![0xAB; 1024 * 1024]; // 1MB

            if stream.write_all(&data).is_err() {
                return;
            }

            let mut received = vec![0u8; data.len()];
            if std::io::Read::read_exact(&mut stream, &mut received).is_err() {
                return;
            }

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
    let listener = match TcpListener::bind("127.0.0.1:0") {
        Ok(l) => l,
        Err(_) => return,
    };
    let addr = match listener.local_addr() {
        Ok(a) => a,
        Err(_) => return,
    };

    thread::spawn(move || {
        for mut s in listener.incoming().flatten() {
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
    });

    thread::sleep(Duration::from_millis(100));

    group.bench_function("echo_small_payload", |b| {
        b.iter(|| {
            let Ok(mut stream) = TcpStream::connect(addr) else {
                return;
            };
            let data = b"Hello, World!"; // 13 bytes

            if stream.write_all(data).is_err() {
                return;
            }

            let mut received = [0u8; 13];
            if std::io::Read::read_exact(&mut stream, &mut received).is_err() {
                return;
            }

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
    let listener = match TcpListener::bind("127.0.0.1:0") {
        Ok(l) => l,
        Err(_) => return,
    };
    let addr = match listener.local_addr() {
        Ok(a) => a,
        Err(_) => return,
    };

    thread::spawn(move || {
        for mut s in listener.incoming().flatten() {
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
    });

    thread::sleep(Duration::from_millis(100));

    group.bench_function("100_connections", |b| {
        b.iter(|| {
            let handles: Vec<_> = (0..100)
                .map(|_| {
                    thread::spawn(move || {
                        let Ok(mut stream) = TcpStream::connect(addr) else {
                            return;
                        };
                        let data = b"test";
                        let _ = stream.write_all(data);
                        let mut received = [0u8; 4];
                        let _ = std::io::Read::read_exact(&mut stream, &mut received);
                        black_box(received);
                    })
                })
                .collect();

            for handle in handles {
                let _ = handle.join();
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
#[cfg(not(feature = "bench"))]
fn main() {}
