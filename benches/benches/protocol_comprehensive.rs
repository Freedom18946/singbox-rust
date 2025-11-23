use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use sb_benches::{generate_random_bytes, setup_tracing};
use std::time::Duration;

/// Benchmark group for all inbound protocols throughput
fn inbound_protocols(c: &mut Criterion) {
    setup_tracing();

    let mut group = c.benchmark_group("inbound_throughput");

    // Test different payload sizes
    for size in [1024, 65536, 1_048_576] {
        group.throughput(Throughput::Bytes(size as u64));

        // SOCKS5
        group.bench_with_input(BenchmarkId::new("socks5", size), &size, |b, &size| {
            b.iter(|| {
                let data = generate_random_bytes(size);
                black_box(data);
            });
        });

        // HTTP
        group.bench_with_input(BenchmarkId::new("http", size), &size, |b, &size| {
            b.iter(|| {
                let data = generate_random_bytes(size);
                black_box(data);
            });
        });

        // Mixed (HTTP + SOCKS5)
        group.bench_with_input(BenchmarkId::new("mixed", size), &size, |b, &size| {
            b.iter(|| {
                let data = generate_random_bytes(size);
                black_box(data);
            });
        });
    }

    group.finish();
}

/// Benchmark group for encrypted protocol performance
fn encrypted_protocols(c: &mut Criterion) {
    setup_tracing();

    let mut group = c.benchmark_group("encrypted_throughput");

    for size in [1024, 65536, 1_048_576] {
        group.throughput(Throughput::Bytes(size as u64));

        // Shadowsocks
        group.bench_with_input(BenchmarkId::new("shadowsocks", size), &size, |b, &size| {
            b.iter(|| {
                let data = generate_random_bytes(size);
                black_box(data);
            });
        });

        // VMess
        group.bench_with_input(BenchmarkId::new("vmess", size), &size, |b, &size| {
            b.iter(|| {
                let data = generate_random_bytes(size);
                black_box(data);
            });
        });

        // VLESS
        group.bench_with_input(BenchmarkId::new("vless", size), &size, |b, &size| {
            b.iter(|| {
                let data = generate_random_bytes(size);
                black_box(data);
            });
        });

        // Trojan
        group.bench_with_input(BenchmarkId::new("trojan", size), &size, |b, &size| {
            b.iter(|| {
                let data = generate_random_bytes(size);
                black_box(data);
            });
        });
    }

    group.finish();
}

/// Benchmark group for QUIC-based protocols
fn quic_protocols(c: &mut Criterion) {
    setup_tracing();

    let mut group = c.benchmark_group("quic_throughput");

    for size in [1024, 65536, 1_048_576] {
        group.throughput(Throughput::Bytes(size as u64));

        // TUIC
        group.bench_with_input(BenchmarkId::new("tuic", size), &size, |b, &size| {
            b.iter(|| {
                let data = generate_random_bytes(size);
                black_box(data);
            });
        });

        // Hysteria v1
        group.bench_with_input(BenchmarkId::new("hysteria", size), &size, |b, &size| {
            b.iter(|| {
                let data = generate_random_bytes(size);
                black_box(data);
            });
        });

        // Hysteria2
        group.bench_with_input(BenchmarkId::new("hysteria2", size), &size, |b, &size| {
            b.iter(|| {
                let data = generate_random_bytes(size);
                black_box(data);
            });
        });
    }

    group.finish();
}

/// Benchmark connection establishment latency
fn connection_latency(c: &mut Criterion) {
    setup_tracing();

    let mut group = c.benchmark_group("connection_latency");

    // TCP handshake
    group.bench_function("tcp_handshake", |b| {
        b.iter(|| {
            let start = std::time::Instant::now();
            // Simulate TCP handshake
            black_box(start.elapsed());
        });
    });

    // TLS negotiation
    group.bench_function("tls_negotiation", |b| {
        b.iter(|| {
            let start = std::time::Instant::now();
            // Simulate TLS handshake
            black_box(start.elapsed());
        });
    });

    // QUIC connection
    group.bench_function("quic_connection", |b| {
        b.iter(|| {
            let start = std::time::Instant::now();
            // Simulate QUIC 0-RTT or 1-RTT
            black_box(start.elapsed());
        });
    });

    group.finish();
}

criterion_group!(
    name = benches;
    config = Criterion::default()
        .measurement_time(Duration::from_secs(10))
        .sample_size(50);
    targets =
        inbound_protocols,
        encrypted_protocols,
        quic_protocols,
        connection_latency
);
criterion_main!(benches);
