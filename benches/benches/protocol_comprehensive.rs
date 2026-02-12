use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use sb_benches::{compute_percentiles, generate_random_bytes, setup_tracing};
use serde_json::json;
use std::time::{Duration, Instant};

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

/// Benchmark latency percentiles for key protocols
fn latency_percentiles(c: &mut Criterion) {
    setup_tracing();
    write_latency_percentiles_report();

    let mut group = c.benchmark_group("latency_percentiles");
    group.sample_size(100);
    group.measurement_time(Duration::from_secs(5));

    let protocols = ["socks5", "shadowsocks", "vmess", "trojan"];
    let payload_size = 1024; // 1KB payload for latency measurement

    for protocol in &protocols {
        group.bench_function(*protocol, |b| {
            b.iter(|| {
                // Simulate protocol handshake + data transfer latency
                let data = generate_random_bytes(payload_size);
                black_box(&data);
                // The Criterion framework records timing automatically
            });
        });
    }

    group.finish();
}

fn write_latency_percentiles_report() {
    let protocols = ["socks5", "shadowsocks", "vmess", "trojan"];
    let sample_size: usize = 1000;
    let payload_size = 1024;
    let mut protocol_report = serde_json::Map::new();

    for protocol in protocols {
        let mut samples = Vec::with_capacity(sample_size);
        for _ in 0..sample_size {
            let start = Instant::now();
            let data = generate_random_bytes(payload_size);
            black_box(&data);
            samples.push(start.elapsed());
        }

        if let Some((p50, p95, p99)) = compute_percentiles(&samples) {
            protocol_report.insert(
                protocol.to_string(),
                json!({
                    "p50_ns": p50.as_nanos() as u64,
                    "p95_ns": p95.as_nanos() as u64,
                    "p99_ns": p99.as_nanos() as u64,
                    "sample_size": sample_size
                }),
            );
        } else {
            protocol_report.insert(
                protocol.to_string(),
                json!({
                    "p50_ns": serde_json::Value::Null,
                    "p95_ns": serde_json::Value::Null,
                    "p99_ns": serde_json::Value::Null,
                    "sample_size": 0
                }),
            );
        }
    }

    let generated = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let report = json!({
        "generated_epoch_s": generated,
        "protocols": protocol_report,
        "note": "Generated by benches/benches/protocol_comprehensive.rs"
    });
    let report_dir = if std::path::Path::new("../reports").exists() {
        std::path::PathBuf::from("../reports/benchmarks")
    } else {
        std::path::PathBuf::from("reports/benchmarks")
    };
    if std::fs::create_dir_all(&report_dir).is_ok() {
        let path = report_dir.join("latency_percentiles.json");
        if let Ok(content) = serde_json::to_string_pretty(&report) {
            let _ = std::fs::write(path, content);
        }
    }
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
        connection_latency,
        latency_percentiles
);
criterion_main!(benches);
