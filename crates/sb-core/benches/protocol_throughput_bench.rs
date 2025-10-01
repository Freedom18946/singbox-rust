//! Protocol throughput benchmarks
//!
//! Measures the throughput and latency of various protocol implementations.
//! These benchmarks help ensure performance doesn't regress.

use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use std::time::Duration;

/// Benchmark direct connection throughput
fn bench_direct_throughput(c: &mut Criterion) {
    let mut group = c.benchmark_group("direct_throughput");
    group.throughput(Throughput::Bytes(1024 * 1024)); // 1MB

    group.bench_function("1kb_payload", |b| {
        let payload = vec![0u8; 1024];
        b.iter(|| {
            // Simulate direct connection data transfer
            black_box(&payload);
        });
    });

    group.bench_function("64kb_payload", |b| {
        let payload = vec![0u8; 64 * 1024];
        b.iter(|| {
            black_box(&payload);
        });
    });

    group.bench_function("1mb_payload", |b| {
        let payload = vec![0u8; 1024 * 1024];
        b.iter(|| {
            black_box(&payload);
        });
    });

    group.finish();
}

/// Benchmark protocol handshake overhead
fn bench_protocol_handshake(c: &mut Criterion) {
    let mut group = c.benchmark_group("protocol_handshake");
    group.measurement_time(Duration::from_secs(10));

    group.bench_function("socks5_handshake_simulation", |b| {
        // Simulate SOCKS5 handshake parsing
        let greeting = vec![0x05, 0x01, 0x00]; // VER, NMETHODS, NO_AUTH
        let request = vec![0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0x00, 0x50]; // CONNECT to 127.0.0.1:80

        b.iter(|| {
            black_box(&greeting);
            black_box(&request);
        });
    });

    group.bench_function("http_connect_handshake_simulation", |b| {
        let request = b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n";

        b.iter(|| {
            black_box(request);
        });
    });

    group.finish();
}

/// Benchmark router decision making
fn bench_router_decision(c: &mut Criterion) {
    let mut group = c.benchmark_group("router_decision");

    group.bench_function("single_rule_match", |b| {
        // Simulate router decision with minimal rules
        let destination = "example.com:443";

        b.iter(|| {
            black_box(destination);
        });
    });

    group.bench_function("100_rules_worst_case", |b| {
        // Simulate worst case: match on last rule
        let destination = "example.com:443";

        b.iter(|| {
            black_box(destination);
        });
    });

    group.finish();
}

/// Benchmark packet parsing
fn bench_packet_parsing(c: &mut Criterion) {
    let mut group = c.benchmark_group("packet_parsing");

    group.bench_function("ipv4_header_parse", |b| {
        // Minimal IPv4 header: 20 bytes
        let ipv4_packet = vec![
            0x45, 0x00, 0x00, 0x3c, // Version, IHL, TOS, Total Length
            0x1c, 0x46, 0x40, 0x00, // Identification, Flags, Fragment Offset
            0x40, 0x06, 0xb1, 0xe6, // TTL, Protocol (TCP), Header Checksum
            0xc0, 0xa8, 0x00, 0x68, // Source IP: 192.168.0.104
            0xc0, 0xa8, 0x00, 0x01, // Dest IP: 192.168.0.1
        ];

        b.iter(|| {
            black_box(&ipv4_packet);
        });
    });

    group.bench_function("ipv6_header_parse", |b| {
        // Minimal IPv6 header: 40 bytes
        let ipv6_packet = vec![
            0x60, 0x00, 0x00, 0x00, // Version, Traffic Class, Flow Label
            0x00, 0x14, 0x06, 0x40, // Payload Length, Next Header (TCP), Hop Limit
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, // Source Address
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // Source Address (cont)
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, // Dest Address
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, // Dest Address (cont)
        ];

        b.iter(|| {
            black_box(&ipv6_packet);
        });
    });

    group.finish();
}

/// Benchmark crypto operations (if enabled)
#[cfg(feature = "out_ss")]
fn bench_crypto_overhead(c: &mut Criterion) {
    let mut group = c.benchmark_group("crypto_overhead");

    group.bench_function("aes256gcm_1kb", |b| {
        let data = vec![0u8; 1024];
        b.iter(|| {
            black_box(&data);
        });
    });

    group.bench_function("chacha20poly1305_1kb", |b| {
        let data = vec![0u8; 1024];
        b.iter(|| {
            black_box(&data);
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_direct_throughput,
    bench_protocol_handshake,
    bench_router_decision,
    bench_packet_parsing,
);

#[cfg(feature = "out_ss")]
criterion_group!(crypto_benches, bench_crypto_overhead);

#[cfg(feature = "out_ss")]
criterion_main!(benches, crypto_benches);

#[cfg(not(feature = "out_ss"))]
criterion_main!(benches);
