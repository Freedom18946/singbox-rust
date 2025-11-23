use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use sb_benches::setup_tracing;
use std::time::Duration;

/// Benchmark DNS query parsing
fn bench_dns_query_parse() -> Duration {
    // DNS query packet for "example.com" A record
    let query = vec![
        0x12, 0x34, // Transaction ID
        0x01, 0x00, // Flags: standard query
        0x00, 0x01, // Questions: 1
        0x00, 0x00, // Answers: 0
        0x00, 0x00, // Authority: 0
        0x00, 0x00, // Additional: 0
        // Question: example.com
        0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm',
        0x00, // End of name
        0x00, 0x01, // Type: A
        0x00, 0x01, // Class: IN
    ];

    let start = std::time::Instant::now();

    // Simulate DNS parsing
    let _id = u16::from_be_bytes([query[0], query[1]]);
    let _flags = u16::from_be_bytes([query[2], query[3]]);
    let _questions = u16::from_be_bytes([query[4], query[5]]);

    black_box(query);
    start.elapsed()
}

/// Benchmark DNS response building
fn bench_dns_response_build() -> Duration {
    let start = std::time::Instant::now();

    let mut response = Vec::with_capacity(64);

    // Header
    response.extend_from_slice(&[
        0x12, 0x34, // Transaction ID
        0x81, 0x80, // Flags: response, no error
        0x00, 0x01, // Questions: 1
        0x00, 0x01, // Answers: 1
        0x00, 0x00, // Authority: 0
        0x00, 0x00, // Additional: 0
    ]);

    // Question
    response.extend_from_slice(&[
        0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00,
        0x01, // Type: A
        0x00, 0x01, // Class: IN
    ]);

    // Answer
    response.extend_from_slice(&[
        0xc0, 0x0c, // Name: pointer to question
        0x00, 0x01, // Type: A
        0x00, 0x01, // Class: IN
        0x00, 0x00, 0x00, 0x3c, // TTL: 60 seconds
        0x00, 0x04, // Data length: 4
        93, 184, 216, 34, // IP: 93.184.216.34 (example.com)
    ]);

    black_box(response);
    start.elapsed()
}

/// Benchmark DNS cache lookup
fn bench_dns_cache_lookup(cache_size: usize) -> Duration {
    use std::collections::HashMap;

    // Build cache
    let mut cache = HashMap::new();
    for i in 0..cache_size {
        cache.insert(
            format!("domain{i}.example.com"),
            vec![std::net::Ipv4Addr::new(192, 168, 0, (i % 255) as u8)],
        );
    }

    let start = std::time::Instant::now();

    // Lookup
    let _result = cache.get("domain500.example.com");

    black_box(cache);
    start.elapsed()
}

fn dns_query_parsing(c: &mut Criterion) {
    setup_tracing();

    c.bench_function("dns_query_parse", |b| {
        b.iter(|| black_box(bench_dns_query_parse()));
    });
}

fn dns_response_building(c: &mut Criterion) {
    setup_tracing();

    c.bench_function("dns_response_build", |b| {
        b.iter(|| black_box(bench_dns_response_build()));
    });
}

fn dns_cache_lookup(c: &mut Criterion) {
    setup_tracing();

    let mut group = c.benchmark_group("dns_cache_lookup");

    for size in [100, 1000, 10000] {
        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, &size| {
            b.iter(|| black_box(bench_dns_cache_lookup(size)));
        });
    }

    group.finish();
}

criterion_group!(
    name = benches;
    config = Criterion::default()
        .measurement_time(Duration::from_secs(5))
        .sample_size(200);
    targets = dns_query_parsing, dns_response_building, dns_cache_lookup
);
criterion_main!(benches);
