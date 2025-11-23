use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use sb_benches::setup_tracing;
use std::time::Duration;

/// Benchmark memory allocation patterns
fn memory_allocation(c: &mut Criterion) {
    setup_tracing();

    let mut group = c.benchmark_group("memory_allocation");

    // Buffer allocation
    group.bench_function("buffer_allocation_64kb", |b| {
        b.iter(|| {
            let buffer = vec![0u8; 65536];
            black_box(buffer);
        });
    });

    // Connection state
    group.bench_function("connection_state_creation", |b| {
        b.iter(|| {
            use std::collections::HashMap;
            let mut state = HashMap::new();
            state.insert("remote_addr", "127.0.0.1:8080");
            state.insert("protocol", "socks5");
            black_box(state);
        });
    });

    // Protocol header parsing (zero-copy vs copy)
    group.bench_function("zero_copy_header_parse", |b| {
        let data = vec![0u8; 1024];
        b.iter(|| {
            // Simulate zero-copy header parsing
            let header = &data[..20];
            black_box(header);
        });
    });

    group.bench_function("copy_header_parse", |b| {
        let data = vec![0u8; 1024];
        b.iter(|| {
            // Simulate copy-based header parsing
            let mut header = vec![0u8; 20];
            header.copy_from_slice(&data[..20]);
            black_box(header);
        });
    });

    group.finish();
}

/// Benchmark concurrent connection handling
fn concurrent_connections(c: &mut Criterion) {
    setup_tracing();

    let mut group = c.benchmark_group("concurrent_connections");

    for conn_count in [10, 100, 1000] {
        group.bench_with_input(
            BenchmarkId::from_parameter(conn_count),
            &conn_count,
            |b, &count| {
                b.iter(|| {
                    use std::collections::HashMap;
                    let mut connections = HashMap::new();
                    for i in 0..count {
                        connections.insert(i, format!("conn_{i}"));
                    }
                    black_box(connections);
                });
            },
        );
    }

    group.finish();
}

/// Benchmark routing decision overhead
fn routing_overhead(c: &mut Criterion) {
    setup_tracing();

    let mut group = c.benchmark_group("routing_overhead");

    // Domain-based routing
    group.bench_function("domain_match", |b| {
        let domain = "example.com";
        let rules = vec!["*.google.com", "*.github.com", "example.com"];

        b.iter(|| {
            let matched = rules.iter().find(|&&rule| {
                // Simple suffix match simulation
                domain.ends_with(rule.trim_start_matches("*."))
            });
            black_box(matched);
        });
    });

    // IP-based routing
    group.bench_function("ip_match", |b| {
        use std::net::Ipv4Addr;
        let ip = Ipv4Addr::new(192, 168, 1, 1);

        b.iter(|| {
            // Simulate CIDR matching
            let network = Ipv4Addr::new(192, 168, 0, 0);
            let mask = 16;
            let matched = (u32::from(ip) >> (32 - mask)) == (u32::from(network) >> (32 - mask));
            black_box(matched);
        });
    });

    // GeoIP lookup
    group.bench_function("geoip_lookup", |b| {
        use std::collections::HashMap;
        let mut geoip_cache = HashMap::new();
        geoip_cache.insert("1.1.1.1", "US");
        geoip_cache.insert("8.8.8.8", "US");
        geoip_cache.insert("114.114.114.114", "CN");

        b.iter(|| {
            let result = geoip_cache.get("8.8.8.8");
            black_box(result);
        });
    });

    group.finish();
}

/// Benchmark crypto operations
fn crypto_operations(c: &mut Criterion) {
    setup_tracing();

    let mut group = c.benchmark_group("crypto_operations");

    // AES-256-GCM encryption
    group.bench_function("aes256gcm_encrypt_1kb", |b| {
        let plaintext = vec![0u8; 1024];
        b.iter(|| {
            // Simulate AES encryption
            let mut ciphertext = plaintext.clone();
            ciphertext.reverse(); // Placeholder
            black_box(ciphertext);
        });
    });

    // ChaCha20-Poly1305 encryption
    group.bench_function("chacha20poly1305_encrypt_1kb", |b| {
        let plaintext = vec![0u8; 1024];
        b.iter(|| {
            // Simulate ChaCha20 encryption
            let mut ciphertext = plaintext.clone();
            ciphertext.reverse(); // Placeholder
            black_box(ciphertext);
        });
    });

    // SHA256 hashing
    group.bench_function("sha256_hash_1kb", |b| {
        let data = vec![0u8; 1024];
        b.iter(|| {
            // Simulate SHA256
            let hash = data
                .iter()
                .fold(0u64, |acc, &byte| acc.wrapping_add(byte as u64));
            black_box(hash);
        });
    });

    group.finish();
}

criterion_group!(
    name = benches;
    config = Criterion::default()
        .measurement_time(Duration::from_secs(5))
        .sample_size(100);
    targets =
        memory_allocation,
        concurrent_connections,
        routing_overhead,
        crypto_operations
);
criterion_main!(benches);
