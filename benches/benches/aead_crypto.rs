use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use sb_benches::{generate_random_bytes, setup_tracing};
use std::time::Duration;

/// Real Shadowsocks AEAD encryption benchmark using actual cipher
fn bench_shadowsocks_aes256gcm(data_size: usize) -> Duration {
    use aes_gcm::{
        aead::{Aead, KeyInit},
        Aes256Gcm, Nonce,
    };

    let data = generate_random_bytes(data_size);
    let key = [42u8; 32]; // 256-bit key
    let cipher = Aes256Gcm::new(&key.into());
    let nonce = Nonce::from_slice(&[0u8; 12]);

    let start = std::time::Instant::now();
    let ciphertext = cipher
        .encrypt(nonce, data.as_ref())
        .expect("encryption failed");
    black_box(ciphertext);
    start.elapsed()
}

fn bench_shadowsocks_chacha20poly1305(data_size: usize) -> Duration {
    use chacha20poly1305::{
        aead::{Aead, KeyInit},
        ChaCha20Poly1305, Nonce,
    };

    let data = generate_random_bytes(data_size);
    let key = [42u8; 32]; // 256-bit key
    let cipher = ChaCha20Poly1305::new(&key.into());
    let nonce = Nonce::from_slice(&[0u8; 12]);

    let start = std::time::Instant::now();
    let ciphertext = cipher
        .encrypt(nonce, data.as_ref())
        .expect("encryption failed");
    black_box(ciphertext);
    start.elapsed()
}

/// AES-256-GCM decryption benchmark
fn bench_shadowsocks_aes256gcm_decrypt(data_size: usize) -> Duration {
    use aes_gcm::{
        aead::{Aead, KeyInit},
        Aes256Gcm, Nonce,
    };

    let data = generate_random_bytes(data_size);
    let key = [42u8; 32];
    let cipher = Aes256Gcm::new(&key.into());
    let nonce = Nonce::from_slice(&[0u8; 12]);

    // Pre-encrypt
    let ciphertext = cipher
        .encrypt(nonce, data.as_ref())
        .expect("encryption failed");

    let start = std::time::Instant::now();
    let plaintext = cipher
        .decrypt(nonce, ciphertext.as_ref())
        .expect("decryption failed");
    black_box(plaintext);
    start.elapsed()
}

/// ChaCha20-Poly1305 decryption benchmark
fn bench_shadowsocks_chacha20poly1305_decrypt(data_size: usize) -> Duration {
    use chacha20poly1305::{
        aead::{Aead, KeyInit},
        ChaCha20Poly1305, Nonce,
    };

    let data = generate_random_bytes(data_size);
    let key = [42u8; 32];
    let cipher = ChaCha20Poly1305::new(&key.into());
    let nonce = Nonce::from_slice(&[0u8; 12]);

    // Pre-encrypt
    let ciphertext = cipher
        .encrypt(nonce, data.as_ref())
        .expect("encryption failed");

    let start = std::time::Instant::now();
    let plaintext = cipher
        .decrypt(nonce, ciphertext.as_ref())
        .expect("decryption failed");
    black_box(plaintext);
    start.elapsed()
}

fn real_aead_encryption(c: &mut Criterion) {
    setup_tracing();

    let mut group = c.benchmark_group("shadowsocks_aead_encrypt");

    for size in [1024, 16384, 65536, 262144, 1_048_576] {
        group.throughput(Throughput::Bytes(size as u64));

        // AES-256-GCM
        group.bench_with_input(BenchmarkId::new("aes256gcm", size), &size, |b, &size| {
            b.iter(|| black_box(bench_shadowsocks_aes256gcm(size)));
        });

        // ChaCha20-Poly1305
        group.bench_with_input(
            BenchmarkId::new("chacha20poly1305", size),
            &size,
            |b, &size| {
                b.iter(|| black_box(bench_shadowsocks_chacha20poly1305(size)));
            },
        );
    }

    group.finish();
}

fn real_aead_decryption(c: &mut Criterion) {
    setup_tracing();

    let mut group = c.benchmark_group("shadowsocks_aead_decrypt");

    for size in [1024, 16384, 65536, 262144, 1_048_576] {
        group.throughput(Throughput::Bytes(size as u64));

        // AES-256-GCM
        group.bench_with_input(BenchmarkId::new("aes256gcm", size), &size, |b, &size| {
            b.iter(|| black_box(bench_shadowsocks_aes256gcm_decrypt(size)));
        });

        // ChaCha20-Poly1305
        group.bench_with_input(
            BenchmarkId::new("chacha20poly1305", size),
            &size,
            |b, &size| {
                b.iter(|| black_box(bench_shadowsocks_chacha20poly1305_decrypt(size)));
            },
        );
    }

    group.finish();
}

/// Benchmark encryption overhead vs direct copy
fn encryption_overhead(c: &mut Criterion) {
    setup_tracing();

    let mut group = c.benchmark_group("encryption_overhead");
    let size = 65536; // 64KB

    group.throughput(Throughput::Bytes(size as u64));

    // Baseline: just copy
    group.bench_function("baseline_copy", |b| {
        let data = generate_random_bytes(size);
        b.iter(|| {
            let copy = data.clone();
            black_box(copy);
        });
    });

    // AES-256-GCM overhead
    group.bench_function("aes256gcm_overhead", |b| {
        b.iter(|| black_box(bench_shadowsocks_aes256gcm(size)));
    });

    // ChaCha20-Poly1305 overhead
    group.bench_function("chacha20poly1305_overhead", |b| {
        b.iter(|| black_box(bench_shadowsocks_chacha20poly1305(size)));
    });

    group.finish();
}

/// Benchmark different packet sizes (realistic scenarios)
fn realistic_packet_sizes(c: &mut Criterion) {
    setup_tracing();

    let mut group = c.benchmark_group("realistic_packets");

    let scenarios = [
        ("tcp_control", 64),     // TCP control packet
        ("small_http", 512),     // Small HTTP request
        ("http_response", 1460), // MTU-sized HTTP response
        ("video_chunk", 16384),  // Video streaming chunk
        ("bulk_data", 65536),    // Bulk transfer
    ];

    for (name, size) in scenarios {
        group.throughput(Throughput::Bytes(size as u64));

        group.bench_with_input(BenchmarkId::new("aes256gcm", name), &size, |b, &size| {
            b.iter(|| black_box(bench_shadowsocks_aes256gcm(size)));
        });

        group.bench_with_input(BenchmarkId::new("chacha20", name), &size, |b, &size| {
            b.iter(|| black_box(bench_shadowsocks_chacha20poly1305(size)));
        });
    }

    group.finish();
}

criterion_group!(
    name = benches;
    config = Criterion::default()
        .measurement_time(Duration::from_secs(10))
        .sample_size(100);
    targets =
        real_aead_encryption,
        real_aead_decryption,
        encryption_overhead,
        realistic_packet_sizes
);
criterion_main!(benches);
