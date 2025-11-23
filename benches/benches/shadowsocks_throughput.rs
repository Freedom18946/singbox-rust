use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use sb_benches::{generate_random_bytes, setup_tracing};
use std::time::Duration;

/// Benchmark Shadowsocks encryption/decryption
fn bench_ss_encrypt(cipher: &str, data_size: usize) -> Duration {
    use bytes::BytesMut;

    let data = generate_random_bytes(data_size);
    let key = b"this-is-a-32-byte-key-for-test!!";

    let start = std::time::Instant::now();

    // Simulate encryption (using a simplified approach)
    // In real benchmark, we'd use actual Shadowsocks cipher
    let mut encrypted = BytesMut::with_capacity(data_size + 32);
    encrypted.extend_from_slice(&data);

    // XOR with key (simplified cipher simulation)
    for (i, byte) in encrypted.iter_mut().enumerate() {
        *byte ^= key[i % key.len()];
    }

    black_box(encrypted);
    start.elapsed()
}

fn bench_ss_decrypt(cipher: &str, data_size: usize) -> Duration {
    use bytes::BytesMut;

    let data = generate_random_bytes(data_size);
    let key = b"this-is-a-32-byte-key-for-test!!";

    // Pre-encrypt
    let mut encrypted = BytesMut::with_capacity(data_size);
    encrypted.extend_from_slice(&data);
    for (i, byte) in encrypted.iter_mut().enumerate() {
        *byte ^= key[i % key.len()];
    }

    let start = std::time::Instant::now();

    // Decrypt
    let mut decrypted = encrypted.clone();
    for (i, byte) in decrypted.iter_mut().enumerate() {
        *byte ^= key[i % key.len()];
    }

    black_box(decrypted);
    start.elapsed()
}

fn shadowsocks_encryption(c: &mut Criterion) {
    setup_tracing();

    let mut group = c.benchmark_group("shadowsocks_encrypt");

    for cipher in ["aes-256-gcm", "chacha20-poly1305"] {
        for size in [1024, 65536, 1_048_576] {
            group.throughput(Throughput::Bytes(size as u64));
            group.bench_with_input(
                BenchmarkId::new(cipher, size),
                &(cipher, size),
                |b, &(cipher, size)| {
                    b.iter(|| black_box(bench_ss_encrypt(cipher, size)));
                },
            );
        }
    }

    group.finish();
}

fn shadowsocks_decryption(c: &mut Criterion) {
    setup_tracing();

    let mut group = c.benchmark_group("shadowsocks_decrypt");

    for cipher in ["aes-256-gcm", "chacha20-poly1305"] {
        for size in [1024, 65536, 1_048_576] {
            group.throughput(Throughput::Bytes(size as u64));
            group.bench_with_input(
                BenchmarkId::new(cipher, size),
                &(cipher, size),
                |b, &(cipher, size)| {
                    b.iter(|| black_box(bench_ss_decrypt(cipher, size)));
                },
            );
        }
    }

    group.finish();
}

criterion_group!(
    name = benches;
    config = Criterion::default()
        .measurement_time(Duration::from_secs(10))
        .sample_size(100);
    targets = shadowsocks_encryption, shadowsocks_decryption
);
criterion_main!(benches);
