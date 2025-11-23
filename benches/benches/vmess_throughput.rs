use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use sb_benches::{generate_random_bytes, setup_tracing};
use std::time::Duration;

/// Benchmark VMess header encoding
fn bench_vmess_header_encode() -> Duration {
    use bytes::BytesMut;

    let start = std::time::Instant::now();

    let mut header = BytesMut::with_capacity(128);

    // Version
    header.extend_from_slice(&[1]);

    // IV (16 bytes)
    header.extend_from_slice(&[0u8; 16]);

    // Key (16 bytes)
    header.extend_from_slice(&[0u8; 16]);

    // Response header
    header.extend_from_slice(&[0]);

    // Option
    header.extend_from_slice(&[0]);

    // Security (AES-128-GCM = 3)
    header.extend_from_slice(&[3]);

    // Command (TCP = 1)
    header.extend_from_slice(&[1]);

    // Port (2 bytes)
    header.extend_from_slice(&[0x00, 0x50]); // Port 80

    // Address Type (IPv4 = 1)
    header.extend_from_slice(&[1]);

    // Address (4 bytes for IPv4)
    header.extend_from_slice(&[127, 0, 0, 1]);

    black_box(header);
    start.elapsed()
}

/// Benchmark VMess AEAD encryption
fn bench_vmess_aead_encrypt(data_size: usize) -> Duration {
    use bytes::BytesMut;

    let data = generate_random_bytes(data_size);
    let key = b"this-is-a-16byte-key-for-vmess!";

    let start = std::time::Instant::now();

    // Simulate AEAD encryption
    let mut encrypted = BytesMut::with_capacity(data_size + 16);

    // Add auth tag (16 bytes)
    encrypted.extend_from_slice(&[0u8; 16]);

    // Add encrypted data (XOR simulation)
    encrypted.extend_from_slice(&data);
    for (i, byte) in encrypted[16..].iter_mut().enumerate() {
        *byte ^= key[i % key.len()];
    }

    black_box(encrypted);
    start.elapsed()
}

/// Benchmark VMess AEAD decryption
fn bench_vmess_aead_decrypt(data_size: usize) -> Duration {
    use bytes::BytesMut;

    let key = b"this-is-a-16byte-key-for-vmess!";

    // Prepare encrypted data
    let mut encrypted = BytesMut::with_capacity(data_size + 16);
    encrypted.extend_from_slice(&[0u8; 16]); // Auth tag
    encrypted.extend_from_slice(&generate_random_bytes(data_size));

    let start = std::time::Instant::now();

    // Verify auth tag (simplified)
    let _tag = &encrypted[..16];

    // Decrypt data
    let mut decrypted = encrypted[16..].to_vec();
    for (i, byte) in decrypted.iter_mut().enumerate() {
        *byte ^= key[i % key.len()];
    }

    black_box(decrypted);
    start.elapsed()
}

fn vmess_header_encoding(c: &mut Criterion) {
    setup_tracing();

    c.bench_function("vmess_header_encode", |b| {
        b.iter(|| black_box(bench_vmess_header_encode()));
    });
}

fn vmess_aead_encryption(c: &mut Criterion) {
    setup_tracing();

    let mut group = c.benchmark_group("vmess_aead_encrypt");

    for size in [1024, 65536, 1_048_576] {
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, &size| {
            b.iter(|| black_box(bench_vmess_aead_encrypt(size)));
        });
    }

    group.finish();
}

fn vmess_aead_decryption(c: &mut Criterion) {
    setup_tracing();

    let mut group = c.benchmark_group("vmess_aead_decrypt");

    for size in [1024, 65536, 1_048_576] {
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, &size| {
            b.iter(|| black_box(bench_vmess_aead_decrypt(size)));
        });
    }

    group.finish();
}

criterion_group!(
    name = benches;
    config = Criterion::default()
        .measurement_time(Duration::from_secs(10))
        .sample_size(100);
    targets = vmess_header_encoding, vmess_aead_encryption, vmess_aead_decryption
);
criterion_main!(benches);
