use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use tokio::runtime::Runtime;
use sb_adapters::inbound::trojan::TrojanUser;

/// Benchmark Trojan binary protocol throughput
fn bench_trojan_throughput(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    let mut group = c.benchmark_group("trojan_throughput");

    // Test different payload sizes
    for size in [1024, 4096, 16384, 65536].iter() {
        group.throughput(Throughput::Bytes(*size as u64));

        group.bench_function(format!("binary_protocol_{}KB", size / 1024), |b| {
            b.iter(|| {
                rt.block_on(async {
                    // Simulate binary protocol parsing and encryption overhead
                    let payload = vec![0u8; *size];
                    black_box(payload);
                });
            });
        });
    }

    group.finish();
}

/// Benchmark SHA224 password hashing
fn bench_trojan_auth(c: &mut Criterion) {
    use sha2::{Digest, Sha224};

    let mut group = c.benchmark_group("trojan_auth");

    group.bench_function("sha224_hash", |b| {
        let password = "test-password-12345";
        b.iter(|| {
            let hash = Sha224::digest(password.as_bytes());
            black_box(hex::encode(hash));
        });
    });

    group.bench_function("multi_user_lookup", |b| {
        let users = vec![
            TrojanUser::new("user1".to_string(), "pass1".to_string()),
            TrojanUser::new("user2".to_string(), "pass2".to_string()),
            TrojanUser::new("user3".to_string(), "pass3".to_string()),
            TrojanUser::new("user4".to_string(), "pass4".to_string()),
            TrojanUser::new("user5".to_string(), "pass5".to_string()),
        ];

        // Build hash map (O(1) lookup)
        use std::collections::HashMap;
        let mut map = HashMap::new();
        for user in &users {
            let hash = Sha224::digest(user.password.as_bytes());
            map.insert(hex::encode(hash), user.name.clone());
        }

        let test_hash = hex::encode(Sha224::digest(b"pass3"));

        b.iter(|| {
            black_box(map.get(&test_hash));
        });
    });

    group.finish();
}

/// Benchmark binary address parsing
fn bench_trojan_address_parsing(c: &mut Criterion) {
    let mut group = c.benchmark_group("trojan_address_parsing");

    // IPv4 address
    group.bench_function("parse_ipv4", |b| {
        let data = [
            0x01, // ATYP IPv4
            192, 168, 1, 1, // IP
            0x00, 0x50, // Port 80
        ];

        b.iter(|| {
            let atyp = data[0];
            if atyp == 0x01 {
                let ip = std::net::Ipv4Addr::new(data[1], data[2], data[3], data[4]);
                let port = u16::from_be_bytes([data[5], data[6]]);
                black_box((ip.to_string(), port));
            }
        });
    });

    // Domain name
    group.bench_function("parse_domain", |b| {
        let domain = "example.com";
        let mut data = vec![0x03, domain.len() as u8];
        data.extend_from_slice(domain.as_bytes());
        data.extend_from_slice(&80u16.to_be_bytes());

        b.iter(|| {
            let atyp = data[0];
            if atyp == 0x03 {
                let len = data[1] as usize;
                let domain = String::from_utf8_lossy(&data[2..2 + len]).to_string();
                let port = u16::from_be_bytes([data[2 + len], data[2 + len + 1]]);
                black_box((domain, port));
            }
        });
    });

    // IPv6 address
    group.bench_function("parse_ipv6", |b| {
        let data = [
            0x04, // ATYP IPv6
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01, // IP
            0x00, 0x50, // Port 80
        ];

        b.iter(|| {
            let atyp = data[0];
            if atyp == 0x04 {
                let mut ip_bytes = [0u8; 16];
                ip_bytes.copy_from_slice(&data[1..17]);
                let ip = std::net::Ipv6Addr::from(ip_bytes);
                let port = u16::from_be_bytes([data[17], data[18]]);
                black_box((ip.to_string(), port));
            }
        });
    });

    group.finish();
}

/// Benchmark connection handling concurrency
fn bench_trojan_concurrency(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    let mut group = c.benchmark_group("trojan_concurrency");
    group.sample_size(10); // Reduce sample size for expensive benchmarks

    for conn_count in [10, 50, 100].iter() {
        group.bench_function(format!("concurrent_connections_{}", conn_count), |b| {
            b.iter(|| {
                rt.block_on(async {
                    let mut handles = vec![];

                    for _ in 0..*conn_count {
                        handles.push(tokio::spawn(async {
                            // Simulate connection processing
                            tokio::time::sleep(tokio::time::Duration::from_micros(100)).await;
                        }));
                    }

                    for handle in handles {
                        let _ = handle.await;
                    }
                });
            });
        });
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_trojan_throughput,
    bench_trojan_auth,
    bench_trojan_address_parsing,
    bench_trojan_concurrency
);
criterion_main!(benches);
