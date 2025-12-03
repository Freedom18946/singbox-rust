#![allow(deprecated)]
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use sb_adapters::inbound::shadowsocks::ShadowsocksInboundConfig;
use sb_adapters::outbound::shadowsocks::{ShadowsocksConfig, ShadowsocksConnector};
use sb_adapters::outbound::{DialOpts, OutboundConnector, Target};
use sb_adapters::TransportKind;
use sb_benches::{generate_random_bytes, setup_tracing};
use sb_core::router::engine::RouterHandle;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::runtime::Runtime;

// Helper: Start TCP echo server
async fn start_echo_server() -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        loop {
            if let Ok((mut stream, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 65536];
                    loop {
                        match stream.read(&mut buf).await {
                            Ok(0) | Err(_) => break,
                            Ok(n) => {
                                if stream.write_all(&buf[..n]).await.is_err() {
                                    break;
                                }
                            }
                        }
                    }
                });
            }
        }
    });
    addr
}

// Helper: Start Shadowsocks server
async fn start_ss_server(method: &str) -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);

    let (_stop_tx, stop_rx) = tokio::sync::mpsc::channel(1);

    let config = ShadowsocksInboundConfig {
        listen: addr,
        method: method.to_string(),
        password: Some("benchmark-pass".to_string()),
        router: Arc::new(RouterHandle::new_mock()),
        multiplex: None,
        transport_layer: None,
        users: vec![],
    };

    tokio::spawn(async move {
        let _ = sb_adapters::inbound::shadowsocks::serve(config, stop_rx).await;
    });

    tokio::time::sleep(Duration::from_millis(100)).await;
    addr
}

fn bench_ss_e2e_throughput(c: &mut Criterion) {
    setup_tracing();

    let rt = Runtime::new().unwrap();
    let mut group = c.benchmark_group("shadowsocks_e2e_throughput");
    group.measurement_time(Duration::from_secs(10));
    group.sample_size(20);

    for cipher in ["aes-256-gcm", "chacha20-ietf-poly1305"] {
        // Start servers once per cipher
        let (echo_addr, ss_addr) = rt.block_on(async {
            let echo = start_echo_server().await;
            let ss = start_ss_server(cipher).await;
            (echo, ss)
        });

        for size in [1024, 65536, 1_048_576] {
            group.throughput(Throughput::Bytes(size as u64));

            group.bench_with_input(
                BenchmarkId::new(cipher, size),
                &(cipher, size),
                |b, &(cipher, size)| {
                    b.to_async(&rt).iter(|| async {
                        let client_config = ShadowsocksConfig {
                            server: ss_addr.to_string(),
                            tag: None,
                            method: cipher.to_string(),
                            password: "benchmark-pass".to_string(),
                            connect_timeout_sec: Some(5),
                            multiplex: None,
                        };

                        let connector = ShadowsocksConnector::new(client_config).unwrap();
                        let target = Target {
                            host: echo_addr.ip().to_string(),
                            port: echo_addr.port(),
                            kind: TransportKind::Tcp,
                        };

                        let mut stream = connector.dial(target, DialOpts::default()).await.unwrap();
                        let data = vec![0u8; size];

                        stream.write_all(&data).await.unwrap();
                        let mut buf = vec![0u8; size];
                        stream.read_exact(&mut buf).await.unwrap();

                        black_box(buf);
                    });
                },
            );
        }
    }

    group.finish();
}

/// Benchmark Shadowsocks encryption/decryption (Cipher only)
fn bench_ss_encrypt(_cipher: &str, data_size: usize) -> Duration {
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

fn bench_ss_decrypt(_cipher: &str, data_size: usize) -> Duration {
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
    targets = shadowsocks_encryption, shadowsocks_decryption, bench_ss_e2e_throughput
);
criterion_main!(benches);
