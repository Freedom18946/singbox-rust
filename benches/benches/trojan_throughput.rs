#![allow(deprecated)]
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use sb_adapters::inbound::trojan::TrojanInboundConfig;
use sb_adapters::outbound::trojan::{TrojanConfig, TrojanConnector};
use sb_adapters::outbound::{DialOpts, OutboundConnector, Target};
use sb_adapters::transport_config::TransportConfig;
use sb_adapters::TransportKind;
use sb_benches::setup_tracing;
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

// Helper: Start Trojan server
async fn start_trojan_server() -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);

    let (_stop_tx, stop_rx) = tokio::sync::mpsc::channel(1);

    let config = TrojanInboundConfig {
        listen: addr,
        password: Some("benchmark-pass".to_string()),
        cert_path: "app/tests/cli/fixtures/pems/cert.pem".to_string(),
        key_path: "app/tests/cli/fixtures/pems/key.pem".to_string(),
        router: Arc::new(RouterHandle::new_mock()),
        transport_layer: None,
        multiplex: None,
        reality: None,
        fallback: None,
        fallback_for_alpn: std::collections::HashMap::new(),
        users: vec![],
    };

    tokio::spawn(async move {
        let _ = sb_adapters::inbound::trojan::serve(config, stop_rx).await;
    });

    tokio::time::sleep(Duration::from_millis(100)).await;
    addr
}

fn bench_trojan_throughput(c: &mut Criterion) {
    setup_tracing();

    let rt = Runtime::new().unwrap();
    let mut group = c.benchmark_group("trojan_throughput");
    group.measurement_time(Duration::from_secs(10));
    group.sample_size(20);

    // Start servers
    let (echo_addr, trojan_addr) = rt.block_on(async {
        let echo = start_echo_server().await;
        let trojan = start_trojan_server().await;
        (echo, trojan)
    });

    for size in [1024, 65536, 1_048_576] {
        group.throughput(Throughput::Bytes(size as u64));

        group.bench_with_input(BenchmarkId::new("tls_1_3", size), &size, |b, &size| {
            b.to_async(&rt).iter(|| async {
                let client_config = TrojanConfig {
                    server: trojan_addr.to_string(),
                    tag: None,
                    password: "benchmark-pass".to_string(),
                    connect_timeout_sec: Some(5),
                    sni: Some("localhost".to_string()),
                    alpn: None,
                    skip_cert_verify: true,
                    transport_layer: TransportConfig::Tcp,
                    reality: None,
                    multiplex: None,
                };

                let connector = TrojanConnector::new(client_config);
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
        });
    }

    group.finish();
}

fn bench_trojan_handshake_overhead(c: &mut Criterion) {
    setup_tracing();

    let rt = Runtime::new().unwrap();
    let mut group = c.benchmark_group("trojan_handshake");
    group.measurement_time(Duration::from_secs(10));
    group.sample_size(50);

    let (echo_addr, trojan_addr) = rt.block_on(async {
        let echo = start_echo_server().await;
        let trojan = start_trojan_server().await;
        (echo, trojan)
    });

    group.bench_function("connect_tls", |b| {
        b.to_async(&rt).iter(|| async {
            let client_config = TrojanConfig {
                server: trojan_addr.to_string(),
                tag: None,
                password: "benchmark-pass".to_string(),
                connect_timeout_sec: Some(5),
                sni: Some("example.com".to_string()),
                alpn: None,
                skip_cert_verify: true,
                transport_layer: TransportConfig::Tcp,
                reality: None,
                multiplex: None,
            };

            let connector = TrojanConnector::new(client_config);
            let target = Target {
                host: echo_addr.ip().to_string(),
                port: echo_addr.port(),
                kind: TransportKind::Tcp,
            };

            let stream = connector.dial(target, DialOpts::default()).await.unwrap();
            black_box(stream);
        });
    });

    group.finish();
}

criterion_group!(
    name = benches;
    config = Criterion::default()
        .measurement_time(Duration::from_secs(10))
        .sample_size(100);
    targets = bench_trojan_throughput, bench_trojan_handshake_overhead
);
criterion_main!(benches);
