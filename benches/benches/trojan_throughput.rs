#![allow(deprecated)]
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use sb_adapters::inbound::trojan::TrojanInboundConfig;
use sb_adapters::outbound::trojan::{TrojanConfig, TrojanConnector};
use sb_adapters::outbound::{DialOpts, OutboundConnector, Target};
use sb_adapters::transport_config::TransportConfig;
use sb_adapters::TransportKind;
use sb_benches::setup_tracing;
use sb_core::router::engine::RouterHandle;
use std::io::Write;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::runtime::Runtime;

struct TrojanServerHandle {
    addr: SocketAddr,
    _stop_tx: tokio::sync::mpsc::Sender<()>,
    _cert_file: tempfile::NamedTempFile,
    _key_file: tempfile::NamedTempFile,
}

fn disable_inbound_rate_limit_for_bench() {
    // Throughput benches create many short-lived connections and would hit default per-IP limits.
    std::env::set_var("SB_INBOUND_RATE_LIMIT_PER_IP", "0");
    std::env::set_var("SB_INBOUND_RATE_LIMIT_QPS", "0");
}

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
async fn start_trojan_server() -> TrojanServerHandle {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);

    let (stop_tx, stop_rx) = tokio::sync::mpsc::channel(1);

    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let cert_pem = cert.cert.pem();
    let key_pem = cert.key_pair.serialize_pem();
    let mut cert_file = tempfile::NamedTempFile::new().unwrap();
    cert_file.write_all(cert_pem.as_bytes()).unwrap();
    let mut key_file = tempfile::NamedTempFile::new().unwrap();
    key_file.write_all(key_pem.as_bytes()).unwrap();

    let config = TrojanInboundConfig {
        listen: addr,
        password: Some("benchmark-pass".to_string()),
        cert_path: cert_file.path().to_string_lossy().to_string(),
        key_path: key_file.path().to_string_lossy().to_string(),
        router: Arc::new(RouterHandle::new_mock()),
        tag: None,
        stats: None,
        conn_tracker: Arc::new(sb_common::conntrack::ConnTracker::new()),
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

    // Do not probe with a raw TCP connection: it can be interpreted as a bad handshake.
    tokio::time::sleep(Duration::from_millis(200)).await;

    TrojanServerHandle {
        addr,
        _stop_tx: stop_tx,
        _cert_file: cert_file,
        _key_file: key_file,
    }
}

async fn wait_for_trojan_ready(
    server_addr: SocketAddr,
    target: SocketAddr,
    timeout: Duration,
) -> bool {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let client_config = TrojanConfig {
            server: server_addr.to_string(),
            tag: None,
            password: "benchmark-pass".to_string(),
            connect_timeout_sec: Some(2),
            sni: Some("localhost".to_string()),
            alpn: None,
            skip_cert_verify: true,
            detour: None,
            transport_layer: TransportConfig::Tcp,
            reality: None,
            multiplex: None,
        };
        let connector = TrojanConnector::new(client_config);
        let dial = connector
            .dial(
                Target {
                    host: target.ip().to_string(),
                    port: target.port(),
                    kind: TransportKind::Tcp,
                },
                DialOpts::default(),
            )
            .await;
        if dial.is_ok() {
            return true;
        }
        if tokio::time::Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

fn bench_trojan_throughput(c: &mut Criterion) {
    setup_tracing();
    disable_inbound_rate_limit_for_bench();

    let rt = Runtime::new().unwrap();
    let dropped_iterations = Arc::new(AtomicU64::new(0));
    let reconnect_failures = Arc::new(AtomicU64::new(0));
    let mut group = c.benchmark_group("trojan_throughput");
    group.measurement_time(Duration::from_secs(10));
    group.sample_size(20);

    // Start servers
    let (echo_addr, trojan_server) = rt.block_on(async {
        let echo = start_echo_server().await;
        let trojan = start_trojan_server().await;
        (echo, trojan)
    });
    let trojan_addr = trojan_server.addr;
    rt.block_on(async {
        if !wait_for_trojan_ready(trojan_addr, echo_addr, Duration::from_secs(3)).await {
            eprintln!(
                "warn: trojan server readiness probe timed out at {}",
                trojan_addr
            );
        }
    });

    for size in [1024, 65536, 1_048_576] {
        group.throughput(Throughput::Bytes(size as u64));
        let dropped_iterations = Arc::clone(&dropped_iterations);
        let reconnect_failures = Arc::clone(&reconnect_failures);

        group.bench_with_input(BenchmarkId::new("tls_1_3", size), &size, |b, &size| {
            let dropped_iterations = Arc::clone(&dropped_iterations);
            let reconnect_failures = Arc::clone(&reconnect_failures);
            b.to_async(&rt).iter_custom(move |iters| {
                let dropped_iterations = Arc::clone(&dropped_iterations);
                let reconnect_failures = Arc::clone(&reconnect_failures);
                async move {
                let client_config = TrojanConfig {
                    server: trojan_addr.to_string(),
                    tag: None,
                    password: "benchmark-pass".to_string(),
                    connect_timeout_sec: Some(5),
                    sni: Some("localhost".to_string()),
                    alpn: None,
                    skip_cert_verify: true,
                    detour: None,
                    transport_layer: TransportConfig::Tcp,
                    reality: None,
                    multiplex: None,
                };

                let connector = TrojanConnector::new(client_config);
                let connect = || async {
                    let mut last_err = String::new();
                    for _ in 0..10 {
                        let target = Target {
                            host: echo_addr.ip().to_string(),
                            port: echo_addr.port(),
                            kind: TransportKind::Tcp,
                        };
                        match connector.dial(target, DialOpts::default()).await {
                            Ok(stream) => return Some(stream),
                            Err(err) => {
                                last_err = err.to_string();
                                tokio::time::sleep(Duration::from_millis(100)).await;
                            }
                        }
                    }
                    eprintln!(
                        "skip benchmark block: TCP connection to Trojan server {} failed after retries: {}",
                        trojan_addr, last_err
                    );
                    None
                };

                let Some(mut stream) = connect().await else {
                    dropped_iterations.fetch_add(1, Ordering::Relaxed);
                    return Duration::from_secs(0);
                };
                let data = vec![0u8; size];
                let mut buf = vec![0u8; size];
                let started = std::time::Instant::now();

                for _ in 0..iters {
                    match tokio::time::timeout(Duration::from_secs(2), stream.write_all(&data))
                        .await
                    {
                        Ok(Ok(())) => {}
                        Ok(Err(err)) => {
                            eprintln!("reconnect after write failure: {}", err);
                            if let Some(new_stream) = connect().await {
                                stream = new_stream;
                            } else {
                                reconnect_failures.fetch_add(1, Ordering::Relaxed);
                                break;
                            }
                            continue;
                        }
                        Err(_) => {
                            eprintln!("reconnect after write timeout");
                            if let Some(new_stream) = connect().await {
                                stream = new_stream;
                            } else {
                                reconnect_failures.fetch_add(1, Ordering::Relaxed);
                                break;
                            }
                            continue;
                        }
                    }

                    match tokio::time::timeout(Duration::from_secs(2), stream.read_exact(&mut buf))
                        .await
                    {
                        Ok(Ok(_)) => {}
                        Ok(Err(err)) => {
                            eprintln!("reconnect after read failure: {}", err);
                            if let Some(new_stream) = connect().await {
                                stream = new_stream;
                            } else {
                                reconnect_failures.fetch_add(1, Ordering::Relaxed);
                                break;
                            }
                            continue;
                        }
                        Err(_) => {
                            eprintln!("reconnect after read timeout");
                            if let Some(new_stream) = connect().await {
                                stream = new_stream;
                            } else {
                                reconnect_failures.fetch_add(1, Ordering::Relaxed);
                                break;
                            }
                            continue;
                        }
                    }
                    black_box(&buf);
                }
                started.elapsed()
            }
            });
        });
    }

    group.finish();
    eprintln!(
        "trojan_throughput summary: dropped_iterations={} reconnect_failures={}",
        dropped_iterations.load(Ordering::Relaxed),
        reconnect_failures.load(Ordering::Relaxed)
    );
}

fn bench_trojan_handshake_overhead(c: &mut Criterion) {
    setup_tracing();
    disable_inbound_rate_limit_for_bench();

    let rt = Runtime::new().unwrap();
    let handshake_skips = Arc::new(AtomicU64::new(0));
    let mut group = c.benchmark_group("trojan_handshake");
    group.measurement_time(Duration::from_secs(10));
    group.sample_size(50);

    let (echo_addr, trojan_server) = rt.block_on(async {
        let echo = start_echo_server().await;
        let trojan = start_trojan_server().await;
        (echo, trojan)
    });
    let trojan_addr = trojan_server.addr;
    rt.block_on(async {
        if !wait_for_trojan_ready(trojan_addr, echo_addr, Duration::from_secs(3)).await {
            eprintln!(
                "warn: trojan handshake server readiness probe timed out at {}",
                trojan_addr
            );
        }
    });

    group.bench_function("connect_tls", |b| {
        let handshake_skips = Arc::clone(&handshake_skips);
        b.to_async(&rt).iter(|| async {
            let client_config = TrojanConfig {
                server: trojan_addr.to_string(),
                tag: None,
                password: "benchmark-pass".to_string(),
                connect_timeout_sec: Some(5),
                sni: Some("example.com".to_string()),
                alpn: None,
                skip_cert_verify: true,
                detour: None,
                transport_layer: TransportConfig::Tcp,
                reality: None,
                multiplex: None,
            };

            let connector = TrojanConnector::new(client_config);
            let stream = {
                let mut connected = None;
                let mut last_err = String::new();
                for _ in 0..10 {
                    let target = Target {
                        host: echo_addr.ip().to_string(),
                        port: echo_addr.port(),
                        kind: TransportKind::Tcp,
                    };
                    match connector.dial(target, DialOpts::default()).await {
                        Ok(stream) => {
                            connected = Some(stream);
                            break;
                        }
                        Err(err) => {
                            last_err = err.to_string();
                            tokio::time::sleep(Duration::from_millis(100)).await;
                        }
                    }
                }
                match connected {
                    Some(stream) => stream,
                    None => {
                        handshake_skips.fetch_add(1, Ordering::Relaxed);
                        eprintln!(
                            "skip iteration: TCP connection to Trojan server {} failed after retries: {}",
                            trojan_addr, last_err
                        );
                        tokio::time::sleep(Duration::from_millis(200)).await;
                        return;
                    }
                }
            };
            black_box(stream);
        });
    });

    group.finish();
    eprintln!(
        "trojan_handshake summary: skipped_iterations={}",
        handshake_skips.load(Ordering::Relaxed)
    );
}

criterion_group!(
    name = benches;
    config = Criterion::default()
        .measurement_time(Duration::from_secs(10))
        .sample_size(100);
    targets = bench_trojan_throughput, bench_trojan_handshake_overhead
);
criterion_main!(benches);
