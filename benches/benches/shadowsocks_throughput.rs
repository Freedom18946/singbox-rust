#![allow(deprecated)]
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use sb_adapters::inbound::shadowsocks::ShadowsocksInboundConfig;
use sb_adapters::outbound::shadowsocks::{ShadowsocksConfig, ShadowsocksConnector};
use sb_adapters::outbound::{DialOpts, OutboundConnector, Target};
use sb_adapters::TransportKind;
use sb_benches::setup_tracing;
use sb_core::router::engine::RouterHandle;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::runtime::Runtime;

struct SsServerHandle {
    addr: SocketAddr,
    _stop_tx: tokio::sync::mpsc::Sender<()>,
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

async fn wait_for_tcp_ready(addr: SocketAddr, timeout: Duration) -> bool {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if TcpStream::connect(addr).await.is_ok() {
            return true;
        }
        if tokio::time::Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

// Helper: Start Shadowsocks server
async fn start_ss_server(method: &str) -> SsServerHandle {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);

    let (stop_tx, stop_rx) = tokio::sync::mpsc::channel(1);

    let config = ShadowsocksInboundConfig {
        listen: addr,
        method: method.to_string(),
        password: Some("benchmark-pass".to_string()),
        router: Arc::new(RouterHandle::new_mock()),
        tag: None,
        stats: None,
        multiplex: None,
        transport_layer: None,
        users: vec![],
    };

    tokio::spawn(async move {
        let _ = sb_adapters::inbound::shadowsocks::serve(config, stop_rx).await;
    });

    if !wait_for_tcp_ready(addr, Duration::from_secs(2)).await {
        eprintln!("warn: shadowsocks server readiness probe timed out at {addr}");
    }

    SsServerHandle {
        addr,
        _stop_tx: stop_tx,
    }
}

fn bench_ss_e2e_throughput(c: &mut Criterion) {
    setup_tracing();
    disable_inbound_rate_limit_for_bench();

    let rt = Runtime::new().unwrap();
    let dropped_iterations = Arc::new(AtomicU64::new(0));
    let reconnect_failures = Arc::new(AtomicU64::new(0));
    let mut group = c.benchmark_group("shadowsocks_e2e_throughput");
    group.measurement_time(Duration::from_secs(10));
    group.sample_size(20);

    for cipher in ["aes-256-gcm", "chacha20-ietf-poly1305"] {
        // Start servers once per cipher
        let (echo_addr, ss_server) = rt.block_on(async {
            let echo = start_echo_server().await;
            let ss = start_ss_server(cipher).await;
            (echo, ss)
        });
        let ss_addr = ss_server.addr;

        for size in [1024, 65536, 1_048_576] {
            group.throughput(Throughput::Bytes(size as u64));
            let dropped_iterations = Arc::clone(&dropped_iterations);
            let reconnect_failures = Arc::clone(&reconnect_failures);

            group.bench_with_input(
                BenchmarkId::new(cipher, size),
                &(cipher, size),
                |b, &(cipher, size)| {
                    let dropped_iterations = Arc::clone(&dropped_iterations);
                    let reconnect_failures = Arc::clone(&reconnect_failures);
                    b.to_async(&rt).iter_custom(move |iters| {
                        let dropped_iterations = Arc::clone(&dropped_iterations);
                        let reconnect_failures = Arc::clone(&reconnect_failures);
                        async move {
                        let client_config = ShadowsocksConfig {
                            server: ss_addr.to_string(),
                            tag: None,
                            method: cipher.to_string(),
                            password: "benchmark-pass".to_string(),
                            connect_timeout_sec: Some(5),
                            detour: None,
                            multiplex: None,
                        };
                        let connector = ShadowsocksConnector::new(client_config).unwrap();

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
                                "skip benchmark block: TCP connection to Shadowsocks server {} failed after retries: {}",
                                ss_addr, last_err
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
                            match tokio::time::timeout(Duration::from_secs(2), stream.write_all(&data)).await {
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
                            match tokio::time::timeout(Duration::from_secs(2), stream.read_exact(&mut buf)).await {
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
                },
            );
        }
    }

    group.finish();
    eprintln!(
        "shadowsocks_e2e_throughput summary: dropped_iterations={} reconnect_failures={}",
        dropped_iterations.load(Ordering::Relaxed),
        reconnect_failures.load(Ordering::Relaxed)
    );
}

criterion_group!(
    name = benches;
    config = Criterion::default()
        .measurement_time(Duration::from_secs(10))
        .sample_size(20);
    targets = bench_ss_e2e_throughput
);
criterion_main!(benches);
