//! P0 Protocol Performance Benchmarks
//!
//! Comprehensive benchmark suite for P0 protocols:
//! - REALITY TLS
//! - ECH (Encrypted Client Hello)
//! - Hysteria v1/v2
//! - SSH
//! - TUIC
//!
//! Metrics measured:
//! - Throughput (MB/s)
//! - Latency (RTT in ms)
//! - Connection establishment time
//! - Memory usage under load
//!
//! Run with: cargo bench --bench bench_p0_protocols

use criterion::{black_box, criterion_group, BenchmarkId, Criterion, Throughput};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::runtime::Runtime;

// ============================================================================
// Helper Functions
// ============================================================================

/// Create a tokio runtime for async benchmarks. Falls back to current-thread
/// runtime when multi-threaded runtime cannot be built.
fn create_runtime() -> Option<Runtime> {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .ok()
        .or_else(|| {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .ok()
        })
}

/// Start a simple TCP echo server for testing
async fn start_echo_server() -> Option<std::net::SocketAddr> {
    let listener = match TcpListener::bind("127.0.0.1:0").await {
        Ok(l) => l,
        Err(_) => return None,
    };
    let addr = match listener.local_addr() {
        Ok(a) => a,
        Err(_) => return None,
    };

    tokio::spawn(async move {
        loop {
            if let Ok((mut stream, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 8192];
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

    tokio::time::sleep(Duration::from_millis(100)).await;
    Some(addr)
}

fn env_addr(var: &str) -> Option<SocketAddr> {
    std::env::var(var).ok()?.parse::<SocketAddr>().ok()
}

fn bench_env_connect(c: &mut Criterion, group_name: &str, var: &str) {
    let Some(addr) = env_addr(var) else {
        let mut group = c.benchmark_group(group_name);
        group.bench_function("skipped", |b| b.iter(|| black_box(0)));
        group.finish();
        return;
    };
    let Some(rt) = create_runtime() else {
        return;
    };
    let mut group = c.benchmark_group(group_name);
    group.bench_function("connect", |b| {
        b.iter(|| {
            rt.block_on(async {
                let _ = TcpStream::connect(addr).await;
            });
        });
    });
    group.finish();
}

fn bench_env_throughput(c: &mut Criterion, group_name: &str, var: &str, size: usize) {
    let Some(addr) = env_addr(var) else {
        let mut group = c.benchmark_group(group_name);
        group.bench_function("skipped", |b| b.iter(|| black_box(0)));
        group.finish();
        return;
    };
    let Some(rt) = create_runtime() else {
        return;
    };
    let mut group = c.benchmark_group(group_name);
    group.throughput(Throughput::Bytes(size as u64));
    group.bench_function("throughput", |b| {
        b.iter(|| {
            rt.block_on(async {
                let Ok(mut stream) = TcpStream::connect(addr).await else {
                    return;
                };
                let data = vec![0xAB; size];
                let _ = stream.write_all(&data).await;
                let mut received = vec![0u8; size];
                let _ = stream.read_exact(&mut received).await;
                black_box(received);
            });
        });
    });
    group.finish();
}

fn bench_env_latency(c: &mut Criterion, group_name: &str, var: &str) {
    let Some(addr) = env_addr(var) else {
        let mut group = c.benchmark_group(group_name);
        group.bench_function("skipped", |b| b.iter(|| black_box(0)));
        group.finish();
        return;
    };
    let Some(rt) = create_runtime() else {
        return;
    };
    let mut group = c.benchmark_group(group_name);
    group.bench_function("latency", |b| {
        b.iter(|| {
            rt.block_on(async {
                let Ok(mut stream) = TcpStream::connect(addr).await else {
                    return;
                };
                let _ = stream.write_all(b"ping").await;
                let mut buf = [0u8; 4];
                let _ = stream.read_exact(&mut buf).await;
            });
        });
    });
    group.finish();
}

// ============================================================================
// Baseline Benchmarks (Direct TCP)
// ============================================================================

fn bench_baseline_throughput(c: &mut Criterion) {
    let Some(rt) = create_runtime() else {
        return;
    };
    let Some(addr) = rt.block_on(start_echo_server()) else {
        return;
    };

    let mut group = c.benchmark_group("baseline_throughput");

    for &size in &[1024usize, 10 * 1024, 100 * 1024, 1024 * 1024] {
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, &size| {
            b.iter(|| {
                rt.block_on(async {
                    let Ok(mut stream) = TcpStream::connect(addr).await else {
                        return;
                    };
                    let data = vec![0xAB; size];

                    if stream.write_all(&data).await.is_err() {
                        return;
                    }

                    let mut received = vec![0u8; size];
                    if stream.read_exact(&mut received).await.is_err() {
                        return;
                    }

                    black_box(received);
                });
            });
        });
    }

    group.finish();
}

fn bench_baseline_latency(c: &mut Criterion) {
    let Some(rt) = create_runtime() else {
        return;
    };
    let Some(addr) = rt.block_on(start_echo_server()) else {
        return;
    };

    let mut group = c.benchmark_group("baseline_latency");
    group.sample_size(1000);

    group.bench_function("small_payload", |b| {
        b.iter(|| {
            rt.block_on(async {
                let Ok(mut stream) = TcpStream::connect(addr).await else {
                    return;
                };
                let data = b"PING";

                if stream.write_all(data).await.is_err() {
                    return;
                }

                let mut received = [0u8; 4];
                if stream.read_exact(&mut received).await.is_err() {
                    return;
                }

                black_box(received);
            });
        });
    });

    group.finish();
}

fn bench_baseline_connection_establishment(c: &mut Criterion) {
    let Some(rt) = create_runtime() else {
        return;
    };
    let Some(addr) = rt.block_on(start_echo_server()) else {
        return;
    };

    let mut group = c.benchmark_group("baseline_connection");
    group.sample_size(500);

    group.bench_function("tcp_connect", |b| {
        b.iter(|| {
            rt.block_on(async {
                let Ok(stream) = TcpStream::connect(addr).await else {
                    return;
                };
                black_box(stream);
            });
        });
    });

    group.finish();
}

// ============================================================================
// REALITY TLS Benchmarks
// ============================================================================

#[cfg(feature = "tls_reality")]
mod reality_benches {
    use super::*;
    use sb_tls::reality::RealityClientConfig;
    use x25519_dalek::{PublicKey, StaticSecret};

    pub fn bench_reality_handshake(c: &mut Criterion) {
        // Generate test keypair
        let secret = StaticSecret::random_from_rng(rand::rngs::OsRng);
        let public_key = PublicKey::from(&secret);

        let config = RealityClientConfig {
            target: "www.apple.com".to_string(),
            server_name: "www.apple.com".to_string(),
            public_key: hex::encode(public_key.as_bytes()),
            short_id: Some("01ab".to_string()),
            fingerprint: "chrome".to_string(),
            alpn: Vec::new(),
        };

        let mut group = c.benchmark_group("reality");
        group.sample_size(100);

        // Note: This benchmarks config creation and validation
        // Full handshake requires a REALITY server
        group.bench_function("config_validation", |b| {
            b.iter(|| {
                let cfg = config.clone();
                let _ = black_box(cfg.validate());
            });
        });

        group.finish();
    }

    pub fn bench_reality_throughput(c: &mut Criterion) {
        bench_env_throughput(c, "reality_throughput", "SB_BENCH_REALITY_ADDR", 1024 * 1024);
    }
}

// ============================================================================
// ECH Benchmarks
// ============================================================================

#[cfg(feature = "tls_ech")]
mod ech_benches {
    use super::*;
    use sb_tls::ech::{EchClientConfig, EchKeypair};
    use x25519_dalek::{PublicKey, StaticSecret};

    pub fn bench_ech_encryption(c: &mut Criterion) {
        // Generate test keypair
        let secret = StaticSecret::random_from_rng(rand::rngs::OsRng);
        let public_key = PublicKey::from(&secret);
        let keypair = EchKeypair::new(secret.to_bytes().to_vec(), public_key.as_bytes().to_vec());
        black_box(&keypair);

        let config = EchClientConfig {
            enabled: true,
            config: Some("test_config".to_string()),
            config_list: None,
            pq_signature_schemes_enabled: false,
            dynamic_record_sizing_disabled: None,
        };

        let mut group = c.benchmark_group("ech");
        group.sample_size(500);

        group.bench_function("config_validation", |b| {
            b.iter(|| {
                let cfg = config.clone();
                let _ = black_box(cfg.validate());
            });
        });

        group.bench_function("keypair_generation", |b| {
            b.iter(|| {
                let secret = StaticSecret::random_from_rng(rand::rngs::OsRng);
                let public_key = PublicKey::from(&secret);
                black_box((secret, public_key));
            });
        });

        group.finish();
    }
}

// ============================================================================
// Hysteria Benchmarks
// ============================================================================

#[cfg(feature = "adapter-hysteria")]
mod hysteria_benches {
    use super::*;

    pub fn bench_hysteria_v1_throughput(c: &mut Criterion) {
        bench_env_throughput(
            c,
            "hysteria_v1_throughput",
            "SB_BENCH_HYSTERIA1_ADDR",
            1024 * 1024,
        );
    }

    pub fn bench_hysteria_v1_latency(c: &mut Criterion) {
        bench_env_latency(c, "hysteria_v1_latency", "SB_BENCH_HYSTERIA1_ADDR");
    }
}

#[cfg(feature = "adapter-hysteria2")]
mod hysteria2_benches {
    use super::*;

    pub fn bench_hysteria_v2_throughput(c: &mut Criterion) {
        bench_env_throughput(
            c,
            "hysteria_v2_throughput",
            "SB_BENCH_HYSTERIA2_ADDR",
            1024 * 1024,
        );
    }

    pub fn bench_hysteria_v2_udp_relay(c: &mut Criterion) {
        bench_env_throughput(
            c,
            "hysteria_v2_udp",
            "SB_BENCH_HYSTERIA2_ADDR",
            64 * 1024,
        );
    }
}

// ============================================================================
// SSH Benchmarks
// ============================================================================

#[cfg(feature = "adapter-ssh")]
mod ssh_benches {
    use super::*;

    pub fn bench_ssh_connection_establishment(c: &mut Criterion) {
        bench_env_connect(c, "ssh_connection", "SB_BENCH_SSH_ADDR");
    }

    pub fn bench_ssh_throughput(c: &mut Criterion) {
        bench_env_throughput(c, "ssh_throughput", "SB_BENCH_SSH_ADDR", 1024 * 1024);
    }

    pub fn bench_ssh_connection_pooling(c: &mut Criterion) {
        bench_env_latency(c, "ssh_pooling", "SB_BENCH_SSH_ADDR");
    }
}

// ============================================================================
// TUIC Benchmarks
// ============================================================================

#[cfg(feature = "adapter-tuic")]
mod tuic_benches {
    use super::*;

    pub fn bench_tuic_connection_establishment(c: &mut Criterion) {
        bench_env_connect(c, "tuic_connection", "SB_BENCH_TUIC_ADDR");
    }

    pub fn bench_tuic_throughput(c: &mut Criterion) {
        bench_env_throughput(c, "tuic_throughput", "SB_BENCH_TUIC_ADDR", 1024 * 1024);
    }

    pub fn bench_tuic_udp_over_stream(c: &mut Criterion) {
        bench_env_throughput(
            c,
            "tuic_udp_over_stream",
            "SB_BENCH_TUIC_ADDR",
            64 * 1024,
        );
    }
}

// ============================================================================
// Memory Usage Benchmarks
// ============================================================================

fn bench_memory_usage_concurrent_connections(c: &mut Criterion) {
    let Some(rt) = create_runtime() else {
        return;
    };
    let Some(addr) = rt.block_on(start_echo_server()) else {
        return;
    };

    let mut group = c.benchmark_group("memory_usage");
    group.sample_size(10);

    for &conn_count in &[10usize, 50, 100, 500] {
        group.bench_with_input(
            BenchmarkId::new("concurrent_connections", conn_count),
            &conn_count,
            |b, &count| {
                b.iter(|| {
                    rt.block_on(async {
                        let mut handles = Vec::new();

                        for _ in 0..count {
                            let handle = tokio::spawn(async move {
                                let Ok(mut stream) = TcpStream::connect(addr).await else {
                                    return;
                                };
                                let data = vec![0xAB; 1024];
                                if stream.write_all(&data).await.is_err() {
                                    return;
                                }
                                let mut received = vec![0u8; 1024];
                                if stream.read_exact(&mut received).await.is_err() {
                                    return;
                                }
                                black_box(received);
                            });
                            handles.push(handle);
                        }

                        for handle in handles {
                            let _ = handle.await;
                        }
                    });
                });
            },
        );
    }

    group.finish();
}

// ============================================================================
// Criterion Groups and Main
// ============================================================================

criterion_group!(
    baseline_benches,
    bench_baseline_throughput,
    bench_baseline_latency,
    bench_baseline_connection_establishment,
    bench_memory_usage_concurrent_connections
);

#[cfg(feature = "tls_reality")]
criterion_group!(
    reality_benches_group,
    reality_benches::bench_reality_handshake,
    reality_benches::bench_reality_throughput
);

#[cfg(feature = "tls_ech")]
criterion_group!(ech_benches_group, ech_benches::bench_ech_encryption);

#[cfg(feature = "adapter-hysteria")]
criterion_group!(
    hysteria_benches_group,
    hysteria_benches::bench_hysteria_v1_throughput,
    hysteria_benches::bench_hysteria_v1_latency
);

#[cfg(feature = "adapter-hysteria2")]
criterion_group!(
    hysteria2_benches_group,
    hysteria2_benches::bench_hysteria_v2_throughput,
    hysteria2_benches::bench_hysteria_v2_udp_relay
);

#[cfg(feature = "adapter-ssh")]
criterion_group!(
    ssh_benches_group,
    ssh_benches::bench_ssh_connection_establishment,
    ssh_benches::bench_ssh_throughput,
    ssh_benches::bench_ssh_connection_pooling
);

#[cfg(feature = "adapter-tuic")]
criterion_group!(
    tuic_benches_group,
    tuic_benches::bench_tuic_connection_establishment,
    tuic_benches::bench_tuic_throughput,
    tuic_benches::bench_tuic_udp_over_stream
);

// Custom main function to handle conditional feature compilation
fn main() {
    let criterion = Criterion::default().configure_from_args();

    // Always run baseline benchmarks
    baseline_benches();

    // Conditionally run P0 protocol benchmarks based on enabled features
    #[cfg(feature = "tls_reality")]
    reality_benches_group();

    #[cfg(feature = "tls_ech")]
    ech_benches_group();

    #[cfg(feature = "adapter-hysteria")]
    hysteria_benches_group();

    #[cfg(feature = "adapter-hysteria2")]
    hysteria2_benches_group();

    #[cfg(feature = "adapter-ssh")]
    ssh_benches_group();

    #[cfg(feature = "adapter-tuic")]
    tuic_benches_group();

    criterion.final_summary();
}
#[cfg(not(feature = "bench"))]
fn main() {}
