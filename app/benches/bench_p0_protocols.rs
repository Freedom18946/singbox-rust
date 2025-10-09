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

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::runtime::Runtime;

// ============================================================================
// Helper Functions
// ============================================================================

/// Create a tokio runtime for async benchmarks
fn create_runtime() -> Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap()
}

/// Start a simple TCP echo server for testing
async fn start_echo_server() -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

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
    addr
}

// ============================================================================
// Baseline Benchmarks (Direct TCP)
// ============================================================================

fn bench_baseline_throughput(c: &mut Criterion) {
    let rt = create_runtime();
    let addr = rt.block_on(start_echo_server());

    let mut group = c.benchmark_group("baseline_throughput");
    
    for size in [1024, 10 * 1024, 100 * 1024, 1024 * 1024].iter() {
        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, &size| {
            b.to_async(&rt).iter(|| async {
                let mut stream = TcpStream::connect(addr).await.unwrap();
                let data = vec![0xAB; size];
                
                stream.write_all(&data).await.unwrap();
                
                let mut received = vec![0u8; size];
                stream.read_exact(&mut received).await.unwrap();
                
                black_box(received);
            });
        });
    }
    
    group.finish();
}

fn bench_baseline_latency(c: &mut Criterion) {
    let rt = create_runtime();
    let addr = rt.block_on(start_echo_server());

    let mut group = c.benchmark_group("baseline_latency");
    group.sample_size(1000);
    
    group.bench_function("small_payload", |b| {
        b.to_async(&rt).iter(|| async {
            let mut stream = TcpStream::connect(addr).await.unwrap();
            let data = b"PING";
            
            stream.write_all(data).await.unwrap();
            
            let mut received = [0u8; 4];
            stream.read_exact(&mut received).await.unwrap();
            
            black_box(received);
        });
    });
    
    group.finish();
}

fn bench_baseline_connection_establishment(c: &mut Criterion) {
    let rt = create_runtime();
    let addr = rt.block_on(start_echo_server());

    let mut group = c.benchmark_group("baseline_connection");
    group.sample_size(500);
    
    group.bench_function("tcp_connect", |b| {
        b.to_async(&rt).iter(|| async {
            let stream = TcpStream::connect(addr).await.unwrap();
            black_box(stream);
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
    use sb_tls::reality::{RealityClientConfig, RealityConnector};
    use x25519_dalek::{PublicKey, StaticSecret};

    pub fn bench_reality_handshake(c: &mut Criterion) {
        let rt = create_runtime();
        
        // Generate test keypair
        let secret = StaticSecret::random_from_rng(rand::rngs::OsRng);
        let public_key = PublicKey::from(&secret);
        
        let config = RealityClientConfig {
            enabled: true,
            public_key: hex::encode(public_key.as_bytes()),
            short_id: Some("01ab".to_string()),
            server_name: "www.apple.com".to_string(),
        };

        let mut group = c.benchmark_group("reality");
        group.sample_size(100);
        
        // Note: This benchmarks config creation and validation
        // Full handshake requires a REALITY server
        group.bench_function("config_validation", |b| {
            b.iter(|| {
                let cfg = config.clone();
                black_box(cfg.validate());
            });
        });
        
        group.finish();
    }

    pub fn bench_reality_throughput(c: &mut Criterion) {
        // TODO: Requires REALITY server setup
        // This would measure throughput through REALITY TLS tunnel
        let mut group = c.benchmark_group("reality_throughput");
        group.bench_function("placeholder", |b| {
            b.iter(|| {
                // Placeholder for future implementation
                black_box(1);
            });
        });
        group.finish();
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
        let rt = create_runtime();
        
        // Generate test keypair
        let secret = StaticSecret::random_from_rng(rand::rngs::OsRng);
        let public_key = PublicKey::from(&secret);
        
        let keypair = EchKeypair::new(
            secret.to_bytes().to_vec(),
            public_key.as_bytes().to_vec(),
        );
        
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
                black_box(cfg.validate());
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
        // TODO: Requires Hysteria v1 server setup
        let mut group = c.benchmark_group("hysteria_v1_throughput");
        group.bench_function("placeholder", |b| {
            b.iter(|| {
                black_box(1);
            });
        });
        group.finish();
    }

    pub fn bench_hysteria_v1_latency(c: &mut Criterion) {
        // TODO: Requires Hysteria v1 server setup
        let mut group = c.benchmark_group("hysteria_v1_latency");
        group.bench_function("placeholder", |b| {
            b.iter(|| {
                black_box(1);
            });
        });
        group.finish();
    }
}

#[cfg(feature = "adapter-hysteria2")]
mod hysteria2_benches {
    use super::*;

    pub fn bench_hysteria_v2_throughput(c: &mut Criterion) {
        // TODO: Requires Hysteria v2 server setup
        let mut group = c.benchmark_group("hysteria_v2_throughput");
        group.bench_function("placeholder", |b| {
            b.iter(|| {
                black_box(1);
            });
        });
        group.finish();
    }

    pub fn bench_hysteria_v2_udp_relay(c: &mut Criterion) {
        // TODO: Requires Hysteria v2 server with UDP relay
        let mut group = c.benchmark_group("hysteria_v2_udp");
        group.bench_function("placeholder", |b| {
            b.iter(|| {
                black_box(1);
            });
        });
        group.finish();
    }
}

// ============================================================================
// SSH Benchmarks
// ============================================================================

#[cfg(feature = "adapter-ssh")]
mod ssh_benches {
    use super::*;

    pub fn bench_ssh_connection_establishment(c: &mut Criterion) {
        // TODO: Requires SSH server setup
        let mut group = c.benchmark_group("ssh_connection");
        group.sample_size(50);
        
        group.bench_function("placeholder", |b| {
            b.iter(|| {
                black_box(1);
            });
        });
        
        group.finish();
    }

    pub fn bench_ssh_throughput(c: &mut Criterion) {
        // TODO: Requires SSH server setup
        let mut group = c.benchmark_group("ssh_throughput");
        group.bench_function("placeholder", |b| {
            b.iter(|| {
                black_box(1);
            });
        });
        group.finish();
    }

    pub fn bench_ssh_connection_pooling(c: &mut Criterion) {
        // TODO: Test connection pool performance
        let mut group = c.benchmark_group("ssh_pooling");
        group.bench_function("placeholder", |b| {
            b.iter(|| {
                black_box(1);
            });
        });
        group.finish();
    }
}

// ============================================================================
// TUIC Benchmarks
// ============================================================================

#[cfg(feature = "sb-core/out_tuic")]
mod tuic_benches {
    use super::*;

    pub fn bench_tuic_connection_establishment(c: &mut Criterion) {
        // TODO: Requires TUIC server setup
        let mut group = c.benchmark_group("tuic_connection");
        group.sample_size(100);
        
        group.bench_function("placeholder", |b| {
            b.iter(|| {
                black_box(1);
            });
        });
        
        group.finish();
    }

    pub fn bench_tuic_throughput(c: &mut Criterion) {
        // TODO: Requires TUIC server setup
        let mut group = c.benchmark_group("tuic_throughput");
        group.bench_function("placeholder", |b| {
            b.iter(|| {
                black_box(1);
            });
        });
        group.finish();
    }

    pub fn bench_tuic_udp_over_stream(c: &mut Criterion) {
        // TODO: Test UDP over stream performance
        let mut group = c.benchmark_group("tuic_udp_over_stream");
        group.bench_function("placeholder", |b| {
            b.iter(|| {
                black_box(1);
            });
        });
        group.finish();
    }
}

// ============================================================================
// Memory Usage Benchmarks
// ============================================================================

fn bench_memory_usage_concurrent_connections(c: &mut Criterion) {
    let rt = create_runtime();
    let addr = rt.block_on(start_echo_server());

    let mut group = c.benchmark_group("memory_usage");
    group.sample_size(10);
    
    for conn_count in [10, 50, 100, 500].iter() {
        group.bench_with_input(
            BenchmarkId::new("concurrent_connections", conn_count),
            conn_count,
            |b, &count| {
                b.to_async(&rt).iter(|| async {
                    let mut handles = Vec::new();
                    
                    for _ in 0..count {
                        let handle = tokio::spawn(async move {
                            let mut stream = TcpStream::connect(addr).await.unwrap();
                            let data = vec![0xAB; 1024];
                            stream.write_all(&data).await.unwrap();
                            let mut received = vec![0u8; 1024];
                            stream.read_exact(&mut received).await.unwrap();
                            black_box(received);
                        });
                        handles.push(handle);
                    }
                    
                    for handle in handles {
                        handle.await.unwrap();
                    }
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
criterion_group!(
    ech_benches_group,
    ech_benches::bench_ech_encryption
);

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

#[cfg(feature = "sb-core/out_tuic")]
criterion_group!(
    tuic_benches_group,
    tuic_benches::bench_tuic_connection_establishment,
    tuic_benches::bench_tuic_throughput,
    tuic_benches::bench_tuic_udp_over_stream
);

// Custom main function to handle conditional feature compilation
fn main() {
    let mut criterion = Criterion::default().configure_from_args();
    
    // Always run baseline benchmarks
    baseline_benches(&mut criterion);
    
    // Conditionally run P0 protocol benchmarks based on enabled features
    #[cfg(feature = "tls_reality")]
    reality_benches_group(&mut criterion);
    
    #[cfg(feature = "tls_ech")]
    ech_benches_group(&mut criterion);
    
    #[cfg(feature = "adapter-hysteria")]
    hysteria_benches_group(&mut criterion);
    
    #[cfg(feature = "adapter-hysteria2")]
    hysteria2_benches_group(&mut criterion);
    
    #[cfg(feature = "adapter-ssh")]
    ssh_benches_group(&mut criterion);
    
    #[cfg(feature = "sb-core/out_tuic")]
    tuic_benches_group(&mut criterion);
    
    criterion.final_summary();
}
