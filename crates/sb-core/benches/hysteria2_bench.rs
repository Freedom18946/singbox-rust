//! Hysteria2 performance benchmarks
//!
//! Benchmarks for Hysteria2 protocol implementation to ensure
//! performance requirements are met and identify optimization opportunities.
#![allow(clippy::unwrap_used, clippy::expect_used)]
#![cfg_attr(not(feature = "bench"), allow(dead_code, unused_imports))]

#[cfg(all(feature = "bench", feature = "out_hysteria2"))]
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
#[cfg(all(feature = "bench", feature = "out_hysteria2"))]
use sb_core::outbound::hysteria2::{
    BandwidthLimiter, BrutalConfig, Hysteria2Config, Hysteria2Outbound,
};

#[cfg(all(feature = "bench", feature = "out_hysteria2"))]
fn bench_auth_hash_generation(c: &mut Criterion) {
    let config = Hysteria2Config {
        server: "127.0.0.1".to_string(),
        port: 8443,
        password: "benchmark-password-for-testing-performance".to_string(),
        congestion_control: Some("bbr".to_string()),
        up_mbps: None,
        down_mbps: None,
        obfs: None,
        skip_cert_verify: true,
        sni: None,
        alpn: None,
        salamander: None,
        brutal: None,
        tls_ca_paths: vec![],
        tls_ca_pem: vec![],
        zero_rtt_handshake: false,
    };

    let outbound = Hysteria2Outbound::new(config).unwrap();

    c.bench_function("auth_hash_generation", |b| {
        b.iter(|| black_box(outbound.generate_auth_hash()))
    });
}

#[cfg(all(feature = "bench", feature = "out_hysteria2"))]
fn bench_auth_hash_with_salamander(c: &mut Criterion) {
    let config = Hysteria2Config {
        server: "127.0.0.1".to_string(),
        port: 8443,
        password: "benchmark-password-for-testing-performance".to_string(),
        congestion_control: Some("bbr".to_string()),
        up_mbps: None,
        down_mbps: None,
        obfs: None,
        skip_cert_verify: true,
        sni: None,
        alpn: None,
        salamander: Some("benchmark-salamander-key".to_string()),
        brutal: None,
        tls_ca_paths: vec![],
        tls_ca_pem: vec![],
        zero_rtt_handshake: false,
    };

    let outbound = Hysteria2Outbound::new(config).unwrap();

    c.bench_function("auth_hash_with_salamander", |b| {
        b.iter(|| black_box(outbound.generate_auth_hash()))
    });
}

#[cfg(all(feature = "bench", feature = "out_hysteria2"))]
fn bench_obfuscation(c: &mut Criterion) {
    let config = Hysteria2Config {
        server: "127.0.0.1".to_string(),
        port: 8443,
        password: "test".to_string(),
        congestion_control: None,
        up_mbps: None,
        down_mbps: None,
        obfs: Some("benchmark-obfuscation-key".to_string()),
        skip_cert_verify: true,
        sni: None,
        alpn: None,
        salamander: None,
        brutal: None,
        tls_ca_paths: vec![],
        tls_ca_pem: vec![],
        zero_rtt_handshake: false,
    };

    let outbound = Hysteria2Outbound::new(config).unwrap();

    let mut group = c.benchmark_group("obfuscation");

    for size in [64, 256, 1024, 4096, 16384].iter() {
        let mut data = vec![0u8; *size];

        group.bench_with_input(BenchmarkId::new("apply_obfuscation", size), size, |b, _| {
            b.iter(|| outbound.apply_obfuscation(black_box(&mut data)))
        });
    }

    group.finish();
}

#[cfg(all(feature = "bench", feature = "out_hysteria2"))]
fn bench_bandwidth_limiter(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();

    let mut group = c.benchmark_group("bandwidth_limiter");

    // Test different bandwidth limits
    for mbps in [10, 100, 1000].iter() {
        let limiter = BandwidthLimiter::new(Some(*mbps), Some(*mbps));

        group.bench_with_input(BenchmarkId::new("consume_tokens", mbps), mbps, |b, _| {
            b.iter(|| rt.block_on(async { black_box(limiter.consume_up(1024).await) }))
        });
    }

    group.finish();
}

#[cfg(all(feature = "bench", feature = "out_hysteria2"))]
fn bench_config_creation(c: &mut Criterion) {
    c.bench_function("config_creation_basic", |b| {
        b.iter(|| {
            black_box(Hysteria2Config {
                server: "127.0.0.1".to_string(),
                port: 8443,
                password: "test-password".to_string(),
                congestion_control: Some("bbr".to_string()),
                up_mbps: Some(100),
                down_mbps: Some(200),
                obfs: None,
                skip_cert_verify: true,
                sni: None,
                alpn: None,
                salamander: None,
                brutal: None,
                tls_ca_paths: vec![],
                tls_ca_pem: vec![],
                zero_rtt_handshake: false,
            })
        })
    });

    c.bench_function("config_creation_full", |b| {
        b.iter(|| {
            black_box(Hysteria2Config {
                server: "example.com".to_string(),
                port: 443,
                password: "complex-password-with-special-chars!@#$%".to_string(),
                congestion_control: Some("brutal".to_string()),
                up_mbps: Some(1000),
                down_mbps: Some(2000),
                obfs: Some("obfuscation-key".to_string()),
                skip_cert_verify: false,
                sni: Some("example.com".to_string()),
                alpn: Some(vec!["h3".to_string(), "hysteria2".to_string()]),
                salamander: Some("salamander-key".to_string()),
                brutal: Some(BrutalConfig {
                    up_mbps: 500,
                    down_mbps: 1000,
                }),
                tls_ca_paths: vec![],
                tls_ca_pem: vec![],
                zero_rtt_handshake: false,
            })
        })
    });
}

#[cfg(all(feature = "bench", feature = "out_hysteria2"))]
fn bench_outbound_creation(c: &mut Criterion) {
    let config = Hysteria2Config {
        server: "127.0.0.1".to_string(),
        port: 8443,
        password: "benchmark-password".to_string(),
        congestion_control: Some("bbr".to_string()),
        up_mbps: Some(100),
        down_mbps: Some(200),
        obfs: Some("benchmark-obfs".to_string()),
        skip_cert_verify: true,
        sni: None,
        alpn: Some(vec!["h3".to_string(), "hysteria2".to_string()]),
        salamander: None,
        brutal: None,
        tls_ca_paths: vec![],
        tls_ca_pem: vec![],
        zero_rtt_handshake: false,
    };

    c.bench_function("outbound_creation", |b| {
        b.iter(|| black_box(Hysteria2Outbound::new(config.clone()).unwrap()))
    });
}

#[cfg(all(feature = "bench", feature = "out_hysteria2"))]
fn bench_congestion_control_variants(c: &mut Criterion) {
    let mut group = c.benchmark_group("congestion_control_creation");

    let algorithms = vec![
        ("bbr", "bbr"),
        ("cubic", "cubic"),
        ("newreno", "newreno"),
        ("brutal", "brutal"),
    ];

    for (name, cc) in algorithms {
        let config = Hysteria2Config {
            server: "127.0.0.1".to_string(),
            port: 8443,
            password: "test".to_string(),
            congestion_control: Some(cc.to_string()),
            up_mbps: None,
            down_mbps: None,
            obfs: None,
            skip_cert_verify: true,
            sni: None,
            alpn: None,
            salamander: None,
            brutal: if cc == "brutal" {
                Some(BrutalConfig {
                    up_mbps: 100,
                    down_mbps: 200,
                })
            } else {
                None
            },
            tls_ca_paths: vec![],
            tls_ca_pem: vec![],
            zero_rtt_handshake: false,
        };

        group.bench_with_input(BenchmarkId::new("create_outbound", name), name, |b, _| {
            b.iter(|| black_box(Hysteria2Outbound::new(config.clone()).unwrap()))
        });
    }

    group.finish();
}

#[cfg(all(feature = "bench", feature = "out_hysteria2"))]
fn bench_bandwidth_limiter_refill(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let limiter = BandwidthLimiter::new(Some(100), Some(200));

    c.bench_function("bandwidth_limiter_refill", |b| {
        b.iter(|| {
            rt.block_on(async {
                limiter.refill_tokens().await;
                black_box(())
            })
        })
    });
}

#[cfg(all(feature = "bench", feature = "out_hysteria2"))]
fn bench_protocol_packet_creation(c: &mut Criterion) {
    let mut group = c.benchmark_group("protocol_packets");

    // Benchmark auth packet creation
    group.bench_function("auth_packet", |b| {
        b.iter(|| {
            let mut auth_packet = Vec::new();
            auth_packet.push(0x01); // Auth command
            auth_packet.extend_from_slice(black_box(&[0u8; 32])); // Hash
            auth_packet.push(0x00); // No obfuscation
            black_box(auth_packet)
        })
    });

    // Benchmark connect packet creation
    group.bench_function("connect_packet_ipv4", |b| {
        b.iter(|| {
            let mut connect_packet = Vec::new();
            connect_packet.push(0x02); // TCP Connect command
            connect_packet.push(0x01); // IPv4
            connect_packet.extend_from_slice(black_box(&[127, 0, 0, 1])); // IP
            connect_packet.extend_from_slice(black_box(&80u16.to_be_bytes())); // Port
            black_box(connect_packet)
        })
    });

    group.bench_function("connect_packet_domain", |b| {
        b.iter(|| {
            let domain = black_box("example.com");
            let mut connect_packet = Vec::new();
            connect_packet.push(0x02); // TCP Connect command
            connect_packet.push(0x03); // Domain
            connect_packet.push(domain.len() as u8);
            connect_packet.extend_from_slice(domain.as_bytes());
            connect_packet.extend_from_slice(&80u16.to_be_bytes());
            black_box(connect_packet)
        })
    });

    group.finish();
}

#[cfg(all(feature = "bench", feature = "out_hysteria2"))]
criterion_group!(
    benches,
    bench_auth_hash_generation,
    bench_auth_hash_with_salamander,
    bench_obfuscation,
    bench_bandwidth_limiter,
    bench_config_creation,
    bench_outbound_creation,
    bench_congestion_control_variants,
    bench_bandwidth_limiter_refill,
    bench_protocol_packet_creation
);

#[cfg(all(feature = "bench", feature = "out_hysteria2"))]
criterion_main!(benches);

#[cfg(not(all(feature = "bench", feature = "out_hysteria2")))]
fn main() {
    println!("Hysteria2 benchmarks disabled; enable with --features bench,sb-core/out_hysteria2");
}
