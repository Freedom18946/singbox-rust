//! Hysteria2 construction benchmarks after relocation to sb-adapters.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use sb_adapters::outbound::hysteria2::{
    Hysteria2AdapterConfig, Hysteria2BrutalConfig, Hysteria2Connector,
};
use sb_types::Outbound;

fn benchmark_config() -> Hysteria2AdapterConfig {
    Hysteria2AdapterConfig {
        tag: Some("benchmark-hy2".to_string()),
        server: "127.0.0.1".to_string(),
        port: 8443,
        password: "benchmark-password".to_string(),
        skip_cert_verify: true,
        sni: Some("example.com".to_string()),
        alpn: Some(vec!["h3".to_string(), "hysteria2".to_string()]),
        congestion_control: Some("brutal".to_string()),
        up_mbps: Some(100),
        down_mbps: Some(200),
        obfs: Some("benchmark-obfs".to_string()),
        salamander: Some("benchmark-salamander".to_string()),
        brutal: Some(Hysteria2BrutalConfig {
            up_mbps: 100,
            down_mbps: 200,
        }),
        tls_ca_paths: Vec::new(),
        tls_ca_pem: Vec::new(),
        zero_rtt_handshake: false,
    }
}

fn bench_connector_creation(c: &mut Criterion) {
    let config = benchmark_config();
    c.bench_function("hysteria2_connector_creation", |b| {
        b.iter(|| Hysteria2Connector::new(black_box(config.clone())))
    });
}

fn bench_contract_access(c: &mut Criterion) {
    let connector = Hysteria2Connector::new(benchmark_config());
    c.bench_function("hysteria2_contract_access", |b| {
        b.iter(|| {
            black_box(connector.tag());
            black_box(connector.network());
        })
    });
}

criterion_group!(benches, bench_connector_creation, bench_contract_access);
criterion_main!(benches);
