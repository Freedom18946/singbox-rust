#![allow(unused)]
use criterion::{criterion_group, criterion_main, BatchSize, Criterion};
use sb_core::router::RouterIndex;

#[cfg(feature = "router_keyword")]
fn build_rules(n: usize) -> String {
    let mut s = String::new();
    for i in 0..n {
        s.push_str(&format!("keyword:k{:04}=direct\n", i));
    }
    s.push_str("default:direct\n");
    s
}

#[cfg(feature = "router_keyword")]
fn bench_keyword(c: &mut Criterion) {
    for &n in &[64usize, 1024, 8192] {
        let name = format!("keyword_match_n{}", n);
        c.bench_function(&name, |b| {
            b.iter_batched(
                || {
                    let text = build_rules(n);
                    RouterIndex::from_str_for_test(&text)
                },
                |idx| {
                    let _ = idx.decide_http_explain("www.k4096.example.com");
                },
                BatchSize::SmallInput,
            );
        });
    }
}

#[cfg(feature = "router_keyword")]
criterion_group!(benches, bench_keyword);

#[cfg(feature = "router_keyword")]
criterion_main!(benches);

#[cfg(not(feature = "router_keyword"))]
criterion_group!(empty, dummy_benchmark);

#[cfg(not(feature = "router_keyword"))]
fn dummy_benchmark(c: &mut Criterion) {
    c.bench_function("dummy", |b| b.iter(|| {}));
}

#[cfg(not(feature = "router_keyword"))]
criterion_main!(empty);
