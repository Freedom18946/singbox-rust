#![allow(unused)]
#![cfg_attr(not(feature = "bench"), allow(dead_code, unused_imports))]

#[cfg(all(feature = "bench", feature = "router_keyword"))]
use criterion::{criterion_group, criterion_main, BatchSize, Criterion};
#[cfg(all(feature = "bench", feature = "router_keyword"))]
use sb_core::router::router_build_index_from_str;

#[cfg(all(feature = "bench", feature = "router_keyword"))]
fn build_rules(n: usize) -> String {
    let mut s = String::new();
    for i in 0..n {
        s.push_str(&format!("keyword:k{:04}=direct\n", i));
    }
    s.push_str("default:direct\n");
    s
}

#[cfg(all(feature = "bench", feature = "router_keyword"))]
fn bench_keyword(c: &mut Criterion) {
    for &n in &[64usize, 1024, 8192] {
        let name = format!("keyword_match_n{}", n);
        c.bench_function(&name, |b| {
            b.iter_batched(
                || {
                    let text = build_rules(n);
                    router_build_index_from_str(&text, 1 << 20).unwrap()
                },
                |idx| {
                    let _ = idx.decide_http_explain("www.k4096.example.com");
                },
                BatchSize::SmallInput,
            );
        });
    }
}

#[cfg(all(feature = "bench", feature = "router_keyword"))]
criterion_group!(benches, bench_keyword);

#[cfg(all(feature = "bench", feature = "router_keyword"))]
criterion_main!(benches);

#[cfg(not(all(feature = "bench", feature = "router_keyword")))]
fn main() {
    eprintln!("keyword benches disabled; enable with --features bench,sb-core/router_keyword");
}
