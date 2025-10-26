#![allow(clippy::unwrap_used)]
#![cfg_attr(not(feature = "bench"), allow(dead_code, unused_imports))]
#[cfg(feature = "bench")]
use criterion::{black_box, criterion_group, criterion_main, Criterion};
#[cfg(feature = "bench")]
use sb_core::router::router_build_index_from_str;
#[cfg(feature = "bench")]
use std::fmt::Write;

#[cfg(feature = "bench")]
fn synth_rules(n_exact: usize, n_suffix: usize) -> String {
    let mut s = String::new();
    for i in 0..n_exact {
        let _ = writeln!(&mut s, "exact:host{0:04}.example.com=proxy", i);
    }
    for i in 0..n_suffix {
        let _ = writeln!(&mut s, "suffix:suf{i:04}.com=direct");
    }
    s.push_str("default:direct\n");
    s
}

#[cfg(feature = "bench")]
fn bench_build(c: &mut Criterion) {
    let r1 = synth_rules(1000, 0);
    let r2 = synth_rules(0, 1000);
    c.bench_function("build_exact_1k", |b| {
        b.iter(|| router_build_index_from_str(black_box(&r1), 1 << 20).unwrap());
    });
    c.bench_function("build_suffix_1k", |b| {
        b.iter(|| router_build_index_from_str(black_box(&r2), 1 << 20).unwrap());
    });
}

#[cfg(feature = "bench")]
criterion_group!(benches, bench_build);
#[cfg(feature = "bench")]
criterion_main!(benches);

#[cfg(not(feature = "bench"))]
fn main() {
    eprintln!("router benches disabled; enable with --features bench");
}
