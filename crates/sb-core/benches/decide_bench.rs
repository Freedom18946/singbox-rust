#![allow(clippy::unwrap_used)]
#[cfg(feature = "bench")]
use criterion::{black_box, criterion_group, criterion_main, Criterion};
#[cfg(feature = "bench")]
use sb_core::router::bench_api::build_index;
#[cfg(feature = "bench")]
use std::fmt::Write;

#[cfg(feature = "bench")]
fn synth_suffix(n: usize) -> String {
    let mut s = String::new();
    for i in 0..n {
        let _ = writeln!(&mut s, "suffix:suf{0:05}.com=proxy", i);
    }
    s.push_str("default:direct\n");
    s
}

#[cfg(feature = "bench")]
fn bench_suffix_build(c: &mut Criterion) {
    let rules = synth_suffix(10_000);
    c.bench_function("build_suffix_10k", |b| {
        b.iter(|| build_index(black_box(&rules)));
    });
}

#[cfg(feature = "bench")]
criterion_group!(benches, bench_suffix_build);
#[cfg(feature = "bench")]
criterion_main!(benches);

#[cfg(not(feature = "bench"))]
fn main() {
    eprintln!("sb-core benches disabled; enable with --features bench");
}
