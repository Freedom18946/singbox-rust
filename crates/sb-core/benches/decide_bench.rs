use criterion::{black_box, criterion_group, criterion_main, Criterion};
use sb_core::router::bench_api::build_index;
use std::fmt::Write;

fn synth_suffix(n: usize) -> String {
    let mut s = String::new();
    for i in 0..n {
        let _ = writeln!(&mut s, "suffix:suf{0:05}.com=proxy", i);
    }
    s.push_str("default:direct\n");
    s
}

fn bench_suffix_build(c: &mut Criterion) {
    let rules = synth_suffix(10_000);
    c.bench_function("build_suffix_10k", |b| {
        b.iter(|| build_index(black_box(&rules)));
    });
}

criterion_group!(benches, bench_suffix_build);
criterion_main!(benches);
