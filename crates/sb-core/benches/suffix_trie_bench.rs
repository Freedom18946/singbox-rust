use criterion::{black_box, criterion_group, criterion_main, Criterion};

#[cfg(feature = "suffix_trie")]
use sb_core::router::bench_api::build_index;

#[cfg(feature = "suffix_trie")]
fn bench_trie(c: &mut Criterion) {
    let mut rules = String::new();
    for i in 0..10_000 {
        rules.push_str(&format!("suffix:dom{0:05}.example.com=proxy\n", i));
    }
    rules.push_str("default:direct\n");
    let idx = build_index(&rules);
    c.bench_function("suffix_trie_query", |b| {
        b.iter(|| {
            let host = black_box("www.dom09999.example.com");
            #[allow(unused_mut)]
            let mut out: Option<&'static str> = None;
            #[cfg(feature = "suffix_trie")]
            {
                out = idx.trial_decide_by_suffix(host);
            }
            out
        });
    });
}

#[cfg(not(feature = "suffix_trie"))]
fn bench_trie(_c: &mut Criterion) {}

criterion_group!(benches, bench_trie);
criterion_main!(benches);
