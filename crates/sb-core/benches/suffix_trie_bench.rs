#![cfg_attr(not(feature = "bench"), allow(dead_code, unused_imports))]
#[cfg(feature = "bench")]
use criterion::{black_box, criterion_group, criterion_main, Criterion};

#[cfg(all(feature = "bench", feature = "suffix_trie"))]
use sb_core::router::bench_api::build_index;

#[cfg(all(feature = "bench", feature = "suffix_trie"))]
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
            #[cfg(feature = "suffix_trie")]
            {
                idx.trial_decide_by_suffix(host)
            }
            #[cfg(not(feature = "suffix_trie"))]
            {
                None::<&'static str>
            }
        });
    });
}

#[cfg(not(all(feature = "bench", feature = "suffix_trie")))]
fn main() {
    eprintln!("suffix_trie bench disabled; enable with --features bench,sb-core/suffix_trie");
}

#[cfg(all(feature = "bench", feature = "suffix_trie"))]
criterion_group!(benches, bench_trie);
#[cfg(all(feature = "bench", feature = "suffix_trie"))]
criterion_main!(benches);
