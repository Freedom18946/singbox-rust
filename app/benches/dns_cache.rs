use criterion::{black_box, criterion_group, criterion_main, Criterion};
use sb_core::router::dns::DnsCache;
use std::time::Duration;

fn bench_dns_cache(c: &mut Criterion) {
    let dc = DnsCache::new(Duration::from_millis(50));
    // Ensure cache warmed at least once
    let _ = dc.resolve_cached_or_lookup("localhost");
    c.bench_function("dns_cached_lookup", |b| {
        b.iter(|| {
            let v = dc.resolve_cached_or_lookup("localhost");
            black_box(v);
        })
    });
}

criterion_group!(benches, bench_dns_cache);
criterion_main!(benches);
#[cfg(not(feature = "bench"))]
fn main() {}
