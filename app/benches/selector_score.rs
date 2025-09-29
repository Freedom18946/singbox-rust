use criterion::{black_box, criterion_group, criterion_main, Criterion};
use sb_core::outbound::p3_selector::{P3Selector, PickerConfig};

fn bench_selector_score(c: &mut Criterion) {
    let mut s = P3Selector::new(
        vec!["a".into(), "b".into(), "c".into()],
        PickerConfig::default(),
    );
    // Warm up with some observations
    for _ in 0..128 {
        s.record_rtt("a", 20.0);
        s.record_rtt("b", 30.0);
        s.record_rtt("c", 25.0);
    }
    c.bench_function("selector_pick", |b| {
        b.iter(|| {
            let pick = s.pick();
            black_box(pick);
        })
    });
}

criterion_group!(benches, bench_selector_score);
criterion_main!(benches);
