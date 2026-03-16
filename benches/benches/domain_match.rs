use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use sb_benches::setup_tracing;
use std::time::Duration;

/// Build a DomainRuleSet from the router::matcher module (the standalone one)
fn build_ruleset(suffix_count: usize) -> sb_core::router::matcher::DomainRuleSet {
    let suffixes: Vec<String> = (0..suffix_count)
        .map(|i| format!("domain-{i}.example.com"))
        .collect();
    let exact = vec!["exact-match.com".to_string()];
    let keyword = vec!["cdn".to_string(), "static".to_string()];
    sb_core::router::matcher::DomainRuleSet::new(exact, suffixes, keyword)
}

fn domain_suffix_match(c: &mut Criterion) {
    setup_tracing();

    let mut group = c.benchmark_group("domain_suffix_match");
    group.measurement_time(Duration::from_secs(5));

    for rule_count in [10, 100, 1000] {
        let ruleset = build_ruleset(rule_count);

        // Hit case: subdomain of a suffix rule
        let hit_host = format!("sub.domain-{}.example.com", rule_count / 2);
        group.bench_with_input(
            BenchmarkId::new("hit", rule_count),
            &rule_count,
            |b, _| {
                b.iter(|| black_box(ruleset.matches_host(&hit_host)));
            },
        );

        // Miss case: no matching rule
        group.bench_with_input(
            BenchmarkId::new("miss", rule_count),
            &rule_count,
            |b, _| {
                b.iter(|| black_box(ruleset.matches_host("not-matching.other.net")));
            },
        );

        // Exact match case
        group.bench_with_input(
            BenchmarkId::new("exact", rule_count),
            &rule_count,
            |b, _| {
                b.iter(|| black_box(ruleset.matches_host("exact-match.com")));
            },
        );

        // Keyword match case
        group.bench_with_input(
            BenchmarkId::new("keyword", rule_count),
            &rule_count,
            |b, _| {
                b.iter(|| black_box(ruleset.matches_host("fast-cdn-node.cloudflare.com")));
            },
        );
    }

    group.finish();
}

criterion_group!(benches, domain_suffix_match);
criterion_main!(benches);
