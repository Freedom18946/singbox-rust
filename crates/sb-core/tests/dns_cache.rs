#![cfg(feature = "dns_cache")]

use std::time::Duration;

use sb_core::dns::cache::{LruDnsCache, Rcode, Source};

#[test]
fn lru_positive_negative_and_eviction() {
    let mut c = LruDnsCache::new(
        2,
        Duration::from_secs(2),
        Duration::from_secs(10),
        Duration::from_secs(1),
    );
    c.put_positive(
        "example.com",
        vec!["1.2.3.4".parse().unwrap()],
        Duration::from_secs(1),
        Source::System,
        Rcode::Ok,
    ); // clamped to 2
    assert!(c.get("example.com").is_some());

    c.put_negative("nx.example", Source::System, Rcode::NxDomain);
    let neg = c.get("nx.example").unwrap();
    assert!(neg.negative && neg.ips.is_empty());

    // capacity 2: insert 3rd triggers eviction of the oldest
    c.put_positive(
        "a",
        vec!["5.6.7.8".parse().unwrap()],
        Duration::from_secs(5),
        Source::System,
        Rcode::Ok,
    );
    // example.com should be evicted due to FIFO/LRU approximation
    let _ = c.get("a");
    assert!(c.get("example.com").is_none());
}
