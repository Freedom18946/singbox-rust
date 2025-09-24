#![cfg(feature = "dns_cache")]
use sb_core::dns::cache::*;
use std::net::IpAddr;
use std::time::Duration;

#[test]
fn stale_and_coalesced() {
    let c = DnsCache::new(8);
    let k = Key {
        host: "example.com".into(),
        qtype: QType::A,
    };
    c.put_pos(k.clone(), vec!["1.1.1.1".parse::<IpAddr>().unwrap()], 0); // 立刻过期
                                                                         // 命中 stale
    let (_e, kind) = c.get(&k).unwrap();
    matches!(kind, HitKind::Stale);
    // 并发合并计数
    assert_eq!(c.mark_inflight(&k), 1);
    assert_eq!(c.mark_inflight(&k), 2);
    c.done_inflight(&k);
    c.done_inflight(&k);
}
