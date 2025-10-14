#![cfg(feature = "dns_cache")]
#![cfg(feature = "dns_cache_v1_DISABLED")]
use sb_core::dns::cache::*;
use std::net::IpAddr;

#[test]
fn pos_and_neg_cache() {
    let c = DnsCache::new(8);
    let k = Key {
        host: "example.com".into(),
        qtype: QType::A,
    };
    assert!(c.get(&k).is_none());
    c.put_pos(k.clone(), vec!["1.2.3.4".parse::<IpAddr>().unwrap()], 1);
    let (e, kind) = c.get(&k).unwrap();
    match (e, kind) {
        (Entry::Pos(pe), HitKind::Pos) => assert_eq!(pe.addrs.len(), 1),
        _ => assert!(false, "Expected positive DNS cache entry"),
    }
    // 负缓存覆盖
    c.put_neg(k.clone(), 3);
    let (e, kind) = c.get(&k).unwrap();
    match (e, kind) {
        (Entry::Neg(_), HitKind::Neg) => {}
        _ => assert!(false, "Expected negative DNS cache entry"),
    }
}
