#![cfg(feature = "dns_cache")]

use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use sb_core::dns::cache::{DnsCache, Key, QType, Rcode, Source};
use sb_core::dns::DnsAnswer;

#[test]
fn basic_positive_and_negative_entries() {
    let c = DnsCache::new(2);

    // Put positive entry for example.com
    let key_example = Key {
        name: "example.com".to_string(),
        qtype: QType::A,
    };
    let ans_example = DnsAnswer {
        ips: vec![IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))],
        ttl: Duration::from_secs(1),
        source: Source::System,
        rcode: Rcode::NoError,
        created_at: std::time::Instant::now(),
    };
    c.put(key_example.clone(), ans_example);
    assert!(c.get(&key_example).is_some());

    // Put negative entry for nx.example
    let key_neg = Key {
        name: "nx.example".to_string(),
        qtype: QType::A,
    };
    c.put_negative(key_neg.clone());
    let neg = c.get(&key_neg).unwrap();
    assert!(neg.ips.is_empty());
}
