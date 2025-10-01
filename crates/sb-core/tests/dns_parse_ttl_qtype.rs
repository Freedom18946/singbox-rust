#[cfg(feature = "dns_udp")]
use sb_core::dns::udp::{build_query, parse_answers};

#[cfg(feature = "dns_udp")]
#[test]
fn parse_answer_ttl_min_and_types() {
    // Test query building for different qtypes
    assert!(build_query("example.com", 1).is_ok()); // A record
    assert!(build_query("example.com", 28).is_ok()); // AAAA record

    // Test with minimal buffer (should error)
    let bad = vec![0u8; 10];
    assert!(parse_answers(&bad, 1).is_err());

    // Test with valid but empty response
    let empty_response = vec![
        0x12, 0x34, // ID
        0x81, 0x80, // Flags (response, no error)
        0x00, 0x01, // QDCOUNT = 1
        0x00, 0x00, // ANCOUNT = 0
        0x00, 0x00, // NSCOUNT = 0
        0x00, 0x00, // ARCOUNT = 0
        // Question section
        0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', // "example"
        0x03, b'c', b'o', b'm', // "com"
        0x00, // null terminator
        0x00, 0x01, // QTYPE = A
        0x00, 0x01, // QCLASS = IN
    ];

    let (ips, ttl) = parse_answers(&empty_response, 1).expect("Should parse empty response");
    assert!(ips.is_empty());
    assert!(ttl.is_none());
}

#[test]
fn dns_cache_qtype_separation() {
    use sb_core::dns::cache_v2::QType;

    // Test that A and AAAA records are different types
    let qtype_a = QType::A;
    let qtype_aaaa = QType::AAAA;

    assert_ne!(qtype_a, qtype_aaaa);

    // Test that cache keys with different qtypes are different
    let key_a = ("example.com".to_string(), QType::A);
    let key_aaaa = ("example.com".to_string(), QType::AAAA);

    assert_ne!(key_a, key_aaaa);
}

#[test]
fn dns_cache_basic_operations() {
    use sb_core::dns::{cache::DnsCache, DnsAnswer};
    use std::{net::IpAddr, time::Duration};

    let cache = DnsCache::new(100);

    // Test basic cache operations
    let ipv4: IpAddr = "1.2.3.4".parse().unwrap();
    let answer = DnsAnswer::new(
        vec![ipv4],
        Duration::from_secs(30),
        sb_core::dns::cache::Source::System,
        sb_core::dns::cache::Rcode::NoError,
    );

    // Put and get from cache
    let key = sb_core::dns::cache::Key {
        name: "test.example".to_string(),
        qtype: sb_core::dns::cache::QType::A,
    };
    cache.put(key.clone(), answer.clone());
    let cached_answer = cache.get(&key);

    assert!(cached_answer.is_some());
    let cached = cached_answer.unwrap();
    assert_eq!(cached.ips, vec![ipv4]);

    // Test negative caching
    let negative_key = sb_core::dns::cache::Key {
        name: "nonexistent.example".to_string(),
        qtype: sb_core::dns::cache::QType::A,
    };
    cache.put_negative(negative_key.clone());
    let negative_result = cache.get(&negative_key);
    assert!(negative_result.is_some());
    let negative = negative_result.unwrap();
    assert!(negative.ips.is_empty());
}
