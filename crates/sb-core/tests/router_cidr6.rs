#![cfg(feature = "router")]
use sb_core::router::decide_udp_with_rules_and_ips_v46;

#[test]
fn cidr6_basic_match_and_miss() {
    let rules = "cidr6:2001:db8::/32=proxy,default=direct";
    let hit = "2001:db8::1".parse().unwrap();
    let miss = "2001:dead:beef::1".parse().unwrap();
    assert_eq!(
        decide_udp_with_rules_and_ips_v46("host", rules, &[], &[hit]),
        "proxy"
    );
    assert_eq!(
        decide_udp_with_rules_and_ips_v46("host", rules, &[], &[miss]),
        "direct"
    );
}

#[test]
fn cidr6_priority_vs_exact_suffix() {
    let rules = "exact:foo.test=reject,suffix:.test=proxy,cidr6:2001:db8::/32=proxy,default=direct";
    let v6 = "2001:db8::2".parse().unwrap();
    // exact wins
    assert_eq!(
        decide_udp_with_rules_and_ips_v46("foo.test", rules, &[], &[v6]),
        "reject"
    );
    // suffix wins if no exact
    assert_eq!(
        decide_udp_with_rules_and_ips_v46("bar.test", rules, &[], &[v6]),
        "proxy"
    );
}
