#![cfg(feature = "router")]
use sb_core::router::decide_udp_with_rules;

#[test]
fn priority_exact_over_suffix() {
    let rules = "suffix:.example.com=reject,exact:api.example.com=proxy,default=direct";
    assert_eq!(
        decide_udp_with_rules("api.example.com", true, rules),
        "proxy"
    );
    assert_eq!(
        decide_udp_with_rules("www.example.com", true, rules),
        "reject"
    );
}

#[test]
fn priority_suffix_over_default() {
    let rules = "suffix:.svc=proxy,default=reject";
    assert_eq!(decide_udp_with_rules("foo.svc", true, rules), "proxy");
    assert_eq!(decide_udp_with_rules("foo.other", true, rules), "reject");
}

#[test]
fn priority_cidr4_over_default() {
    let rules = "cidr4:10.0.0.0/8=reject,default=proxy";
    assert_eq!(decide_udp_with_rules("10.1.2.3", true, rules), "reject");
    assert_eq!(decide_udp_with_rules("1.2.3.4", true, rules), "proxy");
}

#[test]
fn priority_exact_vs_cidr4() {
    let rules = "cidr4:10.0.0.0/8=reject,exact:10.1.2.3=proxy,default=direct";
    // exact should override cidr4
    assert_eq!(decide_udp_with_rules("10.1.2.3", true, rules), "proxy");
}

#[test]
fn priority_suffix_vs_cidr4_overlap() {
    // suffix should apply to domain names; cidr4 applies to ip; they don't conflict directly
    let rules = "suffix:.svc=proxy,cidr4:192.168.0.0/16=reject,default=direct";
    assert_eq!(decide_udp_with_rules("db.svc", true, rules), "proxy");
    assert_eq!(decide_udp_with_rules("192.168.1.2", true, rules), "reject");
}

#[test]
fn priority_suffix_over_default_when_exact_misses() {
    let rules = "exact:api.example.com=proxy,suffix:.example.com=reject,default=direct";
    assert_eq!(
        decide_udp_with_rules("img.example.com", true, rules),
        "reject"
    );
}
