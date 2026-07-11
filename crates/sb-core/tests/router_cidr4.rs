use sb_core::net::datagram::UdpTargetAddr;
use sb_core::router;
use sb_core::runtime_options::RouterRuntimeOptions;
use std::sync::Arc;

fn handle(rules: Option<&str>) -> router::RouterHandle {
    router::RouterHandle::from_options(Arc::new(RouterRuntimeOptions {
        udp_enabled: rules.is_some(),
        udp_rules: rules.map(str::to_string),
        ..RouterRuntimeOptions::default()
    }))
}

#[test]
fn cidr4_basic_match_and_miss() {
    let h = handle(None);
    // 无 UDP 规则时显式 options 默认 unresolved。
    let d = UdpTargetAddr::Ip("10.1.2.3:53".parse().unwrap());
    assert_eq!(h.decide_udp(&d), "unresolved");

    let h = handle(Some("cidr4:10.0.0.0/8=reject,default=unresolved"));
    assert_eq!(h.decide_udp(&d), "reject");

    let e = UdpTargetAddr::Ip("11.0.0.1:53".parse().unwrap());
    assert_eq!(h.decide_udp(&e), "unresolved");
}

#[test]
fn cidr4_illegal_ignored() {
    let h = handle(Some("cidr4:bad/xx=reject,default=unresolved"));
    let x = UdpTargetAddr::Ip("10.0.0.1:1".parse().unwrap());
    assert_eq!(h.decide_udp(&x), "unresolved");
}

#[test]
fn cidr4_ip_uses_cidr_rule() {
    let h = handle(Some(
        "exact:10.1.2.3=proxy,cidr4:10.0.0.0/8=reject,default=unresolved",
    ));
    let ip = UdpTargetAddr::Ip("10.1.2.3:9999".parse().unwrap());
    assert_eq!(h.decide_udp(&ip), "reject");
}
