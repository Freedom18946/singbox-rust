#![cfg(feature = "router")]
use sb_core::router::rules::*;
use std::net::{IpAddr, Ipv4Addr};

fn ctx(dom: Option<&str>, ip: Option<IpAddr>, udp: bool, port: Option<u16>) -> RouteCtx<'_> {
    RouteCtx {
        domain: dom,
        ip,
        transport_udp: udp,
        port,
        ..Default::default()
    }
}

#[test]
fn priority_and_short_circuit() {
    let rules_txt = r#"
        exact:download.example.com = direct
        suffix:.example.com = proxy
        keyword:tracker = reject
        ip_cidr:10.0.0.0/8 = direct
        transport:udp,port:53 = direct
        portset:80,443,8443 = proxy
        default = direct
    "#;
    let rs = parse_rules(rules_txt);
    let eng = Engine::build(rs);

    // exact 胜出（覆盖 suffix）
    let d = eng.decide(&ctx(Some("download.example.com"), None, false, Some(443)));
    assert!(matches!(d, Decision::Direct));

    // suffix 命中（非 exact）
    let d = eng.decide(&ctx(Some("www.example.com"), None, false, Some(80)));
    assert!(matches!(d, Decision::Proxy(_)));

    // keyword 拦截
    let d = eng.decide(&ctx(Some("cdn.tracker.net"), None, false, Some(443)));
    assert!(matches!(d, Decision::Reject));

    // ip_cidr 命中
    let d = eng.decide(&ctx(
        None,
        Some(IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3))),
        false,
        Some(22),
    ));
    assert!(matches!(d, Decision::Direct));

    // transport+port（UDP:53）
    let d = eng.decide(&ctx(Some("dns.google"), None, true, Some(53)));
    assert!(matches!(d, Decision::Direct));

    // portset 覆盖（80→proxy）
    let d = eng.decide(&ctx(Some("other.site"), None, false, Some(80)));
    assert!(matches!(d, Decision::Proxy(_)));

    // default
    let d = eng.decide(&ctx(Some("unknown.tld"), None, false, Some(12345)));
    assert!(matches!(d, Decision::Direct));
}
