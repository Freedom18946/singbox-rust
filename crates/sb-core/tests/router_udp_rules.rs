#![cfg(feature = "router")]
use sb_core::net::datagram::UdpTargetAddr;
use sb_core::router;
use sb_core::runtime_options::RouterRuntimeOptions;
use std::sync::Arc;

#[test]
fn router_udp_rules_default_unresolved() {
    let h = router::RouterHandle::from_options(Arc::new(RouterRuntimeOptions::default()));
    let d = UdpTargetAddr::Domain {
        host: "foo.bar".into(),
        port: 53,
    };
    assert_eq!(h.decide_udp(&d), "unresolved");
}

#[test]
fn router_udp_rules_options_parsing() {
    let h = router::RouterHandle::from_options(Arc::new(RouterRuntimeOptions {
        udp_enabled: true,
        udp_rules: Some("exact:foo.bar=proxy,suffix:.example.com=reject,default=unresolved".into()),
        ..RouterRuntimeOptions::default()
    }));
    let x = UdpTargetAddr::Domain {
        host: "foo.bar".into(),
        port: 53,
    };
    assert_eq!(h.decide_udp(&x), "proxy");
    let y = UdpTargetAddr::Domain {
        host: "api.example.com".into(),
        port: 53,
    };
    assert_eq!(h.decide_udp(&y), "reject");
    let z = UdpTargetAddr::Domain {
        host: "unknown.tld".into(),
        port: 53,
    };
    assert_eq!(h.decide_udp(&z), "unresolved");
}
