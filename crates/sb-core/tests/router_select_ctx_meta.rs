#![cfg(feature = "router")]

use sb_core::outbound::RouteTarget;
use sb_core::router::{router_build_index_from_str, RouteCtx, RouterHandle};

#[test]
fn select_ctx_and_record_with_meta_labels() {
    let rules = r#"
exact:api.example.com=proxy
suffix:example.com=direct
cidr4:10.0.0.0/8=proxy
default=direct
"#;
    let idx = router_build_index_from_str(rules, 8192).expect("build index");
    let handle = RouterHandle::from_index(idx);

    let (target, rule) = handle.select_ctx_and_record_with_meta(RouteCtx {
        host: Some("api.example.com"),
        ..Default::default()
    });
    assert_eq!(rule.as_deref(), Some("exact"));
    assert!(matches!(target, RouteTarget::Named(ref t) if t == "proxy"));

    let (target, rule) = handle.select_ctx_and_record_with_meta(RouteCtx {
        host: Some("www.example.com"),
        ..Default::default()
    });
    assert_eq!(rule.as_deref(), Some("suffix"));
    assert!(matches!(target, RouteTarget::Named(ref t) if t == "direct"));

    let ip: std::net::IpAddr = "10.1.2.3".parse().unwrap();
    let (target, rule) = handle.select_ctx_and_record_with_meta(RouteCtx {
        ip: Some(ip),
        ..Default::default()
    });
    assert_eq!(rule.as_deref(), Some("ip"));
    assert!(matches!(target, RouteTarget::Named(ref t) if t == "proxy"));

    let (target, rule) = handle.select_ctx_and_record_with_meta(RouteCtx {
        host: Some("no-match.example"),
        ..Default::default()
    });
    assert_eq!(rule.as_deref(), Some("final"));
    assert!(matches!(target, RouteTarget::Named(ref t) if t == "direct"));
}
