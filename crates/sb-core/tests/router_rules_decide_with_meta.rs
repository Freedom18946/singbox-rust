use sb_core::router::rules::{parse_rules, Decision, Engine, RouteCtx};

#[test]
fn decide_with_meta_labels_buckets() {
    let rules = parse_rules(
        r#"
exact:example.com=direct
suffix:example.org=proxy
keyword:test=proxy
default=unresolved
"#,
    );
    let eng = Engine::build(rules);

    let (d, rule) = eng.decide_with_meta(&RouteCtx {
        domain: Some("example.com"),
        ..Default::default()
    });
    assert_eq!(rule.as_deref(), Some("exact"));
    assert!(matches!(d, Decision::Direct));

    let (d, rule) = eng.decide_with_meta(&RouteCtx {
        domain: Some("www.example.org"),
        ..Default::default()
    });
    assert_eq!(rule.as_deref(), Some("suffix"));
    assert!(matches!(d, Decision::Proxy(_)));

    let (d, rule) = eng.decide_with_meta(&RouteCtx {
        domain: Some("mytestdomain.com"),
        ..Default::default()
    });
    assert_eq!(rule.as_deref(), Some("keyword"));
    assert!(matches!(d, Decision::Proxy(_)));

    let (d, rule) = eng.decide_with_meta(&RouteCtx {
        domain: Some("no-match.example"),
        ..Default::default()
    });
    assert_eq!(rule.as_deref(), Some("final"));
    assert!(matches!(d, Decision::Proxy(Some(ref tag)) if tag == "unresolved"));
}
