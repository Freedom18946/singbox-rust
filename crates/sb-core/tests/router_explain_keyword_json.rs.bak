#[cfg(feature = "router_keyword")]
#[test]
fn explain_contains_keyword_kind() {
    // Build a minimal index and install it into the shared snapshot
    let rules = r#"
keyword:shop=direct
default:reject
"#;
    let idx = sb_core::router::router_build_index_from_str(rules, 1024).expect("build index");
    {
        let shared = sb_core::router::shared_index();
        *shared.write().expect("poisoned") = idx;
    }
    let e = sb_core::router::decide_http_explain("www.shop.example.com");
    assert_eq!(e.reason_kind, "keyword");
    assert_eq!(e.decision, "direct");
}
