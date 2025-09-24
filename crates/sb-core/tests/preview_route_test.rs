#[cfg(feature = "preview_route")]
#[test]
fn preview_http_basic() {
    let dsl = "\
exact:example.com=direct
suffix:shop.com=proxyA
default:reject
";
    let idx = sb_core::router::preview::build_index_from_rules(dsl).expect("build");
    let ex = sb_core::router::preview::preview_decide_http(&idx, "www.shop.com");
    assert!(ex.reason.to_lowercase().contains("suffix") || ex.reason_kind == "suffix");
    assert!(
        ex.decision.to_lowercase().contains("proxya")
            || ex.decision.to_lowercase().contains("proxy")
    );
}
