#![cfg(feature = "router")]
use sb_core::router::RouterHandle;
use sb_core::runtime_options::RouterRuntimeOptions;
use std::sync::Arc;

#[tokio::test]
async fn explain_reports_reason_paths() {
    let rules = "exact:api.example.com=proxy\nsuffix:.example.com=direct\nport:443=reject\ntransport:udp=proxy\ndefault=unresolved";
    let options = Arc::new(RouterRuntimeOptions {
        rules_inline: rules.into(),
        ..RouterRuntimeOptions::default()
    });
    let idx = sb_core::router::router_build_index_from_str_with_options(
        rules,
        options.rules_max,
        &options,
    )
    .expect("build index");
    let h = RouterHandle::from_index_with_options(idx.clone(), options);
    // HTTP exact
    let e1 = idx.decide_http_explain("api.example.com");
    assert_eq!(e1.decision, "proxy");
    assert!(e1.reason_kind == "exact" || e1.reason_kind == "suffix");
    // HTTP port fallback
    let e2 = h.decide_http("no.match:443");
    assert_eq!(e2, "reject");
    // UDP transport fallback
    let e3 = sb_core::router::decide_udp_async_explain(&h, "no.match").await;
    assert_eq!(e3.decision, "proxy");
    assert_eq!(e3.reason_kind, "transport");
}
