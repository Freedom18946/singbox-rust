#![cfg(feature = "router")]
use sb_core::router::{decide_http_explain, RouterHandle};

#[tokio::test]
async fn explain_reports_reason_paths() {
    let rules = r#"
    exact:api.example.com=proxy
    suffix:.example.com=direct
    port:443=reject
    transport:udp=proxy
    default=direct
    "#;
    std::env::set_var("SB_ROUTER_RULES", rules);
    // HTTP exact
    let e1 = decide_http_explain("api.example.com");
    assert_eq!(e1.decision, "proxy");
    assert!(e1.reason_kind == "exact" || e1.reason_kind == "suffix");
    // HTTP port fallback
    let e2 = decide_http_explain("no.match:443");
    assert_eq!(e2.decision, "reject");
    assert!(e2.reason_kind == "port" || e2.reason.contains("transport/port"));
    // UDP transport fallback
    let h = RouterHandle::from_env();
    let e3 = sb_core::router::decide_udp_async_explain(&h, "no.match").await;
    assert_eq!(e3.decision, "proxy");
    assert_eq!(e3.reason_kind, "transport");
}
