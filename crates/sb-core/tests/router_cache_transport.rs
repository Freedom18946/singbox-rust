#![cfg(feature = "router")]
use sb_core::router::{decide_http, RouterHandle};

#[tokio::test]
async fn udp_cache_key_does_not_pollute_http_path() {
    std::env::set_var("SB_ROUTER_DECISION_CACHE", "1");
    std::env::set_var("SB_ROUTER_DECISION_CACHE_CAP", "16");
    let rules = r#"
    transport:tcp=reject
    transport:udp=proxy
    default=direct
    "#;
    std::env::set_var("SB_ROUTER_RULES", rules);
    let h = RouterHandle::from_env();
    // 首先 UDP 决策，缓存 key=udp|host
    let u = h.decide_udp_async("no.match").await;
    assert_eq!(u, "proxy");
    // HTTP 决策不使用该缓存（且是 tcp 兜底）
    let decision = decide_http("no.match");
    let http_dec = &decision.target;
    assert_eq!(http_dec, "reject");
}
