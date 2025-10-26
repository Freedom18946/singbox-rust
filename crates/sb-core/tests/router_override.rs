use sb_core::router::{decide_http, RouterHandle};

#[tokio::test]
async fn override_exact_suffix_and_defaults() {
    // 覆盖：exact & suffix & tcp 默认
    std::env::set_var("SB_ROUTER_RULES", "default=direct");
    std::env::set_var("SB_ROUTER_OVERRIDE",
        "exact:api.example.com=proxy; suffix:.example.com=reject; transport:tcp=proxy; transport:udp=proxy; default=reject");
    // exact 胜出
    let decision = decide_http("api.example.com");
    assert_eq!(decision.target, "proxy");
    // 非 exact 但命中 suffix
    let decision = decide_http("x.example.com");
    assert_eq!(decision.target, "reject");
    // 非 host 命中，走 transport 覆盖
    let decision = decide_http("no.match");
    assert_eq!(decision.target, "proxy");
    // UDP 路径：覆盖 transport:udp 与默认（使用同一个覆盖设置）
    let h = RouterHandle::from_env();
    let d = h.decide_udp_async("no.match").await;
    assert_eq!(d, "proxy");
}
