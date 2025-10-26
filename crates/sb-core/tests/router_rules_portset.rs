use sb_core::router::decide_http;

#[test]
fn http_portset_first_wins_and_valid() {
    // 清理之前的环境变量
    std::env::remove_var("SB_ROUTER_OVERRIDE");
    let rules = r#"
    portset:80,443,8443=proxy
    port:443=reject   # 已被 portset 初始化时占位，first-wins -> 不生效
    default=direct
    "#;
    std::env::set_var("SB_ROUTER_RULES", rules);
    // 80、443、8443 都应命中 proxy
    for p in [80u16, 443u16, 8443u16] {
        let t = format!("no.match:{}", p);
        let decision = decide_http(&t);
        assert_eq!(decision.target, "proxy");
    }
    // 81 不在集合 -> default
    let decision = decide_http("no.match:81");
    assert_eq!(decision.target, "direct");
}
