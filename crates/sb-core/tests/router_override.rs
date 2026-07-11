#![cfg(feature = "router")]
use sb_core::router::RouterHandle;
use sb_core::runtime_options::RouterRuntimeOptions;
use std::sync::Arc;

#[tokio::test]
async fn override_exact_suffix_and_defaults() {
    // 覆盖：exact & suffix & tcp 默认
    let options = RouterRuntimeOptions {
        rules_inline: "default=unresolved".into(),
        runtime_override: Some(
            "exact:api.example.com=proxy; suffix:.example.com=reject; transport:tcp=proxy; transport:udp=proxy; default=reject".into(),
        ),
        ..RouterRuntimeOptions::default()
    };
    let h = RouterHandle::from_options(Arc::new(options));
    // exact 胜出
    assert_eq!(h.decide_tcp_async("api.example.com").await, "proxy");
    // 非 exact 但命中 suffix
    assert_eq!(h.decide_tcp_async("x.example.com").await, "reject");
    // 非 host 命中，走 transport 覆盖
    assert_eq!(h.decide_tcp_async("no.match").await, "proxy");
    // UDP 路径：覆盖 transport:udp 与默认（使用同一个覆盖设置）
    let d = h.decide_udp_async("no.match").await;
    assert_eq!(d, "proxy");
}
