#![cfg(feature = "dev-cli")]
use sb_core::net::Address;
use sb_core::router::RequestMeta;
use serial_test::serial;
use singbox_rust::config_loader; // <-- 从库导入模块
use std::env;

#[tokio::test]
#[serial] // 避免环境变量串扰
async fn env_block_suffixes_blocks_example_com() {
    // 准备：ENV 直接提供 config JSON 与阻断后缀
    let cfg = r#"
    {
      "inbounds":[ {"type":"http","listen":"127.0.0.1","listen_port":28090} ],
      "route": { "final": "direct", "rules": [] }
    }"#;
    env::set_var("SBR_CONFIG_JSON", cfg);
    env::set_var("SBR_BLOCK_SUFFIXES", "example.com,.ads");

    let loaded = config_loader::load_from_env_or_default().expect("load");

    // 选择目标 www.example.com，应当命中 BlockOutbound → 立刻 Err("blocked")
    let meta = RequestMeta {
        dst: Address::Domain("www.example.com".to_string(), 80),
        ..Default::default()
    };
    let outbound = loaded.router.select(&meta);
    let err = outbound
        .connect(meta.dst.clone())
        .await
        .expect_err("should be blocked");
    let msg = err.to_string();
    assert!(msg.contains("blocked"), "expect blocked error, got: {msg}");
}

#[tokio::test]
#[serial]
async fn env_no_match_falls_back_to_direct() {
    // 清除阻断后缀，或设置一个不会命中的后缀
    env::set_var(
        "SBR_CONFIG_JSON",
        r#"{"inbounds":[],"route":{"final":"direct","rules":[]}}"#,
    );
    env::set_var("SBR_BLOCK_SUFFIXES", "not-this-suffix");
    let loaded = config_loader::load_from_env_or_default().expect("load");

    // 非阻断域名 → 走 direct；连接失败也不应是 "blocked"
    let meta = RequestMeta {
        dst: Address::Domain("nonexistent.invalid".to_string(), 80),
        ..Default::default()
    };
    let outbound = loaded.router.select(&meta);
    let res = outbound.connect(meta.dst.clone()).await;
    if let Err(e) = res {
        assert!(!e.to_string().contains("blocked"), "should not be blocked");
    }
}
