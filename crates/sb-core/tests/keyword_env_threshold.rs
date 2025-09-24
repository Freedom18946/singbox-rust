#[cfg(all(feature = "router_keyword", feature = "router_keyword_ac"))]
#[test]
fn ac_threshold_env() {
    // 默认 64，n=10 不启用 AC，n=128 启用
    std::env::remove_var("SB_ROUTER_KEYWORD_AC_MIN");
    assert_eq!(sb_core::router::keyword::should_enable_ac(10), false);
    assert_eq!(sb_core::router::keyword::should_enable_ac(128), true);

    std::env::set_var("SB_ROUTER_KEYWORD_AC_MIN", "8");
    assert_eq!(sb_core::router::keyword::should_enable_ac(10), true);

    std::env::set_var("SB_ROUTER_KEYWORD_AC_MIN", "not-a-number");
    assert_eq!(sb_core::router::keyword::should_enable_ac(10), false);
}
