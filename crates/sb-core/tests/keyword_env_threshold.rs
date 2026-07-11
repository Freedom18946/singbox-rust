#[cfg(feature = "router_keyword_ac")]
#[test]
fn ac_threshold_is_construction_time_constant() {
    assert!(!sb_core::router::keyword::should_enable_ac(10));
    assert!(sb_core::router::keyword::should_enable_ac(128));
}
