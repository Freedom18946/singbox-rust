#![cfg(feature = "router")]
use sb_core::router::router_build_index_from_str;

#[test]
fn var_default_fallback() {
    let txt = r#"
suffix:${DOMAIN:-example.com}=proxy
default:direct
"#;
    let idx = router_build_index_from_str(txt, 1024).unwrap();
    assert_eq!(idx.default, "direct");
}
