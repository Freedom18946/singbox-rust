#![cfg(feature = "router")]
#[cfg(feature = "router_keyword")]
use sb_core::router::{router_build_index_from_str, router_index_decide_keyword};

#[cfg(feature = "router_keyword")]
#[test]
fn keyword_match_basic() {
    let text = r#"
keyword:shop=direct
default:reject
"#;
    let idx = router_build_index_from_str(text, 8192).expect("build index");
    let d = router_index_decide_keyword(&idx, "foo.shop.example.com").expect("keyword");
    assert_eq!(d, "direct");
}
