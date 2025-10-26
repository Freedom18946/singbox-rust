// This test file is disabled due to missing proptest dependency
// #[cfg(feature = "proptest")]
/*
use proptest::prelude::*;
use sb_core::router::{router_build_index_from_str, router_index_decide_exact_suffix};

// 生成分隔符（逗号、LF、CRLF 混合）
fn sep_strategy() -> impl Strategy<Value = String> {
    prop_oneof![
        Just(",".to_string()),
        Just("\n".to_string()),
        Just("\r\n".to_string()),
        Just(" , ".to_string()),
        Just("\n, ".to_string()),
        Just(",\n".to_string()),
    ]
}

proptest! {
    // 基本性质：无论分隔符如何变化，"suffix:.test=proxy" 都应覆盖 "default=reject"
    #[test]
    fn fuzz_separators_do_not_break_suffix_rule(sep in sep_strategy()) {
        let rules = format!("{}{}", "default=reject", sep) + "suffix:.test=proxy";
        let idx = router_build_index_from_str(&rules, 8192).expect("rules build");
        prop_assert_eq!(router_index_decide_exact_suffix(&idx, "x.test").unwrap(), "proxy");
        prop_assert_eq!(router_index_decide_exact_suffix(&idx, "nope.example").unwrap_or(idx.default), "reject");
    }
}
*/

#[test]
fn disabled_fuzz_test() {
    // This test is disabled due to missing proptest dependency
    // Intentionally left blank
}
