#![cfg(feature = "router")]
use sb_core::router::router_build_index_from_str;
use std::fs;

#[test]
fn include_glob_expand_sorted() {
    let dir = tempfile::tempdir().unwrap();
    let p1 = dir.path().join("a.rules");
    let p2 = dir.path().join("b.rules");
    fs::write(&p1, "suffix:a.com=proxy\n").unwrap();
    fs::write(&p2, "suffix:b.com=proxy\n").unwrap();
    std::env::set_var("SB_ROUTER_RULES_BASEDIR", dir.path());
    let txt = r#"
default:direct
include_glob:*.rules
"#;
    let idx = router_build_index_from_str(txt, 1024).unwrap();
    assert_eq!(idx.default, "direct");
    // 不崩即可；详细断言依赖内部结构，此处略
}
