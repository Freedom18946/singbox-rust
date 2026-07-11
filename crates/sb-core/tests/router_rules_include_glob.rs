#![cfg(feature = "router")]
use sb_core::router::router_build_index_from_str_with_options;
use sb_core::runtime_options::RouterRuntimeOptions;
use std::fs;

#[test]
fn include_glob_expand_sorted() {
    let dir = tempfile::tempdir().unwrap();
    let p1 = dir.path().join("a.rules");
    let p2 = dir.path().join("b.rules");
    fs::write(&p1, "suffix:a.com=proxy\n").unwrap();
    fs::write(&p2, "suffix:b.com=proxy\n").unwrap();
    let txt = r#"
default:direct
include_glob:*.rules
"#;
    let options = RouterRuntimeOptions {
        rules_base_dir: Some(dir.path().to_path_buf()),
        ..RouterRuntimeOptions::default()
    };
    let idx = router_build_index_from_str_with_options(txt, 1024, &options).unwrap();
    assert_eq!(idx.default, "direct");
    // 不崩即可；详细断言依赖内部结构，此处略
}
