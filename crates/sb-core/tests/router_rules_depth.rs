use sb_core::router::{router_build_index_from_str_with_options, BuildError, InvalidReason};
use sb_core::runtime_options::RouterRuntimeOptions;

#[test]
fn include_glob_depth_guard() {
    let d = tempfile::tempdir().unwrap();
    let p = d.path();
    // a.rules include_glob:*.rules —— 自身 + b.rules
    std::fs::write(p.join("a.rules"), "include_glob:*.rules\n").unwrap();
    std::fs::write(p.join("b.rules"), "default:direct\n").unwrap();
    let txt = "include_glob:a.rules";
    let options = RouterRuntimeOptions {
        rules_base_dir: Some(p.to_path_buf()),
        rules_max_depth: 0,
        ..RouterRuntimeOptions::default()
    };
    let e = router_build_index_from_str_with_options(txt, 1024, &options).unwrap_err();
    match e {
        BuildError::Invalid(InvalidReason::IncludeDepthExceeded) => {}
        _ => panic!("Expected IncludeDepthExceeded error for nested includes"),
    }
}
