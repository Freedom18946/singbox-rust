use sb_core::router::{router_build_index_from_str, BuildError, InvalidReason};

#[test]
fn include_glob_depth_guard() {
    let d = tempfile::tempdir().unwrap();
    let p = d.path();
    // a.rules include_glob:*.rules —— 自身 + b.rules
    std::fs::write(p.join("a.rules"), "include_glob:*.rules\n").unwrap();
    std::fs::write(p.join("b.rules"), "default:direct\n").unwrap();
    std::env::set_var("SB_ROUTER_RULES_BASEDIR", p);
    std::env::set_var("SB_ROUTER_RULES_MAX_DEPTH", "0"); // 立即超限
    let txt = "include_glob:a.rules";
    let e = router_build_index_from_str(txt, 1024).unwrap_err();
    match e {
        BuildError::Invalid(InvalidReason::IncludeDepthExceeded) => {}
        _ => panic!("Expected IncludeDepthExceeded error for nested includes"),
    }
    std::env::remove_var("SB_ROUTER_RULES_MAX_DEPTH");
}
