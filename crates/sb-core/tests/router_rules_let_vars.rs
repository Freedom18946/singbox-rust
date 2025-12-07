#![cfg(feature = "router")]
use sb_core::router::{router_build_index_from_str, BuildError, InvalidReason};

#[test]
fn let_and_expand_ok() {
    let txt = r#"
let:DOMAIN=example.com
suffix:$DOMAIN=proxy
default:direct
"#;
    let idx = router_build_index_from_str(txt, 1024).unwrap();
    assert_eq!(idx.default, "direct");
}

#[test]
fn bad_var_name_rejected() {
    let txt = r#"
let:bad-name=value
default:direct
"#;
    let e = router_build_index_from_str(txt, 1024).unwrap_err();
    match e {
        BuildError::Invalid(InvalidReason::BadVarName) => {}
        _ => panic!("Expected BadVarName error for invalid variable name"),
    }
}
