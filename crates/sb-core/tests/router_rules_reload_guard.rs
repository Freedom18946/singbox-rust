#![cfg(feature = "router")]
use sb_core::router::{router_build_index_from_str_with_options, BuildError, InvalidReason};
use sb_core::runtime_options::RouterRuntimeOptions;

#[test]
fn require_default_guard() {
    let txt = "suffix:example.com=proxy";
    let options = RouterRuntimeOptions {
        rules_require_default: true,
        ..RouterRuntimeOptions::default()
    };
    let e = router_build_index_from_str_with_options(txt, 1024, &options).unwrap_err();
    match e {
        BuildError::Invalid(InvalidReason::MissingDefault) => {}
        _ => panic!("Expected MissingDefault error when default rule is required"),
    }
}
