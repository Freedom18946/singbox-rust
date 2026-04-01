#[test]
fn wp30ap_pin_e2e_subs_security_suite_requires_admin_debug_feature() {
    let source = include_str!("e2e_subs_security.rs");
    assert!(source.contains("#![cfg(feature = \"admin_debug\")]"));
}

#[test]
fn wp30ap_pin_outbound_groups_remains_test_only_legacy_runtime_seam() {
    let lib = include_str!("../src/lib.rs");
    assert!(lib.contains("#[cfg(all(feature = \"router\", test))]\nmod outbound_groups;"));
}
