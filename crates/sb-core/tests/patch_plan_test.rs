#![cfg(feature = "rules_tool")]

use sb_core::router::patch_plan::{apply_plan, build_plan};

#[test]
fn plan_and_apply() {
    let txt = "port:80=proxy\nport:81=proxy\nexact:a.example.com=proxy\nsuffix:example.com=direct\ndefault:direct\n";
    let plan = build_plan(
        txt,
        &["port_aggregate", "suffix_shadow_cleanup"],
        Some("rules.conf"),
    );
    assert!(plan.summary.adds > 0 || plan.summary.dels > 0);
    let out = apply_plan(txt, &["port_aggregate", "suffix_shadow_cleanup"]);
    assert!(out.contains("default:direct"));
    assert!(!out.contains("exact:a.example.com=proxy"));
}
