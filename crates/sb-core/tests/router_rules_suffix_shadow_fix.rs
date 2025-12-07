#![cfg(feature = "router")]
use sb_core::router::analyze::analyze;
#[cfg(feature = "rules_tool")]
use sb_core::router::analyze_fix::build_suffix_shadow_cleanup_patch;

#[test]
fn build_suffix_shadow_cleanup_patch_basic() {
    let txt = r#"
exact:a.example.com=proxy
suffix:example.com=direct
default:direct
"#;
    #[cfg_attr(not(feature = "rules_tool"), allow(unused_variables))]
    let r = analyze(txt);
    #[cfg(feature = "rules_tool")]
    {
        let p = build_suffix_shadow_cleanup_patch(&r, None).expect("patch");
        assert!(p.patch_text.contains("-exact:a.example.com="));
        assert!(p.patch_text.contains("*** rules.txt"));
    }
}
