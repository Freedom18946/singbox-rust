#![cfg(feature = "router")]
use sb_core::router::analyze::analyze;
#[cfg(feature = "rules_tool")]
use sb_core::router::analyze_fix::build_suffix_shadow_cleanup_patch;
#[cfg(feature = "rules_tool")]
use sb_core::router::patch_apply::apply_cli_patch;

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

#[test]
fn suffix_shadow_cleanup_patch_applies_placeholder_delete() {
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
        let out = apply_cli_patch(txt, &p.patch_text).expect("apply");
        assert!(!out.contains("exact:a.example.com=proxy"));
        assert!(out.contains("suffix:example.com=direct"));
        assert!(out.contains("default:direct"));
    }
}
