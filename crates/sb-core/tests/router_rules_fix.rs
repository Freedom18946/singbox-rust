use sb_core::router::analyze::analyze;
#[cfg(feature = "rules_tool")]
use sb_core::router::analyze_fix::build_portrange_merge_patch;

#[test]
fn build_merge_patch_basic() {
    let txt = r#"
portrange:80-90=proxy
portrange:91-100=proxy
default:direct
"#;
    #[cfg_attr(not(feature = "rules_tool"), allow(unused_variables))]
    let r = analyze(txt);
    #[cfg(feature = "rules_tool")]
    {
        let p = build_portrange_merge_patch(&r, txt, Some("rules.conf")).expect("patch");
        assert!(p.patch_text.contains("+portrange:80-100=proxy"));
        assert!(p.patch_text.contains("*** rules.conf"));
    }
}
