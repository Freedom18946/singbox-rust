#![cfg(feature = "router")]
use sb_core::router::analyze::analyze;

#[test]
fn analyze_basic() {
    let txt = r#"
exact:a.example.com=proxy
suffix:example.com=direct
portrange:80-90=proxy
portrange:91-100=proxy
default:direct
"#;
    let r = analyze(txt);
    assert!(r.total_rules >= 5);
    assert!(r.shadows.iter().any(|s| s.kind == "suffix_over_exact"));
    assert!(r.suggestions.iter().any(|s| s.contains("merge portrange")));
}
