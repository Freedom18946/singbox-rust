use serde_json::Value;

#[test]
fn go1124_view_matches_golden() {
    let input = include_str!("data/demo.json");
    let ir: sb_config::ir::ConfigIr = serde_json::from_str(input).expect("parse IR");

    let view = sb_config::present::to_view(&ir, sb_config::present::FormatProfile::Go1124);

    let got: Value = view;
    let want: Value = serde_json::from_str(include_str!("data/go_1124_demo_golden.json")).unwrap();

    assert_eq!(got, want, "Presenter Go1124 view drifted from golden");
}
