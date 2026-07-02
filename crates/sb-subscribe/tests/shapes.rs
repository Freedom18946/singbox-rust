#[test]
fn profile_shape_helpers_are_stable() {
    let mut profile = sb_subscribe::model::Profile::default();
    profile.rules.push(sb_subscribe::model::RuleEntry {
        line: "default=direct".to_string(),
    });
    profile.outbounds.push(sb_subscribe::model::Outbound {
        name: "direct".to_string(),
        kind: "direct".to_string(),
        ..Default::default()
    });

    assert_eq!(profile.rules_len(), 1);
    assert_eq!(profile.outbounds_kinds(), vec!["direct:direct".to_string()]);
}
