use anyhow::Result;

#[test]
fn sb_rule_coverage_emits_plain_json_snapshot() -> Result<()> {
    let output = assert_cmd::cargo::cargo_bin_cmd!("sb-rule-coverage")
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let value: serde_json::Value = serde_json::from_slice(&output)?;

    assert!(value.is_array(), "coverage snapshot must be a JSON array");
    assert!(value.get("ok").is_none(), "snapshot must not be enveloped");
    Ok(())
}
