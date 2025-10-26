use serde_json::json;

#[test]
fn missing_schema_version_warns() -> anyhow::Result<()> {
    let v = json!({"inbounds":[],"outbounds":[],"route":{"rules":[],"default":"direct"}});
    let issues = sb_config::validator::v2::validate_v2(&v, false);
    assert!(issues.iter().any(|i| i["ptr"] == "/schema_version"));
    Ok(())
}

#[test]
fn wrong_schema_version_errors() -> anyhow::Result<()> {
    let v = json!({"schema_version":1,"inbounds":[],"outbounds":[],"route":{"rules":[],"default":"direct"}});
    let issues = sb_config::validator::v2::validate_v2(&v, false);
    assert!(issues
        .iter()
        .any(|i| i["ptr"] == "/schema_version" && i["kind"] == "error"));
    Ok(())
}
