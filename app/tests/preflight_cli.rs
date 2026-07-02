use predicates::prelude::*;
use std::fs;

#[test]
fn preflight_valid_config_reports_contract() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let config = dir.path().join("config.json");
    fs::write(
        &config,
        r#"{
            "inbounds": [],
            "outbounds": [],
            "route": { "rules": [] }
        }"#,
    )?;

    assert_cmd::cargo::cargo_bin_cmd!("preflight")
        .arg("--config")
        .arg(&config)
        .assert()
        .success()
        .stdout(predicate::str::contains(r#""event": "preflight""#));

    Ok(())
}

#[test]
fn preflight_missing_config_fails_instead_of_using_empty_object() {
    assert_cmd::cargo::cargo_bin_cmd!("preflight")
        .arg("--config")
        .arg("missing-preflight-config.json")
        .assert()
        .failure()
        .stderr(predicate::str::contains("failed to read config"));
}

#[test]
fn preflight_invalid_json_fails_instead_of_using_empty_object(
) -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let config = dir.path().join("bad.json");
    fs::write(&config, "{not json")?;

    assert_cmd::cargo::cargo_bin_cmd!("preflight")
        .arg("--config")
        .arg(&config)
        .assert()
        .failure()
        .stderr(predicate::str::contains("failed to parse JSON config"));

    Ok(())
}
