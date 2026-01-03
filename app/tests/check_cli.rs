// app/tests/check_cli.rs
use std::fs;
use tempfile::NamedTempFile;

#[allow(dead_code)]
fn bin() -> String {
    // Use assert_cmd to find the binary instead of hardcoded path
    "check".to_string()
}

#[test]
fn good_config_ok() {
    let good = r#"
schema_version: 2
inbounds: [ { type: http, listen: "127.0.0.1", port: 18081 } ]
outbounds: [ { type: direct, name: direct } ]
route: { rules: [ { domain: ["example.com"], outbound: "direct" } ] }
"#;
    let temp_file = NamedTempFile::new().unwrap();
    fs::write(temp_file.path(), good).unwrap();

    let mut cmd = assert_cmd::cargo::cargo_bin_cmd!("check");
    cmd.args(["--config", temp_file.path().to_str().unwrap()])
        .assert()
        .success();
}

#[test]
fn bad_config_fails() {
    let bad = r#"
inbounds: [ { type: socks, listen: "127.0.0.1", port: 70000 } ]
outbounds: [ { type: socks, server: "127.0.0.1", port: 1080 } ]
route: { rules: [ { when: { proto: "tcp" }, to: "proxy:up#1" } ] }
dns: { mode: bad }
"#;
    let temp_file = NamedTempFile::new().unwrap();
    fs::write(temp_file.path(), bad).unwrap();
    let mut cmd = assert_cmd::cargo::cargo_bin_cmd!("check");
    cmd.args([
        "--config",
        temp_file.path().to_str().unwrap(),
        "--format",
        "json",
    ])
    .assert()
    .failure();
}

#[test]
#[cfg(feature = "schema-v2")]
fn schema_v2_validate_flag_works() {
    let config = r#"
schema_version: 2
inbounds: [ { type: http, listen: "127.0.0.1", port: 18082 } ]
outbounds: [ { type: direct } ]
route: { rules: [ { domain_suffix: ["example.com"], outbound: "direct" } ] }
dns: { mode: system }
"#;
    let temp_file = NamedTempFile::new().unwrap();
    fs::write(temp_file.path(), config).unwrap();
    let mut cmd = assert_cmd::cargo::cargo_bin_cmd!("check");
    cmd.args([
        "--config",
        temp_file.path().to_str().unwrap(),
        "--schema-v2-validate",
    ])
    .assert()
    .success();
}

#[test]
#[cfg(feature = "schema-v2")]
fn schema_v2_validate_unknown_field_fails() {
    let config = r#"
schema_version: 2
inbounds: [ { type: http, listen: "127.0.0.1", port: 18083 } ]
outbounds: [ { type: direct } ]
route: { rules: [ { domain_suffix: ["example.com"], outbound: "direct" } ] }
dns: { mode: system }
unknown_field: "should_fail"
"#;
    let temp_file = NamedTempFile::new().unwrap();
    fs::write(temp_file.path(), config).unwrap();
    let mut cmd = assert_cmd::cargo::cargo_bin_cmd!("check");
    cmd.args([
        "--config",
        temp_file.path().to_str().unwrap(),
        "--schema-v2-validate",
    ])
    .assert()
    .failure();
}

#[test]
#[cfg(feature = "schema-v2")]
fn deny_unknown_enables_schema_v2_validation() {
    let config = r#"
schema_version: 2
inbounds: [ { type: http, listen: "127.0.0.1", port: 18084 } ]
outbounds: [ { type: direct } ]
route: { rules: [ { domain_suffix: ["example.com"], outbound: "direct" } ] }
dns: { mode: system }
unknown_field: "should_fail"
"#;
    let temp_file = NamedTempFile::new().unwrap();
    fs::write(temp_file.path(), config).unwrap();
    let mut cmd = assert_cmd::cargo::cargo_bin_cmd!("check");
    cmd.args([
        "--config",
        temp_file.path().to_str().unwrap(),
        "--deny-unknown",
    ])
    .assert()
    .failure();
}

#[test]
#[cfg(not(feature = "schema-v2"))]
fn schema_v2_disabled_shows_warning() {
    let config = r#"
inbounds: [ { type: http, listen: "127.0.0.1", port: 18085 } ]
outbounds: [ { type: direct } ]
route: { rules: [ { outbound: "direct" } ] }
dns: { mode: system }
"#;
    let temp_file = NamedTempFile::new().unwrap();
    fs::write(temp_file.path(), config).unwrap();
    let mut cmd = assert_cmd::cargo::cargo_bin_cmd!("check");
    let output = cmd
        .args([
            "--config",
            temp_file.path().to_str().unwrap(),
            "--schema-v2-validate",
            "--format",
            "json",
        ])
        .output()
        .unwrap();

    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("schema-v2 feature disabled at build"));
}

#[test]
#[cfg(feature = "schema-v2")]
fn schema_v2_issue_format_stable_ptr_and_code() {
    use serde_json::Value as Json;
    // 构造一个含未知顶层字段的配置，命中 deny_unknown_fields
    let bad = r#"
schema_version: 2
inbounds: [ { type: http, listen: "127.0.0.1", port: 18086 } ]
outbounds: [ { type: direct } ]
route: { rules: [ { domain_suffix: ["example.com"], outbound: "direct" } ] }
dns: { mode: system }
unknown_field: "should_fail"
"#;
    let temp_file = NamedTempFile::new().unwrap();
    fs::write(temp_file.path(), bad).unwrap();
    let mut cmd = assert_cmd::cargo::cargo_bin_cmd!("check");
    let out = cmd
        .args([
            "--config",
            temp_file.path().to_str().unwrap(),
            "--schema-v2-validate",
            "--format",
            "json",
        ])
        .output()
        .unwrap();
    assert!(!out.status.success());
    let stdout = String::from_utf8(out.stdout).unwrap();
    let v: Json = serde_json::from_str(&stdout).unwrap();
    let issues = v.get("issues").and_then(|x| x.as_array()).unwrap();
    // 需要至少一个 UnknownField，且 ptr 为 RFC6901 形式（以 /unknown_field 结尾）
    let mut ok = false;
    for it in issues {
        let code = it.get("code").and_then(|x| x.as_str()).unwrap_or("");
        let ptr = it.get("ptr").and_then(|x| x.as_str()).unwrap_or("");
        if code == "UnknownField" && ptr.ends_with("/unknown_field") {
            ok = true;
            break;
        }
    }
    assert!(
        ok,
        "expect UnknownField with ptr=/unknown_field; got: {stdout}"
    );
}

#[test]
#[cfg(feature = "schema-v2")]
fn schema_v2_fingerprint_generation() {
    use serde_json::Value as Json;
    // Test that fingerprint is generated correctly for schema v2 errors
    let bad_config = r#"
schema_version: 2
inbounds: [ { type: http, listen: "127.0.0.1", port: 18087 } ]
outbounds: [ { type: direct } ]
route: { rules: [ { domain_suffix: ["example.com"], outbound: "direct" } ] }
dns: { mode: system }
unknown_field_1: "error1"
unknown_field_2: "error2"
"#;
    let temp_file = NamedTempFile::new().unwrap();
    fs::write(temp_file.path(), bad_config).unwrap();
    let mut cmd = assert_cmd::cargo::cargo_bin_cmd!("check");
    let out = cmd
        .args([
            "--config",
            temp_file.path().to_str().unwrap(),
            "--schema-v2-validate",
            "--format",
            "json",
            "--fingerprint",
        ])
        .output()
        .unwrap();
    assert!(!out.status.success());
    let stdout = String::from_utf8(out.stdout).unwrap();
    let v: Json = serde_json::from_str(&stdout).unwrap();

    // Check that fingerprint is present and follows SHA256-8 format (8 hex chars)
    let fingerprint = v.get("fingerprint").and_then(|x| x.as_str()).unwrap();
    assert_eq!(fingerprint.len(), 8); // 8 hex chars for SHA256-8
    assert!(fingerprint.chars().all(|c| c.is_ascii_hexdigit()));

    // Check that issues are present
    let issues = v.get("issues").and_then(|x| x.as_array()).unwrap();
    assert!(!issues.is_empty());

    // Verify that running the same config produces the same fingerprint
    let mut cmd2 = assert_cmd::cargo::cargo_bin_cmd!("check");
    let out2 = cmd2
        .args([
            "--config",
            temp_file.path().to_str().unwrap(),
            "--schema-v2-validate",
            "--format",
            "json",
            "--fingerprint",
        ])
        .output()
        .unwrap();
    let stdout2 = String::from_utf8(out2.stdout).unwrap();
    let v2: Json = serde_json::from_str(&stdout2).unwrap();
    let fingerprint2 = v2.get("fingerprint").and_then(|x| x.as_str()).unwrap();

    assert_eq!(
        fingerprint, fingerprint2,
        "Fingerprints should be deterministic"
    );
}

#[test]
#[cfg(feature = "schema-v2")]
fn schema_v2_error_classification() {
    use serde_json::Value as Json;
    // Test different types of schema errors are classified correctly
    let type_error_config = r#"
schema_version: 2
inbounds: [ { type: http, listen: "127.0.0.1", port: "not_a_number" } ]
outbounds: [ { type: direct } ]
route: { rules: [ { domain_suffix: ["example.com"], outbound: "direct" } ] }
dns: { mode: system }
"#;
    let temp_file = NamedTempFile::new().unwrap();
    fs::write(temp_file.path(), type_error_config).unwrap();
    let mut cmd = assert_cmd::cargo::cargo_bin_cmd!("check");
    let out = cmd
        .args([
            "--config",
            temp_file.path().to_str().unwrap(),
            "--schema-v2-validate",
            "--format",
            "json",
        ])
        .output()
        .unwrap();
    assert!(!out.status.success());
    let stdout = String::from_utf8(out.stdout).unwrap();
    let v: Json = serde_json::from_str(&stdout).unwrap();
    let issues = v.get("issues").and_then(|x| x.as_array()).unwrap();

    // Should have at least one issue with appropriate error classification
    let mut found_type_error = false;
    for issue in issues {
        let code = issue.get("code").and_then(|x| x.as_str()).unwrap_or("");
        let hint = issue.get("hint").and_then(|x| x.as_str());

        if code == "TypeMismatch" || code == "InvalidType" {
            found_type_error = true;
            // Should have a helpful hint
            assert!(hint.is_some(), "Type errors should include hints");
        }
    }

    assert!(found_type_error, "Should detect type mismatch errors");
}

#[test]
#[cfg(feature = "schema-v2")]
fn schema_v2_structured_error_format() {
    use serde_json::Value as Json;
    // Test that the structured error format matches the expected schema
    let bad_config = r#"
schema_version: 2
inbounds: [ { type: http, listen: "127.0.0.1", port: 18088 } ]
outbounds: [ { type: direct } ]
route: { rules: [ { domain_suffix: ["example.com"], outbound: "direct" } ] }
dns: { mode: system }
invalid_field: "test"
"#;
    let temp_file = NamedTempFile::new().unwrap();
    fs::write(temp_file.path(), bad_config).unwrap();
    let mut cmd = assert_cmd::cargo::cargo_bin_cmd!("check");
    let out = cmd
        .args([
            "--config",
            temp_file.path().to_str().unwrap(),
            "--schema-v2-validate",
            "--format",
            "json",
        ])
        .output()
        .unwrap();
    assert!(!out.status.success());
    let stdout = String::from_utf8(out.stdout).unwrap();
    let v: Json = serde_json::from_str(&stdout).unwrap();

    // Verify the report structure matches requirements
    assert!(!v.get("ok").and_then(|x| x.as_bool()).unwrap());
    assert!(v.get("file").and_then(|x| x.as_str()).is_some());

    let issues = v.get("issues").and_then(|x| x.as_array()).unwrap();
    assert!(!issues.is_empty());

    // Check each issue has the required fields
    for issue in issues {
        assert!(issue.get("level").and_then(|x| x.as_str()).is_some());
        assert!(issue.get("code").and_then(|x| x.as_str()).is_some());
        assert!(issue.get("ptr").and_then(|x| x.as_str()).is_some());
        assert!(issue.get("message").and_then(|x| x.as_str()).is_some());
        // hint is optional but should be present for schema errors

        let ptr = issue.get("ptr").and_then(|x| x.as_str()).unwrap();
        // RFC6901 JSON pointer should start with /
        assert!(ptr.starts_with("/"), "JSON pointer should start with /");
    }
}
