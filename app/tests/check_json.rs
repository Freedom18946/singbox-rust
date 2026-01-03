use serde_json::Value;
use std::fs;

fn write_file(contents: &str) -> tempfile::NamedTempFile {
    let f = tempfile::NamedTempFile::new().unwrap();
    fs::write(f.path(), contents.as_bytes()).unwrap();
    f
}

#[test]
fn check_ok_warn_bad_with_exit_codes() {
    // ok.json: minimal valid config
    let ok = r#"{
        "schema_version": 2,
        "inbounds": [ { "type": "http", "listen": "127.0.0.1", "port": 18081 } ],
        "outbounds": [ { "type": "direct", "name": "direct" } ],
        "route": { "rules": [], "default": "direct" }
    }"#;
    // warn.json: include an unknown field that should be warning when allowed via prefix
    // We enable schema-v2 validation and allow unknown at root to downgrade to warning
    let warn = r#"{
        "schema_version": 2,
        "unknown_field": 1,
        "inbounds": [ { "type": "http", "listen": "127.0.0.1", "port": 18082 } ],
        "outbounds": [ { "type": "direct", "name": "direct" } ],
        "route": { "rules": [], "default": "direct" }
    }"#;
    // bad.json: missing required field to trigger error
    let bad = r#"{
        "schema_version": 2,
        "inbounds": [ { "listen": "127.0.0.1", "port": 18083 } ],
        "outbounds": [ { "type": "direct", "name": "direct" } ],
        "route": { "rules": [], "default": "direct" }
    }"#;

    let okf = write_file(ok);
    let warnf = write_file(warn);
    let badf = write_file(bad);

    // ok
    let ok_out = assert_cmd::cargo::cargo_bin_cmd!("app")
        .args([
            "check",
            "-c",
            okf.path().to_str().unwrap(),
            "--schema-v2-validate",
            "--format",
            "json",
        ])
        .output()
        .unwrap();
    assert!(ok_out.status.success());
    let v_ok: Value = serde_json::from_slice(&ok_out.stdout).unwrap();
    assert_eq!(v_ok.get("ok").and_then(|x| x.as_bool()), Some(true));
    let s_ok = v_ok.get("summary").unwrap();
    assert_eq!(s_ok.get("errors").and_then(|x| x.as_u64()), Some(0));
    assert_eq!(s_ok.get("warnings").and_then(|x| x.as_u64()), Some(0));

    // warn: allow unknown downgrades unknown_field to warning; expect exit code 1
    let warn_out = assert_cmd::cargo::cargo_bin_cmd!("app")
        .args([
            "check",
            "-c",
            warnf.path().to_str().unwrap(),
            "--schema-v2-validate",
            "--allow-unknown",
            "/",
            "--format",
            "json",
        ])
        .output()
        .unwrap();
    assert_eq!(warn_out.status.code(), Some(1));
    let v_warn: Value = serde_json::from_slice(&warn_out.stdout).unwrap();
    assert_eq!(v_warn.get("ok").and_then(|x| x.as_bool()), Some(true));
    let s_warn = v_warn.get("summary").unwrap();
    assert!(s_warn.get("warnings").and_then(|x| x.as_u64()).unwrap_or(0) > 0);

    // bad: expect exit code 2
    let bad_out = assert_cmd::cargo::cargo_bin_cmd!("app")
        .args([
            "check",
            "-c",
            badf.path().to_str().unwrap(),
            "--schema-v2-validate",
            "--format",
            "json",
        ])
        .output()
        .unwrap();
    assert_eq!(bad_out.status.code(), Some(2));
    let v_bad: Value = serde_json::from_slice(&bad_out.stdout).unwrap();
    assert_eq!(v_bad.get("ok").and_then(|x| x.as_bool()), Some(false));
    let s_bad = v_bad.get("summary").unwrap();
    assert!(s_bad.get("errors").and_then(|x| x.as_u64()).unwrap_or(0) > 0);
}
