use std::fs;
use std::path::Path;

fn write_file(path: &Path, content: &str) -> std::io::Result<()> {
    fs::write(path, content.as_bytes())
}

#[test]
fn subs_merge_and_diff() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let base = dir.path().join("base.json");
    let a = dir.path().join("a.json");
    let out = dir.path().join("merged.json");
    write_file(
        &base,
        r#"{"inbounds":[],"outbounds":[],"route":{"rules":[]}}"#,
    )?;
    write_file(
        &a,
        r#"{"inbounds":[{"type":"socks","listen":"0.0.0.0","port":1080}],"route":{"rules":[{"domain":["a.com"]}]}}"#,
    )?;
    let _ = assert_cmd::cargo::cargo_bin_cmd!("subs")
        .arg("merge")
        .arg(&base)
        .arg(&a)
        .arg("-o")
        .arg(&out)
        .assert()
        .success();
    let merged = fs::read_to_string(out)?;
    assert!(merged.contains("inbounds"));

    // diff self -> should be empty
    let d = assert_cmd::cargo::cargo_bin_cmd!("subs")
        .arg("diff")
        .arg(&a)
        .arg(&a)
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let v: serde_json::Value = serde_json::from_slice(&d)?;
    assert!(v
        .get("added")
        .and_then(serde_json::Value::as_object)
        .is_some_and(serde_json::Map::is_empty));
    assert!(v
        .get("removed")
        .and_then(serde_json::Value::as_object)
        .is_some_and(serde_json::Map::is_empty));

    Ok(())
}

#[test]
fn subs_invalid_json_reports_error_without_panic() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let bad = dir.path().join("bad.json");
    write_file(&bad, "{not json")?;

    let output = assert_cmd::cargo::cargo_bin_cmd!("subs")
        .arg("diff")
        .arg(&bad)
        .arg(&bad)
        .assert()
        .failure()
        .get_output()
        .stderr
        .clone();
    let stderr = String::from_utf8(output)?;

    assert!(stderr.contains("failed to parse JSON"));
    assert!(!stderr.contains("panicked"));

    Ok(())
}
