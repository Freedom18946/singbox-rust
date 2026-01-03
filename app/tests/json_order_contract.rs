#![cfg(feature = "dev-cli")]
use std::fs;
use std::io;

fn write_cfg(content: &str) -> io::Result<tempfile::NamedTempFile> {
    let f = tempfile::NamedTempFile::new()?;
    fs::write(f.path(), content.as_bytes())?;
    Ok(f)
}

fn find_pos(s: &str, needle: &str) -> usize {
    if let Some(pos) = s.find(needle) {
        pos
    } else {
        assert!(s.contains(needle), "missing {} in output: {}", needle, s);
        0
    }
}

#[test]
fn version_json_field_order_locked() -> Result<(), Box<dyn std::error::Error>> {
    let out = assert_cmd::cargo::cargo_bin_cmd!("version")
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let s = std::str::from_utf8(&out)?;
    // Expect deterministic lexicographic key order from serde_json::Map (BTreeMap).
    let build_info_pos = find_pos(s, "\"build_info\"");
    let features_pos = find_pos(s, "\"features\"");
    let fingerprint_pos = find_pos(s, "\"fingerprint\"");
    let license_pos = find_pos(s, "\"license\"");
    let license_notice_pos = find_pos(s, "\"license_notice\"");
    let name_pos = find_pos(s, "\"name\"");
    let version_pos = find_pos(s, "\"version\"");
    assert!(
        build_info_pos < features_pos
            && features_pos < fingerprint_pos
            && fingerprint_pos < license_pos
            && license_pos < license_notice_pos
            && license_notice_pos < name_pos
            && name_pos < version_pos
    );
    let build_ts_pos = find_pos(s, "\"build_ts\"");
    let git_sha_pos = find_pos(s, "\"git_sha\"");
    assert!(build_ts_pos < git_sha_pos);
    Ok(())
}

#[test]
fn route_explain_json_field_order_locked() -> Result<(), Box<dyn std::error::Error>> {
    let cfg = r#"{"inbounds":[{"type":"socks","listen":"127.0.0.1","port":1080}]}"#;
    let tmp = write_cfg(cfg)?;
    let tmp_path = tmp.path().to_str().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "temp config path is not valid UTF-8",
        )
    })?;
    let out = assert_cmd::cargo::cargo_bin_cmd!("app")
        .args([
            "route",
            "-c",
            tmp_path,
            "--dest",
            "example.com:443",
            "--explain",
            "--format",
            "json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let s = std::str::from_utf8(&out)?;
    let dest = find_pos(s, "\"dest\"");
    let mr = find_pos(s, "\"matched_rule\"");
    let chain = find_pos(s, "\"chain\"");
    let ob = find_pos(s, "\"outbound\"");
    assert!(dest < mr && mr < chain && chain < ob);
    Ok(())
}
