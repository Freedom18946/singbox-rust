use assert_cmd::Command;
use std::fs;

fn write_file(p: &str, s: &str) {
    fs::write(p, s.as_bytes()).unwrap();
}

#[test]
fn subs_merge_and_diff() {
    let dir = tempfile::tempdir().unwrap();
    let base = dir.path().join("base.json");
    let a = dir.path().join("a.json");
    let out = dir.path().join("merged.json");
    write_file(
        base.to_str().unwrap(),
        r#"{"inbounds":[],"outbounds":[],"route":{"rules":[]}}"#,
    );
    write_file(
        a.to_str().unwrap(),
        r#"{"inbounds":[{"type":"socks","listen":"0.0.0.0","port":1080}],"route":{"rules":[{"domain":["a.com"]}]}}"#,
    );
    let _ = Command::cargo_bin("subs")
        .unwrap()
        .args([
            "merge",
            base.to_str().unwrap(),
            a.to_str().unwrap(),
            "-o",
            out.to_str().unwrap(),
        ])
        .assert()
        .success();
    let merged = fs::read_to_string(out).unwrap();
    assert!(merged.contains("inbounds"));
    // diff self -> should be empty
    let d = Command::cargo_bin("subs")
        .unwrap()
        .args(["diff", a.to_str().unwrap(), a.to_str().unwrap()])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let v: serde_json::Value = serde_json::from_slice(&d).unwrap();
    assert!(v.get("added").unwrap().as_object().unwrap().is_empty());
    assert!(v.get("removed").unwrap().as_object().unwrap().is_empty());
}
