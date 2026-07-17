use serde_json::Value;
use std::process::Command;

#[test]
fn check_json_shape() {
    let bin = xtests::ensure_workspace_bin("app", "app", &[]);
    let out = Command::new(&bin)
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .args([
            "check",
            "-c",
            "tests/assets/check/bad_unreachable.yaml",
            "--format",
            "json",
            "--with-rule-id",
        ])
        .output()
        .expect("run");
    // Fixture intentionally triggers diagnostics, so check returns a non-zero diagnostic exit code.
    assert!(
        matches!(out.status.code(), Some(1) | Some(2)),
        "unexpected exit status: {:?}, stderr={}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr)
    );
    let v: Value = serde_json::from_slice(&out.stdout).expect("json");
    let arr = v
        .get("issues")
        .and_then(|x| x.as_array())
        .expect("issues array");
    assert!(!arr.is_empty());
    let item = &arr[0];
    assert!(item.get("code").is_some());
    assert!(item.get("ptr").is_some());
    assert!(v.get("summary").is_some());
}
