use serde_json::Value;
use std::path::PathBuf;
use std::process::Command;

#[test]
fn explain_json_shape() {
    let workspace_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace root")
        .to_path_buf();
    let bin = xtests::ensure_workspace_bin("app", "app", &[]);

    let out = Command::new(&bin)
        .current_dir(&workspace_root)
        .args([
            "-c",
            "examples/quick-start/01-minimal.json",
            "route",
            "--dest",
            "www.example.com:443",
            "--format",
            "json",
            "--with-trace",
            "--explain",
        ])
        .output()
        .expect("run app route --explain");
    assert!(
        out.status.success(),
        "app route --explain failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v: Value = serde_json::from_slice(&out.stdout).expect("json");
    assert!(v.get("dest").is_some(), "missing dest");
    assert!(v.get("outbound").is_some(), "missing outbound");
    assert!(v.get("matched_rule").is_some(), "missing matched_rule");
    assert!(
        v.get("chain").and_then(|x| x.as_array()).is_some(),
        "missing chain array"
    );
}
