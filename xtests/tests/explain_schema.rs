use serde_json::Value;
use std::path::PathBuf;
use std::process::Command;

#[test]
fn explain_json_shape() {
    let workspace_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace root")
        .to_path_buf();
    let bin = workspace_root
        .join("target")
        .join("debug")
        .join("route-explain");
    if !bin.exists() {
        let status = Command::new("cargo")
            .args(["build", "-p", "app", "--bin", "route-explain", "--features", "explain"])
            .status()
            .expect("build route-explain");
        assert!(status.success(), "failed to build route-explain binary");
    }

    let out = Command::new(&bin)
        .current_dir(&workspace_root)
        .args([
            "-c",
            "examples/quick-start/01-minimal.json",
            "--destination",
            "www.example.com:443",
            "--format",
            "json",
            "--with-trace",
        ])
        .output()
        .expect("run route-explain");
    assert!(
        out.status.success(),
        "route-explain failed: {}",
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
