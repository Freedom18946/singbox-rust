use serde_json::Value;
use std::path::PathBuf;
use std::process::Command;

/// 契约：docs/07-reference/schemas/ (路由解释输出格式)
#[test]
fn explain_cli_envelope() {
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
        .expect("run");
    assert!(
        out.status.success(),
        "route-explain failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v: Value = serde_json::from_slice(&out.stdout).expect("json");
    assert!(v.get("outbound").is_some(), "missing outbound");
    assert!(v.get("matched_rule").is_some(), "missing matched_rule");
}
