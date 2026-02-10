use std::path::PathBuf;
use std::process::Command;

#[test]
fn cli_help_has_core_flags() {
    let workspace_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace root")
        .to_path_buf();
    let bin = workspace_root.join("target").join("debug").join("app");
    if !bin.exists() {
        let status = Command::new("cargo")
            .args(["build", "-p", "app"])
            .status()
            .expect("build app");
        assert!(status.success(), "failed to build app binary for help test");
    }

    // The checker surface is a core acceptance interface: ensure the check help mentions key flags.
    let out = Command::new(&bin)
        .args(["check", "--help"])
        .output()
        .expect("run app check --help");
    assert!(
        out.status.success(),
        "app check --help failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let help = String::from_utf8_lossy(&out.stdout);
    assert!(
        help.contains("--schema-v2-validate"),
        "missing --schema-v2-validate"
    );
    assert!(help.contains("--deny-unknown"), "missing --deny-unknown");
}
