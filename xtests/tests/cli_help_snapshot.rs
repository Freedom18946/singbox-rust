use std::process::Command;

#[test]
fn cli_help_has_core_flags() {
    let bin = xtests::ensure_workspace_bin("app", "app", &[]);

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
