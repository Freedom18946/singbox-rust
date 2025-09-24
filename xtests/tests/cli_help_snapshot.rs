use std::process::Command;

#[test]
fn cli_help_has_core_flags() {
    let out = Command::new("bash").args(["-lc","target/debug/singbox-rust --help | grep -E \"--check|--http|--schema-v2-validate\" | wc -l"]).output().unwrap();
    assert!(out.status.success());
    let n = String::from_utf8(out.stdout)
        .unwrap()
        .trim()
        .parse::<i32>()
        .unwrap_or(0);
    assert!(n >= 2, "core help flags missing");
}
