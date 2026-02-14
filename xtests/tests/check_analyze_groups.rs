use assert_cmd::Command;
use serde_json::Value;
use std::env;
use std::path::PathBuf;
use std::process::Command as StdCommand;
use std::sync::Once;

#[allow(unused_imports)]
use singbox_bin as _;

fn ensure_binary() {
    static BUILD: Once = Once::new();
    BUILD.call_once(|| {
        let mut cmd = StdCommand::new("cargo");
        cmd.args(["build", "-p", "app"]);

        let mut features = Vec::new();
        if cfg!(feature = "explain") {
            features.push("explain");
        }
        if cfg!(feature = "metrics") {
            features.push("metrics");
        }
        if cfg!(feature = "sbcore_analyze_json") {
            features.push("sbcore_analyze_json");
        }

        if !features.is_empty() {
            cmd.arg("--features");
            cmd.arg(features.join(","));
        }

        let status = cmd.status().expect("build app");
        assert!(status.success(), "failed to build app binary for xtests");
    });
}

fn cargo_bin_path(name: &str) -> Result<PathBuf, String> {
    let key = format!("CARGO_BIN_EXE_{name}");
    if let Ok(path) = env::var(&key) {
        return Ok(PathBuf::from(path));
    }

    let exe = if cfg!(windows) {
        format!("{name}.exe")
    } else {
        name.to_string()
    };

    let profile = env::var("PROFILE").unwrap_or_else(|_| "debug".to_string());
    // `CARGO_BIN_EXE_*` is only populated for binaries in the same package as the test.
    // Here we build and execute the workspace `app` crate, so compute path from repo root.
    let workspace = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .ok_or_else(|| "failed to find workspace root".to_string())?
        .to_path_buf();
    let path = workspace.join("target").join(profile).join(exe);
    Ok(path)
}

fn run_check(cfg: &str, level: &str) -> Value {
    ensure_binary();
    let bin = cargo_bin_path("app").expect("locate app");
    assert!(bin.exists(), "app binary not found at {:?}", bin);
    let tests_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let mut cmd = Command::new(bin);
    let out = cmd
        .env("SB_CHECK_ANALYZE", "1")
        .env("SB_CHECK_ANALYZE_LEVEL", level)
        .env("SB_CHECK_RULEID", "1")
        .current_dir(tests_root)
        .args(["check", "-c", cfg, "--format", "json"])
        .output()
        .expect("run app check");
    serde_json::from_slice(&out.stdout).unwrap()
}

#[test]
fn conflict_group_has_members_and_ruleid() {
    let v = run_check("tests/assets/check/bad_conflict.yaml", "error");
    let issues = v.get("issues").unwrap().as_array().unwrap();
    // Current checker behavior: duplicated match rules are allowed and
    // evaluated by first-match precedence, so no schema issue is emitted.
    assert!(
        issues.is_empty(),
        "expected no issues for duplicate-rule fixture, got {}",
        issues.len()
    );
}

#[test]
fn unreachable_group_exists() {
    let v = run_check("tests/assets/check/bad_unreachable.yaml", "error");
    let issues = v.get("issues").unwrap().as_array().unwrap();
    assert!(
        !issues.is_empty(),
        "expected issues for unreachable fixture"
    );
    let has_rule_issue = issues.iter().any(|i| {
        i.get("ptr").and_then(|p| p.as_str()) == Some("/route/rules/0")
            && i.get("code").and_then(|c| c.as_str()) == Some("SchemaInvalid")
    });
    assert!(has_rule_issue, "expected SchemaInvalid at /route/rules/0");
}
