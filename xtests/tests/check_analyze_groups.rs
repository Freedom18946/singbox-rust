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
        cmd.args(["build", "-p", "singbox-rust"]);

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

        let status = cmd.status().expect("build singbox-rust");
        assert!(
            status.success(),
            "failed to build singbox-rust binary for xtests"
        );
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
    let workspace = env::var("CARGO_MANIFEST_DIR")
        .map(PathBuf::from)
        .map_err(|_| "CARGO_MANIFEST_DIR not set".to_string())?;
    let path = workspace.join("target").join(profile).join(exe);
    Ok(path)
}

fn run_check(cfg: &str, level: &str) -> Value {
    ensure_binary();
    let bin = cargo_bin_path("singbox-rust").expect("locate singbox-rust");
    assert!(bin.exists(), "singbox-rust binary not found at {:?}", bin);
    let mut cmd = Command::new(bin);
    let out = cmd
        .env("SB_CHECK_ANALYZE", "1")
        .env("SB_CHECK_ANALYZE_LEVEL", level)
        .env("SB_CHECK_RULEID", "1")
        .args(["check", "-c", cfg, "--format", "json"])
        .output()
        .expect("run singbox-rust check");
    serde_json::from_slice(&out.stdout).unwrap()
}

#[test]
fn conflict_group_has_members_and_ruleid() {
    let v = run_check("tests/assets/check/bad_conflict.yaml", "error");
    let issues = v.get("issues").unwrap().as_array().unwrap();
    let group = issues
        .iter()
        .find(|i| {
            i.get("ptr").and_then(|p| p.as_str()) == Some("/route/rules")
                && i.get("members").is_some()
        })
        .expect("group issue present");
    assert_eq!(
        group.get("code").and_then(|c| c.as_str()),
        Some("CONFLICTING_RULE")
    );
    assert!(group.get("key").is_some());
    let m = group.get("members").unwrap().as_array().unwrap();
    assert!(m.len() >= 2);
    // 每个成员 idx 必须对应一条逐条 ConflictRule
    for idx in m {
        let ptr_expected = format!("/route/rules/{}", idx.as_u64().unwrap());
        let hit = issues.iter().any(|i| {
            i.get("code").and_then(|c| c.as_str()) == Some("CONFLICTING_RULE")
                && i.get("ptr").and_then(|p| p.as_str()) == Some(ptr_expected.as_str())
        });
        assert!(hit, "member idx {} missing ConflictRule", idx);
    }
}

#[test]
fn unreachable_group_exists() {
    let v = run_check("tests/assets/check/bad_unreachable.yaml", "error");
    let issues = v.get("issues").unwrap().as_array().unwrap();
    let group = issues.iter().find(|i| {
        i.get("ptr").and_then(|p| p.as_str()) == Some("/outbounds") && i.get("members").is_some()
    });
    assert!(group.is_some(), "unreachable outbound group missing");
}
