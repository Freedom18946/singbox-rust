use assert_cmd::Command;
use serde_json::Value;
use std::path::PathBuf;

fn run_check(cfg: &str) -> Value {
    let bin = xtests::ensure_workspace_bin("app", "app", &[]);
    assert!(bin.exists(), "app binary not found at {:?}", bin);
    let tests_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let mut cmd = Command::new(bin);
    let out = cmd
        .current_dir(tests_root)
        .args(["check", "-c", cfg, "--format", "json", "--with-rule-id"])
        .output()
        .expect("run app check");
    serde_json::from_slice(&out.stdout).expect("check json")
}

#[test]
fn duplicate_match_rules_are_allowed() {
    let v = run_check("tests/assets/check/duplicate_match_allowed.yaml");
    let issues = v
        .get("issues")
        .expect("issues")
        .as_array()
        .expect("issues array");
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
    let v = run_check("tests/assets/check/bad_unreachable.yaml");
    let issues = v
        .get("issues")
        .expect("issues")
        .as_array()
        .expect("issues array");
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
