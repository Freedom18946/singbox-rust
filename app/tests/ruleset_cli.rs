#![cfg(feature = "router")]

use assert_cmd::Command;
use predicates::str::contains;
use serde_json::json;
use std::fs;
use tempfile::{Builder, NamedTempFile};

fn write_ruleset_file() -> NamedTempFile {
    let file = Builder::new()
        .suffix(".json")
        .tempfile()
        .expect("temp file");
    let content = json!({
        "version": 3,
        "rules": [
            {
                "domain": ["example.com"],
                "network": ["tcp"],
                "port": [443]
            }
        ]
    });
    fs::write(
        file.path(),
        serde_json::to_string(&content).expect("serialize"),
    )
    .expect("write ruleset");
    file
}

#[test]
fn ruleset_validate_and_info() {
    let file = write_ruleset_file();
    Command::cargo_bin("app")
        .unwrap()
        .args(["ruleset", "validate", file.path().to_str().unwrap()])
        .assert()
        .success()
        .stdout(contains("Rule-set is valid"));

    Command::cargo_bin("app")
        .unwrap()
        .args(["ruleset", "info", file.path().to_str().unwrap()])
        .assert()
        .success()
        .stdout(contains("Rule-Set Information"))
        .stdout(contains("Total Rules: 1"));
}

#[test]
fn ruleset_format_outputs_pretty_json() {
    let file = write_ruleset_file();
    Command::cargo_bin("app")
        .unwrap()
        .args(["ruleset", "format", file.path().to_str().unwrap()])
        .assert()
        .success()
        .stdout(contains("\n  \"rules\""));
}

#[test]
fn ruleset_match_bool_output() {
    let file = write_ruleset_file();
    Command::cargo_bin("app")
        .unwrap()
        .args([
            "ruleset",
            "match",
            file.path().to_str().unwrap(),
            "--domain",
            "example.com",
            "--network",
            "tcp",
        ])
        .assert()
        .success()
        .stdout(contains("matched: true"));

    Command::cargo_bin("app")
        .unwrap()
        .args([
            "ruleset",
            "match",
            file.path().to_str().unwrap(),
            "--domain",
            "other.com",
        ])
        .assert()
        .success()
        .stdout(contains("matched: false"));
}

#[test]
fn ruleset_compile_and_convert_roundtrip() {
    let json_in = write_ruleset_file();
    let srs_out = Builder::new()
        .suffix(".srs")
        .tempfile()
        .expect("temp srs");
    let json_out = Builder::new()
        .suffix(".json")
        .tempfile()
        .expect("temp json output");

    // compile JSON -> SRS
    Command::cargo_bin("app")
        .unwrap()
        .args([
            "ruleset",
            "compile",
            json_in.path().to_str().unwrap(),
            srs_out.path().to_str().unwrap(),
            "--version",
            "3",
        ])
        .assert()
        .success();
    let srs_bytes = fs::read(srs_out.path()).expect("read srs");
    assert!(!srs_bytes.is_empty());

    // convert SRS -> JSON and ensure fields survive
    Command::cargo_bin("app")
        .unwrap()
        .args([
            "ruleset",
            "convert",
            srs_out.path().to_str().unwrap(),
            json_out.path().to_str().unwrap(),
        ])
        .assert()
        .success();
    let json_text = fs::read_to_string(json_out.path()).expect("read converted json");
    assert!(json_text.contains("example.com"));
}

fn write_ruleset_with_domain(domain: &str) -> NamedTempFile {
    let file = Builder::new()
        .suffix(".json")
        .tempfile()
        .expect("temp file");
    let content = json!({
        "version": 3,
        "rules": [
            {
                "domain": [domain],
            }
        ]
    });
    fs::write(
        file.path(),
        serde_json::to_string(&content).expect("serialize"),
    )
    .expect("write ruleset");
    file
}

#[test]
fn ruleset_merge_combines_inputs() {
    let a = write_ruleset_with_domain("foo.com");
    let b = write_ruleset_with_domain("bar.com");
    let merged = Builder::new()
        .suffix(".json")
        .tempfile()
        .expect("merged output");

    Command::cargo_bin("app")
        .unwrap()
        .args([
            "ruleset",
            "merge",
            "-o",
            merged.path().to_str().unwrap(),
            a.path().to_str().unwrap(),
            b.path().to_str().unwrap(),
        ])
        .assert()
        .success();

    let merged_text = fs::read_to_string(merged.path()).expect("read merged");
    assert!(merged_text.contains("foo.com"));
    assert!(merged_text.contains("bar.com"));
}

#[test]
fn ruleset_upgrade_sets_target_version() {
    let json_in = write_ruleset_file();
    let srs_in = Builder::new()
        .suffix(".srs")
        .tempfile()
        .expect("srs input");
    let upgraded = Builder::new()
        .suffix(".json")
        .tempfile()
        .expect("upgraded output");

    // compile JSON to SRS version 1
    Command::cargo_bin("app")
        .unwrap()
        .args([
            "ruleset",
            "compile",
            json_in.path().to_str().unwrap(),
            srs_in.path().to_str().unwrap(),
            "--version",
            "1",
        ])
        .assert()
        .success();

    // upgrade to version 5 and write JSON
    Command::cargo_bin("app")
        .unwrap()
        .args([
            "ruleset",
            "upgrade",
            srs_in.path().to_str().unwrap(),
            upgraded.path().to_str().unwrap(),
            "--version",
            "5",
        ])
        .assert()
        .success();

    let upgraded_text = fs::read_to_string(upgraded.path()).expect("read upgraded");
    assert!(upgraded_text.contains("\"version\": 5"));
}
