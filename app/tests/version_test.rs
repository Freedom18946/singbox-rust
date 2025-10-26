use serde_json::{from_str, Value};
use std::process::Command;

#[test]
fn test_sb_version_output_format() {
    let output = Command::new("cargo")
        .args(["run", "--bin", "sb-version"])
        .output()
        .expect("Failed to execute sb-version");

    assert!(output.status.success(), "sb-version command failed");

    let stdout = String::from_utf8(output.stdout).expect("Invalid UTF-8 output");
    let json: Value = from_str(&stdout).expect("Invalid JSON output");

    // Verify required fields exist
    assert!(json.get("version").is_some(), "Missing version field");
    assert!(json.get("commit").is_some(), "Missing commit field");
    assert!(json.get("build_time").is_some(), "Missing build_time field");
    assert!(json.get("features").is_some(), "Missing features field");
    assert!(json.get("platform").is_some(), "Missing platform field");

    // Verify platform structure
    let platform = json.get("platform").unwrap();
    assert!(platform.get("os").is_some(), "Missing platform.os field");
    assert!(
        platform.get("arch").is_some(),
        "Missing platform.arch field"
    );
    assert!(
        platform.get("target").is_some(),
        "Missing platform.target field"
    );

    // Verify features is an array
    assert!(
        json.get("features").unwrap().is_array(),
        "Features should be an array"
    );

    // Verify version is a string and not empty
    let version = json.get("version").unwrap().as_str().unwrap();
    assert!(!version.is_empty(), "Version should not be empty");

    // Verify commit is a string
    let commit = json.get("commit").unwrap().as_str().unwrap();
    assert!(!commit.is_empty(), "Commit should not be empty");

    // Verify build_time is a string
    let build_time = json.get("build_time").unwrap().as_str().unwrap();
    assert!(!build_time.is_empty(), "Build time should not be empty");
}

#[test]
fn test_sb_version_platform_fields() {
    let output = Command::new("cargo")
        .args(["run", "--bin", "sb-version"])
        .output()
        .expect("Failed to execute sb-version");

    assert!(output.status.success(), "sb-version command failed");

    let stdout = String::from_utf8(output.stdout).expect("Invalid UTF-8 output");
    let json: Value = from_str(&stdout).expect("Invalid JSON output");

    let platform = json.get("platform").unwrap();

    // Verify OS field is valid
    let os = platform.get("os").unwrap().as_str().unwrap();
    assert!(
        ["linux", "macos", "windows"].contains(&os),
        "OS should be linux, macos, or windows, got: {}",
        os
    );

    // Verify arch field is valid
    let arch = platform.get("arch").unwrap().as_str().unwrap();
    assert!(
        ["x86_64", "aarch64", "x86"].contains(&arch),
        "Arch should be x86_64, aarch64, or x86, got: {}",
        arch
    );

    // Verify target field contains arch
    let target = platform.get("target").unwrap().as_str().unwrap();
    assert!(
        target.contains(arch),
        "Target should contain arch, got target: {}, arch: {}",
        target,
        arch
    );
}

#[test]
fn test_sb_version_features_array() {
    let output = Command::new("cargo")
        .args(["run", "--bin", "sb-version"])
        .output()
        .expect("Failed to execute sb-version");

    assert!(output.status.success(), "sb-version command failed");

    let stdout = String::from_utf8(output.stdout).expect("Invalid UTF-8 output");
    let json: Value = from_str(&stdout).expect("Invalid JSON output");

    // The features array might be empty if SB_FEATURES env var is not set
    // This is expected behavior in development builds
    let _features = json.get("features").unwrap().as_array().unwrap();
    // Successfully getting as_array() verifies it's an array
}
