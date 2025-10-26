#![cfg(feature = "dev-cli")]
use serde_json::{from_str, Value};
use std::io::Write;
use std::process::Command;
use tempfile::NamedTempFile;

#[test]
fn test_minimize_rules_with_negation_detection() {
    // Test configuration with negation rules
    let config_with_negation = r#"
route:
  rules:
    - when:
        domain: "example.com"
      outbound: "proxy"
    - when:
        not_domain: "internal.com"
        port: 80
      outbound: "direct"
    - when:
        domain: "test.com"
      outbound: "proxy"
outbound:
  - tag: "direct"
    type: "direct"
  - tag: "proxy"
    type: "socks"
    server: "127.0.0.1"
    server_port: 1080
"#;

    // Create temporary file
    let mut temp_file = NamedTempFile::new().expect("Failed to create temp file");
    temp_file
        .write_all(config_with_negation.as_bytes())
        .expect("Failed to write to temp file");

    // Run minimize-rules command
    let output = Command::new("cargo")
        .args([
            "run",
            "--bin",
            "singbox-rust",
            "check",
            "-c",
            temp_file.path().to_str().unwrap(),
            "--minimize-rules",
        ])
        .output()
        .expect("Failed to execute command");

    // Check that the command succeeded
    assert!(output.status.success(), "Command should succeed");

    // Check stderr for the negation detection message
    let stderr = String::from_utf8(output.stderr).expect("Invalid UTF-8 in stderr");
    assert!(
        stderr.contains("MINIMIZE_SKIPPED: negation_present=true"),
        "Should detect negation and skip minimization"
    );

    // Parse stdout as JSON
    let stdout = String::from_utf8(output.stdout).expect("Invalid UTF-8 in stdout");
    let json: Value = from_str(&stdout).expect("Invalid JSON output");

    // Verify that all rules are preserved (canonicalized but not minimized)
    let rules = json
        .pointer("/route/rules")
        .and_then(|r| r.as_array())
        .expect("Rules should exist");
    assert_eq!(
        rules.len(),
        3,
        "All 3 rules should be preserved when negation is detected"
    );

    // Verify the not_domain rule is still present
    let has_not_domain = rules
        .iter()
        .any(|rule| rule.pointer("/when/not_domain").is_some());
    assert!(has_not_domain, "not_domain rule should be preserved");
}

#[test]
fn test_minimize_rules_without_negation() {
    // Test configuration without negation rules
    let config_without_negation = r#"
route:
  rules:
    - when:
        domain: "example.com"
      outbound: "proxy"
    - when:
        domain: "example.com"
        port: 80
      outbound: "proxy"
    - when:
        domain: "different.com"
      outbound: "proxy"
    - when:
        ip_cidr: "192.168.1.0/24"
      outbound: "direct"
outbound:
  - tag: "direct"
    type: "direct"
  - tag: "proxy"
    type: "socks"
    server: "127.0.0.1"
    server_port: 1080
"#;

    // Create temporary file
    let mut temp_file = NamedTempFile::new().expect("Failed to create temp file");
    temp_file
        .write_all(config_without_negation.as_bytes())
        .expect("Failed to write to temp file");

    // Run minimize-rules command
    let output = Command::new("cargo")
        .args([
            "run",
            "--bin",
            "singbox-rust",
            "check",
            "-c",
            temp_file.path().to_str().unwrap(),
            "--minimize-rules",
        ])
        .output()
        .expect("Failed to execute command");

    // Check that the command succeeded
    assert!(output.status.success(), "Command should succeed");

    // Check stderr does NOT contain the negation detection message
    let stderr = String::from_utf8(output.stderr).expect("Invalid UTF-8 in stderr");
    assert!(
        !stderr.contains("MINIMIZE_SKIPPED: negation_present=true"),
        "Should not detect negation when none present"
    );

    // Parse stdout as JSON
    let stdout = String::from_utf8(output.stdout).expect("Invalid UTF-8 in stdout");
    let json: Value = from_str(&stdout).expect("Invalid JSON output");

    // Verify that rules are minimized
    let rules = json
        .pointer("/route/rules")
        .and_then(|r| r.as_array())
        .expect("Rules should exist");

    // The second rule (domain: "example.com" + port: 80) should be removed as it's covered by the first
    // So we should have fewer than 4 rules
    assert!(
        rules.len() < 4,
        "Some rules should be removed during minimization"
    );
    assert!(rules.len() > 0, "At least some rules should remain");

    // Verify that unique rules are preserved
    let has_different_domain = rules
        .iter()
        .any(|rule| rule.pointer("/when/domain").and_then(|d| d.as_str()) == Some("different.com"));
    let has_ip_cidr = rules
        .iter()
        .any(|rule| rule.pointer("/when/ip_cidr").is_some());

    assert!(
        has_different_domain || has_ip_cidr,
        "Unique rules should be preserved"
    );
}

#[test]
fn test_negation_detection_various_types() {
    // Test that different types of negation rules are detected
    let negation_types = vec!["not_domain", "not_ip_cidr", "not_port", "not_protocol"];

    for negation_type in negation_types {
        let config = format!(
            r#"
route:
  rules:
    - when:
        domain: "example.com"
      outbound: "proxy"
    - when:
        {}: "test_value"
      outbound: "direct"
outbound:
  - tag: "direct"
    type: "direct"
  - tag: "proxy"
    type: "socks"
    server: "127.0.0.1"
    server_port: 1080
"#,
            negation_type
        );

        // Create temporary file
        let mut temp_file = NamedTempFile::new().expect("Failed to create temp file");
        temp_file
            .write_all(config.as_bytes())
            .expect("Failed to write to temp file");

        // Run minimize-rules command
        let output = Command::new("cargo")
            .args([
                "run",
                "--bin",
                "singbox-rust",
                "check",
                "-c",
                temp_file.path().to_str().unwrap(),
                "--minimize-rules",
            ])
            .output()
            .expect("Failed to execute command");

        // Check stderr for the negation detection message
        let stderr = String::from_utf8(output.stderr).expect("Invalid UTF-8 in stderr");
        assert!(
            stderr.contains("MINIMIZE_SKIPPED: negation_present=true"),
            "Should detect {} negation type",
            negation_type
        );
    }
}
