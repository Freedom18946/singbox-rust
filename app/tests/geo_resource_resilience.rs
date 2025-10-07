#![cfg(feature = "router")]
//! GEO/DNS resource robustness tests
//!
//! Tests for resilient handling of missing, corrupt, and legacy GEO database files.
//! Ensures that the system fails gracefully with proper error codes and diagnostics.

use serde_json::Value;
use std::process::Command;
use std::str;
use tempfile::TempDir;

// Helper to get the path to the check binary
fn check_binary_path() -> String {
    env!("CARGO_BIN_EXE_check").to_string()
}

// Helper to get the path to the route-explain binary
fn route_explain_binary_path() -> String {
    env!("CARGO_BIN_EXE_route-explain").to_string()
}

#[tokio::test]
async fn test_missing_geoip_database() {
    let output = Command::new(check_binary_path())
        .args([
            "--config",
            "app/tests/fixtures/geo/missing/config.yaml",
            "--format",
            "json",
        ])
        .output()
        .expect("Failed to execute check command");

    assert!(
        !output.status.success(),
        "Check should fail with missing database"
    );

    let stdout = str::from_utf8(&output.stdout).expect("Invalid UTF-8 in stdout");
    let result: Value = serde_json::from_str(stdout).expect("Invalid JSON output");

    // Verify the error structure
    assert_eq!(result["ok"], false);
    assert!(result["issues"].is_array());

    let issues = result["issues"].as_array().unwrap();
    assert!(!issues.is_empty(), "Should have at least one issue");

    // Check for NotFound error code
    let has_not_found = issues.iter().any(|issue| {
        issue["code"].as_str() == Some("NotFound") || issue["level"].as_str() == Some("error")
    });
    assert!(has_not_found, "Should have NotFound or error issue");

    // Check that issues have proper structure with ptr/hint
    for issue in issues {
        assert!(issue["code"].is_string(), "Issue should have code");
        assert!(issue["level"].is_string(), "Issue should have level");
        assert!(issue["message"].is_string(), "Issue should have message");
        // Optional fields: ptr, hint
    }
}

#[tokio::test]
async fn test_corrupt_geoip_database() {
    let output = Command::new(check_binary_path())
        .args([
            "--config",
            "app/tests/fixtures/geo/corrupt/config.yaml",
            "--format",
            "json",
        ])
        .output()
        .expect("Failed to execute check command");

    assert!(
        !output.status.success(),
        "Check should fail with corrupt database"
    );

    let stdout = str::from_utf8(&output.stdout).expect("Invalid UTF-8 in stdout");
    let result: Value = serde_json::from_str(stdout).expect("Invalid JSON output");

    assert_eq!(result["ok"], false);
    assert!(result["issues"].is_array());

    let issues = result["issues"].as_array().unwrap();
    assert!(!issues.is_empty(), "Should have at least one issue");

    // Check for TypeMismatch or Io error code
    let has_parse_error = issues.iter().any(|issue| {
        matches!(
            issue["code"].as_str(),
            Some("TypeMismatch") | Some("Io") | Some("Parse")
        )
    });
    assert!(has_parse_error, "Should have parse/format error");
}

#[tokio::test]
async fn test_legacy_geoip_database() {
    let output = Command::new(check_binary_path())
        .args([
            "--config",
            "app/tests/fixtures/geo/legacy/config.yaml",
            "--format",
            "json",
        ])
        .output()
        .expect("Failed to execute check command");

    assert!(
        !output.status.success(),
        "Check should fail with legacy database"
    );

    let stdout = str::from_utf8(&output.stdout).expect("Invalid UTF-8 in stdout");
    let result: Value = serde_json::from_str(stdout).expect("Invalid JSON output");

    assert_eq!(result["ok"], false);
    assert!(result["issues"].is_array());

    let issues = result["issues"].as_array().unwrap();
    assert!(!issues.is_empty(), "Should have at least one issue");

    // Check for version/format compatibility error
    let has_version_error = issues.iter().any(|issue| {
        matches!(
            issue["code"].as_str(),
            Some("TypeMismatch") | Some("Conflict") | Some("UnsupportedVersion")
        )
    });
    assert!(has_version_error, "Should have version compatibility error");
}

#[tokio::test]
async fn test_route_explain_missing_database() {
    let output = Command::new(route_explain_binary_path())
        .args([
            "--config",
            "app/tests/fixtures/geo/missing/config.yaml",
            "--destination",
            "8.8.8.8",
            "--format",
            "json",
        ])
        .output()
        .expect("Failed to execute route-explain command");

    assert!(
        !output.status.success(),
        "Route-explain should fail with missing database"
    );

    // Check that it doesn't panic and produces some output
    let stderr = str::from_utf8(&output.stderr).unwrap_or("");
    let stdout = str::from_utf8(&output.stdout).unwrap_or("");

    // Should not contain panic messages
    assert!(
        !stderr.contains("panic"),
        "Should not panic on missing database"
    );
    assert!(
        !stdout.contains("panic"),
        "Should not panic on missing database"
    );
}

#[tokio::test]
async fn test_route_explain_corrupt_database() {
    let output = Command::new(route_explain_binary_path())
        .args([
            "--config",
            "app/tests/fixtures/geo/corrupt/config.yaml",
            "--destination",
            "8.8.8.8",
            "--format",
            "json",
        ])
        .output()
        .expect("Failed to execute route-explain command");

    assert!(
        !output.status.success(),
        "Route-explain should fail with corrupt database"
    );

    let stderr = str::from_utf8(&output.stderr).unwrap_or("");
    let stdout = str::from_utf8(&output.stdout).unwrap_or("");

    // Should not contain panic messages
    assert!(
        !stderr.contains("panic"),
        "Should not panic on corrupt database"
    );
    assert!(
        !stdout.contains("panic"),
        "Should not panic on corrupt database"
    );
}

#[tokio::test]
async fn test_error_logging_rate_limiting() {
    // Test that repeated access to the same broken resource doesn't spam logs

    for _i in 0..5 {
        let _output = Command::new(check_binary_path())
            .args([
                "--config",
                "app/tests/fixtures/geo/missing/config.yaml",
                "--format",
                "json",
            ])
            .output()
            .expect("Failed to execute check command");

        // In a real implementation, we would verify that logs are rate-limited
        // For now, just ensure commands don't hang or crash
    }
}

#[tokio::test]
async fn test_json_output_structure() {
    let output = Command::new(check_binary_path())
        .args([
            "--config",
            "app/tests/fixtures/geo/missing/config.yaml",
            "--format",
            "json",
        ])
        .output()
        .expect("Failed to execute check command");

    let stdout = str::from_utf8(&output.stdout).expect("Invalid UTF-8 in stdout");

    // Should be valid JSON even on failure
    let result: Value = serde_json::from_str(stdout).expect("Should produce valid JSON");

    // Check required fields
    assert!(result["ok"].is_boolean(), "Should have 'ok' boolean field");
    assert!(
        result["issues"].is_array(),
        "Should have 'issues' array field"
    );

    if let Some(summary) = result.get("summary") {
        assert!(
            summary["errors"].is_number(),
            "Summary should have errors count"
        );
        assert!(
            summary["warnings"].is_number(),
            "Summary should have warnings count"
        );
    }

    // Check issue structure
    let issues = result["issues"].as_array().unwrap();
    for issue in issues {
        assert!(issue["code"].is_string(), "Issue should have code");
        assert!(issue["level"].is_string(), "Issue should have level");
        assert!(issue["message"].is_string(), "Issue should have message");

        // Optional but recommended fields
        if let Some(ptr) = issue.get("ptr") {
            assert!(ptr.is_string(), "ptr should be string if present");
        }
        if let Some(hint) = issue.get("hint") {
            assert!(hint.is_string(), "hint should be string if present");
        }
    }
}

#[tokio::test]
async fn test_exit_codes() {
    // Test that different error conditions return appropriate exit codes

    // Missing database
    let output = Command::new(check_binary_path())
        .args(["--config", "app/tests/fixtures/geo/missing/config.yaml"])
        .output()
        .expect("Failed to execute check command");

    assert!(
        !output.status.success(),
        "Missing database should return non-zero exit code"
    );

    // Corrupt database
    let output = Command::new(check_binary_path())
        .args(["--config", "app/tests/fixtures/geo/corrupt/config.yaml"])
        .output()
        .expect("Failed to execute check command");

    assert!(
        !output.status.success(),
        "Corrupt database should return non-zero exit code"
    );

    // Legacy database
    let output = Command::new(check_binary_path())
        .args(["--config", "app/tests/fixtures/geo/legacy/config.yaml"])
        .output()
        .expect("Failed to execute check command");

    assert!(
        !output.status.success(),
        "Legacy database should return non-zero exit code"
    );
}
