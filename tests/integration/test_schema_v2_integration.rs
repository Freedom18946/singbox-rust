// Integration test for Schema v2 error format CLI integration
// This test verifies that the --schema-v2-validate flag works correctly

#[cfg(test)]
mod schema_v2_integration_tests {
    use std::process::Command;
    use std::fs;
    use serde_json::Value as Json;

    fn get_binary_path() -> String {
        std::env::var("CHECK_BIN").unwrap_or_else(|_| "target/debug/singbox-rust".into())
    }

    #[test]
    #[cfg(feature = "schema-v2")]
    fn test_schema_v2_validate_flag_integration() {
        // Test that --schema-v2-validate flag is properly integrated
        
        // Create a valid configuration
        let valid_config = r#"
inbounds:
  - type: http
    listen: "127.0.0.1"
    port: 18080
outbounds:
  - type: direct
route:
  rules:
    - to: "direct"
dns:
  mode: system
"#;
        fs::write("target/test_valid_v2.yaml", valid_config).unwrap();
        
        // Test valid configuration passes
        let output = Command::new(get_binary_path())
            .args([
                "check",
                "-c", "target/test_valid_v2.yaml",
                "--schema-v2-validate",
                "--format", "json"
            ])
            .output()
            .unwrap();
        
        assert!(output.status.success(), "Valid config should pass schema v2 validation");
        
        let stdout = String::from_utf8(output.stdout).unwrap();
        let report: Json = serde_json::from_str(&stdout).unwrap();
        assert_eq!(report.get("ok").and_then(|x| x.as_bool()).unwrap(), true);
    }

    #[test]
    #[cfg(feature = "schema-v2")]
    fn test_schema_v2_validate_unknown_field_error() {
        // Test that unknown fields are properly detected and reported
        
        let invalid_config = r#"
inbounds:
  - type: http
    listen: "127.0.0.1"
    port: 18080
outbounds:
  - type: direct
route:
  rules:
    - to: "direct"
dns:
  mode: system
unknown_field: "should cause error"
"#;
        fs::write("target/test_invalid_v2.yaml", invalid_config).unwrap();
        
        let output = Command::new(get_binary_path())
            .args([
                "check",
                "-c", "target/test_invalid_v2.yaml",
                "--schema-v2-validate",
                "--format", "json"
            ])
            .output()
            .unwrap();
        
        assert!(!output.status.success(), "Invalid config should fail schema v2 validation");
        
        let stdout = String::from_utf8(output.stdout).unwrap();
        let report: Json = serde_json::from_str(&stdout).unwrap();
        
        // Verify report structure
        assert_eq!(report.get("ok").and_then(|x| x.as_bool()).unwrap(), false);
        
        let issues = report.get("issues").and_then(|x| x.as_array()).unwrap();
        assert!(!issues.is_empty(), "Should have validation issues");
        
        // Find the unknown field error
        let mut found_unknown_field = false;
        for issue in issues {
            let code = issue.get("code").and_then(|x| x.as_str()).unwrap_or("");
            let ptr = issue.get("ptr").and_then(|x| x.as_str()).unwrap_or("");
            
            if code == "UnknownField" && ptr.contains("unknown_field") {
                found_unknown_field = true;
                
                // Verify issue structure
                assert!(issue.get("kind").and_then(|x| x.as_str()).is_some());
                assert!(issue.get("msg").and_then(|x| x.as_str()).is_some());
                assert!(ptr.starts_with("/"), "JSON pointer should start with /");
                
                // Should have a hint for unknown fields
                let hint = issue.get("hint").and_then(|x| x.as_str());
                assert!(hint.is_some(), "Unknown field errors should include hints");
                break;
            }
        }
        
        assert!(found_unknown_field, "Should detect unknown field error");
    }

    #[test]
    #[cfg(feature = "schema-v2")]
    fn test_schema_v2_fingerprint_generation() {
        // Test that fingerprint is generated correctly for schema v2 errors
        
        let config_with_errors = r#"
inbounds:
  - type: http
    listen: "127.0.0.1"
    port: 18080
outbounds:
  - type: direct
route:
  rules:
    - to: "direct"
dns:
  mode: system
error_field_1: "error1"
error_field_2: "error2"
"#;
        fs::write("target/test_fingerprint_v2.yaml", config_with_errors).unwrap();
        
        let output = Command::new(get_binary_path())
            .args([
                "check",
                "-c", "target/test_fingerprint_v2.yaml",
                "--schema-v2-validate",
                "--format", "json",
                "--fingerprint"
            ])
            .output()
            .unwrap();
        
        assert!(!output.status.success());
        
        let stdout = String::from_utf8(output.stdout).unwrap();
        let report: Json = serde_json::from_str(&stdout).unwrap();
        
        // Verify fingerprint is present and correctly formatted
        let fingerprint = report.get("fingerprint").and_then(|x| x.as_str()).unwrap();
        assert!(fingerprint.starts_with("sha256:"), "Fingerprint should start with sha256:");
        assert_eq!(fingerprint.len(), 71, "Fingerprint should be sha256: + 64 hex chars");
        
        // Verify fingerprint is deterministic by running again
        let output2 = Command::new(get_binary_path())
            .args([
                "check",
                "-c", "target/test_fingerprint_v2.yaml",
                "--schema-v2-validate",
                "--format", "json",
                "--fingerprint"
            ])
            .output()
            .unwrap();
        
        let stdout2 = String::from_utf8(output2.stdout).unwrap();
        let report2: Json = serde_json::from_str(&stdout2).unwrap();
        let fingerprint2 = report2.get("fingerprint").and_then(|x| x.as_str()).unwrap();
        
        assert_eq!(fingerprint, fingerprint2, "Fingerprints should be deterministic");
    }

    #[test]
    #[cfg(feature = "schema-v2")]
    fn test_deny_unknown_enables_schema_v2() {
        // Test that --deny-unknown automatically enables schema v2 validation
        
        let config_with_unknown = r#"
inbounds:
  - type: http
    listen: "127.0.0.1"
    port: 18080
outbounds:
  - type: direct
route:
  rules:
    - to: "direct"
dns:
  mode: system
unknown_field: "should fail"
"#;
        fs::write("target/test_deny_unknown_v2.yaml", config_with_unknown).unwrap();
        
        let output = Command::new(get_binary_path())
            .args([
                "check",
                "-c", "target/test_deny_unknown_v2.yaml",
                "--deny-unknown",
                "--format", "json"
            ])
            .output()
            .unwrap();
        
        assert!(!output.status.success(), "--deny-unknown should trigger schema v2 validation");
        
        let stdout = String::from_utf8(output.stdout).unwrap();
        let report: Json = serde_json::from_str(&stdout).unwrap();
        
        let issues = report.get("issues").and_then(|x| x.as_array()).unwrap();
        assert!(!issues.is_empty(), "Should have validation issues");
        
        // Should find schema v2 validation errors
        let has_schema_error = issues.iter().any(|issue| {
            let msg = issue.get("msg").and_then(|x| x.as_str()).unwrap_or("");
            msg.contains("schema v2") || issue.get("code").and_then(|x| x.as_str()).unwrap_or("") == "UnknownField"
        });
        
        assert!(has_schema_error, "Should have schema v2 validation errors");
    }

    #[test]
    #[cfg(not(feature = "schema-v2"))]
    fn test_schema_v2_disabled_warning() {
        // Test that when schema-v2 feature is disabled, a warning is shown
        
        let config = r#"
inbounds:
  - type: http
    listen: "127.0.0.1"
    port: 18080
outbounds:
  - type: direct
route:
  rules:
    - to: "direct"
dns:
  mode: system
"#;
        fs::write("target/test_disabled_v2.yaml", config).unwrap();
        
        let output = Command::new(get_binary_path())
            .args([
                "check",
                "-c", "target/test_disabled_v2.yaml",
                "--schema-v2-validate",
                "--format", "json"
            ])
            .output()
            .unwrap();
        
        let stdout = String::from_utf8(output.stdout).unwrap();
        let report: Json = serde_json::from_str(&stdout).unwrap();
        
        let issues = report.get("issues").and_then(|x| x.as_array()).unwrap();
        
        // Should have a warning about schema-v2 being disabled
        let has_disabled_warning = issues.iter().any(|issue| {
            let msg = issue.get("msg").and_then(|x| x.as_str()).unwrap_or("");
            msg.contains("schema-v2 feature disabled")
        });
        
        assert!(has_disabled_warning, "Should warn when schema-v2 feature is disabled");
    }
}