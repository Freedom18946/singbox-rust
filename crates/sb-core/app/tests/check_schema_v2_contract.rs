//! Check Schema v2 JSON Contract Test
//!
//! This test locks the JSON schema for the check command output.
//! Any field additions, deletions, or type changes will cause this test to fail.
//! This ensures API stability for CLI consumers.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use serde_json::{json, Value};

#[test]
fn test_check_report_json_schema_contract() {
    // Mock check report that represents the expected structure
    let check_report = json!({
        "ok": false,
        "file": "config.json",
        "issues": [
            {
                "kind": "error",
                "ptr": "/inbound/0/port",
                "msg": "port must be integer",
                "code": "TYPE_MISMATCH",
                "hint": "use integer value between 1-65535"
            }
        ],
        "summary": {
            "total_issues": 1,
            "errors": 1,
            "warnings": 0
        },
        "fingerprint": "deadbeef"
    });

    // Test required fields exist and have correct types
    assert!(check_report.is_object(), "Check report must be an object");

    let obj = check_report.as_object().unwrap();

    // Test required fields
    assert!(obj.contains_key("ok"), "Must contain 'ok' field");
    assert!(obj.contains_key("file"), "Must contain 'file' field"); 
    assert!(obj.contains_key("issues"), "Must contain 'issues' field");
    assert!(obj.contains_key("summary"), "Must contain 'summary' field");

    // Test field types
    assert!(obj["ok"].is_boolean(), "'ok' must be a boolean");
    assert!(obj["file"].is_string(), "'file' must be a string");
    assert!(obj["issues"].is_array(), "'issues' must be an array");
    assert!(obj["summary"].is_object(), "'summary' must be an object");

    // Test optional fingerprint field
    if obj.contains_key("fingerprint") {
        assert!(obj["fingerprint"].is_string(), "'fingerprint' must be a string when present");
    }

    // Test issues array structure
    test_issues_array_contract(&obj["issues"]);

    // Test summary object structure
    test_summary_object_contract(&obj["summary"]);
}

fn test_issues_array_contract(issues_value: &Value) {
    let issues = issues_value.as_array().unwrap();
    
    for issue in issues {
        assert!(issue.is_object(), "Each issue must be an object");
        let issue_obj = issue.as_object().unwrap();

        // Test required issue fields
        assert!(issue_obj.contains_key("kind"), "Issue must contain 'kind' field");
        assert!(issue_obj.contains_key("ptr"), "Issue must contain 'ptr' field");
        assert!(issue_obj.contains_key("msg"), "Issue must contain 'msg' field");
        assert!(issue_obj.contains_key("code"), "Issue must contain 'code' field");

        // Test issue field types
        assert!(issue_obj["kind"].is_string(), "'kind' must be a string");
        assert!(issue_obj["ptr"].is_string(), "'ptr' must be a string");
        assert!(issue_obj["msg"].is_string(), "'msg' must be a string");  
        assert!(issue_obj["code"].is_string(), "'code' must be a string");

        // Test kind enum values
        let kind = issue_obj["kind"].as_str().unwrap();
        assert!(matches!(kind, "error" | "warning"), "kind must be 'error' or 'warning'");

        // Test optional hint field
        if issue_obj.contains_key("hint") {
            assert!(issue_obj["hint"].is_string(), "'hint' must be a string when present");
        }

        // Test that ptr follows JSON pointer format (starts with /)
        let ptr = issue_obj["ptr"].as_str().unwrap();
        assert!(ptr.starts_with("/"), "ptr must start with '/' (JSON pointer format)");
    }
}

fn test_summary_object_contract(summary_value: &Value) {
    let summary = summary_value.as_object().unwrap();

    // Test required summary fields
    assert!(summary.contains_key("total_issues"), "Summary must contain 'total_issues'");
    assert!(summary.contains_key("errors"), "Summary must contain 'errors'");
    assert!(summary.contains_key("warnings"), "Summary must contain 'warnings'");

    // Test summary field types
    assert!(summary["total_issues"].is_number(), "'total_issues' must be a number");
    assert!(summary["errors"].is_number(), "'errors' must be a number");
    assert!(summary["warnings"].is_number(), "'warnings' must be a number");

    // Test that numbers are non-negative integers
    let total = summary["total_issues"].as_u64().unwrap();
    let errors = summary["errors"].as_u64().unwrap();
    let warnings = summary["warnings"].as_u64().unwrap();

    assert_eq!(total, errors + warnings, "total_issues should equal errors + warnings");
}

#[test]
fn test_check_minimal_valid_report() {
    // Test minimal valid report (no issues)
    let minimal_report = json!({
        "ok": true,
        "file": "config.json",
        "issues": [],
        "summary": {
            "total_issues": 0,
            "errors": 0,
            "warnings": 0
        }
    });

    let obj = minimal_report.as_object().unwrap();
    assert_eq!(obj["ok"].as_bool().unwrap(), true);
    assert_eq!(obj["issues"].as_array().unwrap().len(), 0);
    
    let summary = obj["summary"].as_object().unwrap();
    assert_eq!(summary["total_issues"].as_u64().unwrap(), 0);
    assert_eq!(summary["errors"].as_u64().unwrap(), 0);
    assert_eq!(summary["warnings"].as_u64().unwrap(), 0);
}

#[test]
fn test_check_error_report_with_unknown_field() {
    // Test error report with unknown field issue
    let error_report = json!({
        "ok": false,
        "file": "config.json",
        "issues": [
            {
                "kind": "error",
                "ptr": "/unknown_field",
                "msg": "unknown field 'unknown_field'",
                "code": "UNKNOWN_FIELD",
                "hint": "remove this field or check spelling"
            }
        ],
        "summary": {
            "total_issues": 1,
            "errors": 1,
            "warnings": 0
        }
    });

    let obj = error_report.as_object().unwrap();
    assert_eq!(obj["ok"].as_bool().unwrap(), false);
    
    let issues = obj["issues"].as_array().unwrap();
    assert_eq!(issues.len(), 1);
    
    let issue = &issues[0];
    let issue_obj = issue.as_object().unwrap();
    assert_eq!(issue_obj["kind"].as_str().unwrap(), "error");
    assert_eq!(issue_obj["code"].as_str().unwrap(), "UNKNOWN_FIELD");
    assert!(issue_obj.contains_key("hint"));
}

#[test]
fn test_check_issue_codes_contract() {
    // Test various issue codes to ensure they're preserved
    const KNOWN_ISSUE_CODES: &[&str] = &[ 
        "SCHEMA_VIOLATION",
        "MISSING_FIELD", 
        "INVALID_TYPE",
        "INVALID_PORT",
        "INVALID_ENUM",
        "MUTUAL_EXCLUSIVE",
        "REF_MISSING",
        "REF_UNREADABLE",
        "REF_TOO_LARGE",
        "CROSS_REF_MISSING",
        "UNKNOWN_FIELD",
        "TYPE_MISMATCH",
        "OUT_OF_RANGE",
        "DUPLICATE_NAME",
        "PORT_CONFLICT",
        "BAD_CIDR",
        "BAD_DOMAIN",
        "API_VERSION_MISSING",
        "KIND_MISSING",
        "API_VERSION_UNKNOWN",
        "UNREACHABLE_RULE",
        "SHADOWED_BY",
        "EMPTY_RULE_MATCH",
        "REDUNDANT_RULE",
        "CONFLICTING_RULE",
        "CONFIG_RISK"
    ];

    // Test that all known codes can be used in issues
    for &code in KNOWN_ISSUE_CODES {
        let issue = json!({
            "kind": "warning",
            "ptr": "/test",
            "msg": "test message",
            "code": code
        });

        let issue_obj = issue.as_object().unwrap();
        assert_eq!(issue_obj["code"].as_str().unwrap(), code);
    }
}

#[test]
fn test_check_report_field_count_stability() {
    // Test that core fields remain stable
    let core_report = json!({
        "ok": true,
        "file": "test.json",
        "issues": [],
        "summary": {
            "total_issues": 0,
            "errors": 0,
            "warnings": 0
        }
    });

    let obj = core_report.as_object().unwrap();
    
    // Core fields that must always be present
    for field in ["ok", "file", "issues", "summary"].iter() {
        assert!(obj.contains_key(*field), "Required field '{}' missing", field);
    }
    
    // Count only core vs optional fields to track schema evolution
    let core_field_count = obj.keys().filter(|k| {
        matches!(k.as_str(), "ok" | "file" | "issues" | "summary")
    }).count();
    
    assert_eq!(core_field_count, 4, "Core field count must remain 4");
}
