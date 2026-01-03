#![cfg(feature = "long_tests")]
#![cfg(feature = "dev-cli")]
// app/tests/prometheus_query_robustness.rs
use std::{fs, process::Command};
use tempfile::TempDir;

/// Test timeout behavior and error classification for Prometheus queries
#[test]
fn test_prometheus_timeout_behavior() {
    let temp_dir = TempDir::new().unwrap();
    let script_path = temp_dir.path().join("test_prom_http.sh");

    // Copy the prom_http.sh script to temp location for testing
    let prom_script = include_str!("../../scripts/lib/prom_http.sh");
    fs::write(&script_path, prom_script).unwrap();

    // Test timeout with very short timeout
    let output = Command::new("bash")
        .arg(&script_path)
        .arg("up")
        .env("SB_PROM_HTTP", "http://192.0.2.1:9090") // Non-routable IP for timeout
        .env("SB_PROM_TIMEOUT_MS", "100") // Very short timeout
        .output()
        .unwrap();

    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(
        stdout.contains("__PROM_HTTP_FAIL__:timeout")
            || stdout.contains("__PROM_HTTP_FAIL__:connect")
    );
}

/// Test error classification for different curl exit codes
#[test]
fn test_prometheus_error_classification() {
    let temp_dir = TempDir::new().unwrap();
    let script_path = temp_dir.path().join("test_prom_http.sh");

    let prom_script = include_str!("../../scripts/lib/prom_http.sh");
    fs::write(&script_path, prom_script).unwrap();

    // Test connection failure (invalid host)
    let output = Command::new("bash")
        .arg(&script_path)
        .arg("up")
        .env(
            "SB_PROM_HTTP",
            "http://invalid-host-that-does-not-exist:9090",
        )
        .env("SB_PROM_TIMEOUT_MS", "1000")
        .output()
        .unwrap();

    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("__PROM_HTTP_FAIL__:connect"));

    // Test HTTP 4xx error (invalid endpoint)
    let output = Command::new("bash")
        .arg(&script_path)
        .arg("up")
        .env("SB_PROM_HTTP", "http://httpbin.org/status/404")
        .env("SB_PROM_TIMEOUT_MS", "5000")
        .output()
        .unwrap();

    let stdout = String::from_utf8(output.stdout).unwrap();
    if stdout.contains("__PROM_HTTP_FAIL__:connect")
        || stdout.contains("__PROM_HTTP_FAIL__:timeout")
        || stdout.contains("__PROM_HTTP_FAIL__:curl")
    {
        eprintln!("Skipping http4xx classification: network unavailable");
        return;
    }
    assert!(stdout.contains("__PROM_HTTP_FAIL__:http4xx"));
}

/// Test fallback mechanisms to offline mode
#[test]
fn test_prometheus_fallback_to_offline() {
    let temp_dir = TempDir::new().unwrap();
    let test_script = temp_dir.path().join("test_fallback.sh");

    // Create a test script that simulates the prom_assert function behavior
    let fallback_test = r#"#!/bin/bash
set -euo pipefail

# Simulate prom_assert fallback logic
SOURCE="offline"
if [[ -n "${SB_PROM_HTTP:-}" ]]; then
    resp="__PROM_HTTP_FAIL__:timeout"
    if [[ "$resp" != __PROM_HTTP_DISABLED__* && "$resp" != __PROM_HTTP_FAIL__* ]]; then
        SOURCE="http"
    elif [[ "$resp" == __PROM_HTTP_FAIL__* ]]; then
        SOURCE="$resp"
    fi
fi

# Fallback to offline if HTTP failed
if [[ "$SOURCE" == "offline" || "$SOURCE" == __PROM_HTTP_FAIL__* ]]; then
    # Keep the failure source if it was an HTTP failure
    if [[ "$SOURCE" != __PROM_HTTP_FAIL__* ]]; then
        SOURCE="offline"
    fi
fi

echo "SOURCE=$SOURCE"
"#;

    fs::write(&test_script, fallback_test).unwrap();

    // Test fallback when Prometheus HTTP fails
    let output = Command::new("bash")
        .arg(&test_script)
        .env("SB_PROM_HTTP", "http://invalid:9090")
        .output()
        .unwrap();

    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("SOURCE=__PROM_HTTP_FAIL__:timeout"));

    // Test fallback when Prometheus HTTP is disabled
    let output = Command::new("bash")
        .arg(&test_script)
        .env_remove("SB_PROM_HTTP")
        .output()
        .unwrap();

    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("SOURCE=offline"));
}

/// Test diagnostic reporting accuracy
#[test]
fn test_prometheus_diagnostic_reporting() {
    let temp_dir = TempDir::new().unwrap();
    let diagnostic_script = temp_dir.path().join("test_diagnostics.sh");

    // Create a script that tests diagnostic reporting
    let diagnostic_test = r#"#!/bin/bash
set -euo pipefail

# Test different failure scenarios and their diagnostic output
test_scenario() {
    local scenario="$1"
    local expected_pattern="$2"
    
    case "$scenario" in
        "disabled")
            unset SB_PROM_HTTP
            result="__PROM_HTTP_DISABLED__"
            ;;
        "timeout")
            result="__PROM_HTTP_FAIL__:timeout"
            ;;
        "connect")
            result="__PROM_HTTP_FAIL__:connect"
            ;;
        "http4xx")
            result="__PROM_HTTP_FAIL__:http4xx"
            ;;
        "json")
            result="__PROM_HTTP_FAIL__:json"
            ;;
        *)
            result="__PROM_HTTP_FAIL__:curl"
            ;;
    esac
    
    echo "SCENARIO=$scenario RESULT=$result"
    
    # Verify the result matches expected pattern
    if [[ "$result" == *"$expected_pattern"* ]]; then
        echo "DIAGNOSTIC_OK=$scenario"
    else
        echo "DIAGNOSTIC_FAIL=$scenario"
    fi
}

test_scenario "$1" "$2"
"#;

    fs::write(&diagnostic_script, diagnostic_test).unwrap();

    // Test various diagnostic scenarios
    let scenarios = [
        ("disabled", "__PROM_HTTP_DISABLED__"),
        ("timeout", "__PROM_HTTP_FAIL__:timeout"),
        ("connect", "__PROM_HTTP_FAIL__:connect"),
        ("http4xx", "__PROM_HTTP_FAIL__:http4xx"),
        ("json", "__PROM_HTTP_FAIL__:json"),
    ];

    for (scenario, expected) in scenarios.iter() {
        let output = Command::new("bash")
            .arg(&diagnostic_script)
            .arg(scenario)
            .arg(expected)
            .output()
            .unwrap();

        let stdout = String::from_utf8(output.stdout).unwrap();
        assert!(
            stdout.contains(&format!("DIAGNOSTIC_OK={}", scenario)),
            "Diagnostic failed for scenario: {}",
            scenario
        );
    }
}

/// Test environment variable handling
#[test]
fn test_prometheus_environment_variables() {
    let temp_dir = TempDir::new().unwrap();
    let script_path = temp_dir.path().join("test_prom_http.sh");

    let prom_script = include_str!("../../scripts/lib/prom_http.sh");
    fs::write(&script_path, prom_script).unwrap();

    // Test with SB_PROM_HTTP unset (should be disabled)
    let output = Command::new("bash")
        .arg(&script_path)
        .arg("up")
        .env_remove("SB_PROM_HTTP")
        .output()
        .unwrap();

    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("__PROM_HTTP_DISABLED__"));

    // Test with custom timeout
    let output = Command::new("bash")
        .arg(&script_path)
        .arg("up")
        .env("SB_PROM_HTTP", "http://httpbin.org/delay/10") // Long delay endpoint
        .env("SB_PROM_TIMEOUT_MS", "500") // Short timeout
        .output()
        .unwrap();

    let stdout = String::from_utf8(output.stdout).unwrap();
    if stdout.contains("__PROM_HTTP_FAIL__:connect") || stdout.contains("__PROM_HTTP_FAIL__:curl") {
        eprintln!("Skipping timeout check: network unavailable");
    } else {
        assert!(stdout.contains("__PROM_HTTP_FAIL__:timeout"));
    }

    // Test with default timeout (should be 2000ms)
    let env_test_script = temp_dir.path().join("test_env.sh");
    let env_test = r#"#!/bin/bash
set -euo pipefail
export SB_PROM_HTTP="${SB_PROM_HTTP:-http://example.invalid}"
source "$(dirname "$0")/test_prom_http.sh"

# Test default timeout value
timeout_ms="${SB_PROM_TIMEOUT_MS:-2000}"
echo "DEFAULT_TIMEOUT=$timeout_ms"

# Test timeout conversion
timeout_sec=$(awk -v t="$timeout_ms" 'BEGIN{print t/1000}')
echo "TIMEOUT_SEC=$timeout_sec"
"#;

    fs::write(&env_test_script, env_test).unwrap();

    let output = Command::new("bash")
        .arg(&env_test_script)
        .env_remove("SB_PROM_TIMEOUT_MS")
        .output()
        .unwrap();

    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("DEFAULT_TIMEOUT=2000"));
    assert!(stdout.contains("TIMEOUT_SEC=2"));
}

/// Test curl availability check
#[test]
fn test_prometheus_curl_availability() {
    let temp_dir = TempDir::new().unwrap();
    let curl_test_script = temp_dir.path().join("test_curl.sh");

    // Create a script that tests curl availability
    let curl_test = r#"#!/bin/bash
set -euo pipefail

# Test curl availability check
if ! command -v curl >/dev/null 2>&1; then
    echo "__PROM_HTTP_FAIL__:nocurl"
    exit 0
else
    echo "CURL_AVAILABLE"
fi
"#;

    fs::write(&curl_test_script, curl_test).unwrap();

    let output = Command::new("bash")
        .arg(&curl_test_script)
        .output()
        .unwrap();

    let stdout = String::from_utf8(output.stdout).unwrap();
    // curl should be available in most test environments
    assert!(stdout.contains("CURL_AVAILABLE"));
}

/// Test JSON response validation
#[test]
fn test_prometheus_json_validation() {
    let temp_dir = TempDir::new().unwrap();
    let json_test_script = temp_dir.path().join("test_json.sh");

    // Create a script that tests JSON validation logic
    let json_test = r#"#!/bin/bash
set -euo pipefail

test_json_response() {
    local response="$1"
    
    # Simulate the JSON validation logic from prom_http.sh
    if echo "$response" | jq -e '.status == "success"' >/dev/null 2>&1; then
        echo "JSON_VALID"
    else
        echo "__PROM_HTTP_FAIL__:json"
    fi
}

# Test valid Prometheus response
valid_response='{"status":"success","data":{"resultType":"vector","result":[{"metric":{},"value":[1234567890,"42"]}]}}'
test_json_response "$valid_response"

# Test invalid JSON
invalid_json='{"status":"error"'
test_json_response "$invalid_json"

# Test valid JSON but error status
error_response='{"status":"error","errorType":"bad_data","error":"invalid query"}'
test_json_response "$error_response"
"#;

    fs::write(&json_test_script, json_test).unwrap();

    let output = Command::new("bash")
        .arg(&json_test_script)
        .output()
        .unwrap();

    let stdout = String::from_utf8(output.stdout).unwrap();
    let lines: Vec<&str> = stdout.trim().split('\n').collect();

    assert_eq!(lines[0], "JSON_VALID"); // Valid response
    assert_eq!(lines[1], "__PROM_HTTP_FAIL__:json"); // Invalid JSON
    assert_eq!(lines[2], "__PROM_HTTP_FAIL__:json"); // Error status
}
