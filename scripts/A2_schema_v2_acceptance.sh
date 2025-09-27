#!/bin/bash
# A2: Schema v2 validation acceptance testing
#
# Exit codes:
# 0 - All schema validation tests passed
# 1 - Some validation tests failed
# 2 - Critical failure or setup error
# 77 - Skipped (schema-v2 feature not available)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Configuration
E2E_DIR="$PROJECT_ROOT/.e2e"
RUST_BIN="$PROJECT_ROOT/target/debug/app"
RESULTS_FILE="$E2E_DIR/schema_v2_results.json"

echo "=== A2: Schema v2 Validation Acceptance Test ==="

# Check if rust binary exists
if [[ ! -x "$RUST_BIN" ]]; then
    echo "ERROR: Rust binary not found at $RUST_BIN"
    echo "Run 'cargo build' first"
    exit 2
fi

# Test schema v2 feature availability
if ! "$RUST_BIN" check --help | grep -q "schema-v2\|deny-unknown"; then
    echo "SKIP: Schema v2 features not available"
    echo '{"status":"skipped","reason":"schema_v2_not_available","timestamp":"'$(date -u +%Y-%m-%dT%H:%M:%SZ)'"}' > "$RESULTS_FILE"
    exit 77
fi

# Test configurations
declare -A test_configs

# Valid v2 config
test_configs["valid_v2"]=$(cat <<'EOF'
{
  "schema_version": 2,
  "inbounds": [
    {"type": "socks", "listen": "127.0.0.1", "port": 1080}
  ],
  "outbounds": [
    {"type": "direct"}
  ]
}
EOF
)

# Invalid config with unknown fields
test_configs["unknown_fields"]=$(cat <<'EOF'
{
  "schema_version": 2,
  "unknown_field": "should_error",
  "inbounds": [
    {"type": "socks", "listen": "127.0.0.1", "port": 1080, "invalid_field": "test"}
  ],
  "outbounds": [
    {"type": "direct"}
  ]
}
EOF
)

# Config missing required fields
test_configs["missing_required"]=$(cat <<'EOF'
{
  "schema_version": 2,
  "inbounds": [
    {"type": "socks"}
  ],
  "outbounds": [
    {"type": "direct"}
  ]
}
EOF
)

# Config with type mismatches
test_configs["type_mismatch"]=$(cat <<'EOF'
{
  "schema_version": 2,
  "inbounds": [
    {"type": "socks", "listen": "127.0.0.1", "port": "invalid_port_type"}
  ],
  "outbounds": [
    {"type": "direct"}
  ]
}
EOF
)

# Results tracking
declare -A test_results
tests_passed=0
tests_failed=0
total_tests=0

echo "Running schema v2 validation tests..."

# Test 1: Valid v2 config should pass
echo "Test 1: Valid v2 config"
config_file=$(mktemp)
echo "${test_configs["valid_v2"]}" > "$config_file"

if "$RUST_BIN" check -c "$config_file" --deny-unknown --format json >/dev/null 2>&1; then
    test_results["valid_v2"]="PASS"
    tests_passed=$((tests_passed + 1))
    echo "  PASS: Valid config accepted"
else
    test_results["valid_v2"]="FAIL"
    tests_failed=$((tests_failed + 1))
    echo "  FAIL: Valid config rejected"
fi
total_tests=$((total_tests + 1))
rm -f "$config_file"

# Test 2: Unknown fields should be caught with --deny-unknown
echo "Test 2: Unknown fields detection"
config_file=$(mktemp)
echo "${test_configs["unknown_fields"]}" > "$config_file"

if output=$("$RUST_BIN" check -c "$config_file" --deny-unknown --format json 2>&1); then
    if echo "$output" | jq -e '.issues[] | select(.code == "UnknownField")' >/dev/null 2>&1; then
        test_results["unknown_fields"]="PASS"
        tests_passed=$((tests_passed + 1))
        echo "  PASS: Unknown fields detected"
    else
        test_results["unknown_fields"]="FAIL"
        tests_failed=$((tests_failed + 1))
        echo "  FAIL: Unknown fields not detected in output"
    fi
else
    test_results["unknown_fields"]="PASS"
    tests_passed=$((tests_passed + 1))
    echo "  PASS: Unknown fields caused validation failure"
fi
total_tests=$((total_tests + 1))
rm -f "$config_file"

# Test 3: Missing required fields should be detected
echo "Test 3: Missing required fields"
config_file=$(mktemp)
echo "${test_configs["missing_required"]}" > "$config_file"

if output=$("$RUST_BIN" check -c "$config_file" --deny-unknown --format json 2>&1); then
    if echo "$output" | jq -e '.issues[] | select(.code == "MissingRequired")' >/dev/null 2>&1; then
        test_results["missing_required"]="PASS"
        tests_passed=$((tests_passed + 1))
        echo "  PASS: Missing required fields detected"
    else
        test_results["missing_required"]="FAIL"
        tests_failed=$((tests_failed + 1))
        echo "  FAIL: Missing required fields not detected"
    fi
else
    test_results["missing_required"]="PASS"
    tests_passed=$((tests_passed + 1))
    echo "  PASS: Missing required fields caused validation failure"
fi
total_tests=$((total_tests + 1))
rm -f "$config_file"

# Test 4: Type mismatches should be detected
echo "Test 4: Type mismatch detection"
config_file=$(mktemp)
echo "${test_configs["type_mismatch"]}" > "$config_file"

if output=$("$RUST_BIN" check -c "$config_file" --deny-unknown --format json 2>&1); then
    if echo "$output" | jq -e '.issues[] | select(.code == "TypeMismatch")' >/dev/null 2>&1; then
        test_results["type_mismatch"]="PASS"
        tests_passed=$((tests_passed + 1))
        echo "  PASS: Type mismatch detected"
    else
        test_results["type_mismatch"]="FAIL"
        tests_failed=$((tests_failed + 1))
        echo "  FAIL: Type mismatch not detected"
    fi
else
    test_results["type_mismatch"]="PASS"
    tests_passed=$((tests_passed + 1))
    echo "  PASS: Type mismatch caused validation failure"
fi
total_tests=$((total_tests + 1))
rm -f "$config_file"

# Test 5: Allow unknown with prefix should work
echo "Test 5: Allow unknown with prefix"
config_file=$(mktemp)
echo "${test_configs["unknown_fields"]}" > "$config_file"

if output=$("$RUST_BIN" check -c "$config_file" --deny-unknown --allow-unknown "/unknown" --format json 2>&1); then
    if echo "$output" | jq -e '.issues[] | select(.code == "UnknownField" and .kind == "warning")' >/dev/null 2>&1; then
        test_results["allow_unknown_prefix"]="PASS"
        tests_passed=$((tests_passed + 1))
        echo "  PASS: Unknown field downgraded to warning with --allow-unknown"
    else
        test_results["allow_unknown_prefix"]="PARTIAL"
        tests_failed=$((tests_failed + 1))
        echo "  PARTIAL: Allow unknown behavior not as expected"
    fi
else
    test_results["allow_unknown_prefix"]="FAIL"
    tests_failed=$((tests_failed + 1))
    echo "  FAIL: Allow unknown prefix not working"
fi
total_tests=$((total_tests + 1))
rm -f "$config_file"

# Generate results report
{
    echo "{"
    echo "  \"timestamp\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\","
    echo "  \"total_tests\": $total_tests,"
    echo "  \"tests_passed\": $tests_passed,"
    echo "  \"tests_failed\": $tests_failed,"
    echo "  \"success_rate\": $(awk "BEGIN {printf \"%.2f\", $tests_passed/$total_tests*100}"),"
    echo "  \"status\": \"$([ $tests_failed -eq 0 ] && echo "pass" || echo "partial")\","
    echo "  \"test_results\": {"
    first=true
    for test in "${!test_results[@]}"; do
        if [[ "$first" = true ]]; then
            first=false
        else
            echo ","
        fi
        echo "    \"$test\": \"${test_results[$test]}\""
    done
    echo ""
    echo "  }"
    echo "}"
} > "$RESULTS_FILE"

echo ""
echo "=== Results ==="
echo "Total tests: $total_tests"
echo "Passed: $tests_passed"
echo "Failed: $tests_failed"
echo "Success rate: $(awk "BEGIN {printf \"%.1f\", $tests_passed/$total_tests*100}")%"
echo "Results saved to: $RESULTS_FILE"

# Determine exit code
if [[ $tests_failed -eq 0 ]]; then
    echo "SUCCESS: All schema v2 validation tests passed"
    exit 0
else
    echo "PARTIAL: $tests_failed validation tests failed"
    exit 1
fi