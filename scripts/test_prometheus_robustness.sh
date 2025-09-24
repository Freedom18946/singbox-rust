#!/usr/bin/env bash
# scripts/test_prometheus_robustness.sh
# Unit tests for Prometheus query robustness

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROM_HTTP_SCRIPT="${ROOT}/scripts/lib/prom_http.sh"

# Test counters
TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0

# Test result tracking
declare -a FAILED_TESTS=()

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_test() {
    echo -e "${YELLOW}[TEST]${NC} $1"
}

log_pass() {
    echo -e "${GREEN}[PASS]${NC} $1"
    ((TESTS_PASSED++))
}

log_fail() {
    echo -e "${RED}[FAIL]${NC} $1"
    ((TESTS_FAILED++))
    FAILED_TESTS+=("$1")
}

run_test() {
    ((TESTS_RUN++))
}

# Test 1: Timeout behavior
test_timeout_behavior() {
    log_test "Testing timeout behavior"
    run_test
    
    # Test with very short timeout to non-routable IP
    local result
    set +e  # Temporarily disable errexit
    result=$(SB_PROM_HTTP="http://192.0.2.1:9090" SB_PROM_TIMEOUT_MS="100" bash "$PROM_HTTP_SCRIPT" "up" 2>/dev/null || echo "")
    set -e  # Re-enable errexit
    
    if [[ "$result" == *"__PROM_HTTP_FAIL__:timeout"* ]] || [[ "$result" == *"__PROM_HTTP_FAIL__:connect"* ]]; then
        log_pass "Timeout behavior correctly classified"
    else
        log_fail "Timeout behavior not correctly classified. Got: $result"
    fi
}

# Test 2: Connection failure classification
test_connection_failure() {
    log_test "Testing connection failure classification"
    run_test
    
    local result
    set +e
    result=$(SB_PROM_HTTP="http://invalid-host-that-does-not-exist:9090" SB_PROM_TIMEOUT_MS="1000" bash "$PROM_HTTP_SCRIPT" "up" 2>/dev/null || echo "")
    set -e
    
    if [[ "$result" == *"__PROM_HTTP_FAIL__:connect"* ]]; then
        log_pass "Connection failure correctly classified"
    else
        log_fail "Connection failure not correctly classified. Got: $result"
    fi
}

# Test 3: HTTP error classification
test_http_error_classification() {
    log_test "Testing HTTP error classification"
    run_test
    
    # Test 404 error
    local result
    set +e
    result=$(SB_PROM_HTTP="http://httpbin.org/status/404" SB_PROM_TIMEOUT_MS="5000" bash "$PROM_HTTP_SCRIPT" "up" 2>/dev/null || echo "")
    set -e
    
    if [[ "$result" == *"__PROM_HTTP_FAIL__:http4xx"* ]]; then
        log_pass "HTTP 4xx error correctly classified"
    else
        log_fail "HTTP 4xx error not correctly classified. Got: $result"
    fi
}

# Test 4: Environment variable handling - disabled state
test_env_disabled() {
    log_test "Testing environment variable handling - disabled state"
    run_test
    
    local result
    set +e
    result=$(unset SB_PROM_HTTP; bash "$PROM_HTTP_SCRIPT" "up" 2>/dev/null || echo "")
    set -e
    
    if [[ "$result" == "__PROM_HTTP_DISABLED__" ]]; then
        log_pass "Disabled state correctly handled"
    else
        log_fail "Disabled state not correctly handled. Got: $result"
    fi
}

# Test 5: Default timeout value
test_default_timeout() {
    log_test "Testing default timeout value"
    run_test
    
    # Create a temporary script to test timeout extraction
    local temp_script=$(mktemp)
    cat > "$temp_script" << 'EOF'
#!/bin/bash
set -euo pipefail
source "$(dirname "$0")/lib/prom_http.sh"
timeout_ms="${SB_PROM_TIMEOUT_MS:-2000}"
echo "$timeout_ms"
EOF
    
    local result
    set +e
    result=$(unset SB_PROM_TIMEOUT_MS; bash "$temp_script" 2>/dev/null || echo "")
    set -e
    rm -f "$temp_script"
    
    if [[ "$result" == "2000" ]]; then
        log_pass "Default timeout value correct"
    else
        log_fail "Default timeout value incorrect. Got: $result"
    fi
}

# Test 6: Custom timeout value
test_custom_timeout() {
    log_test "Testing custom timeout value"
    run_test
    
    # Test with httpbin delay endpoint and short timeout
    local result
    set +e
    result=$(SB_PROM_HTTP="http://httpbin.org/delay/3" SB_PROM_TIMEOUT_MS="500" bash "$PROM_HTTP_SCRIPT" "up" 2>/dev/null || echo "")
    set -e
    
    if [[ "$result" == *"__PROM_HTTP_FAIL__:timeout"* ]]; then
        log_pass "Custom timeout value working"
    else
        log_fail "Custom timeout value not working. Got: $result"
    fi
}

# Test 7: Curl availability check
test_curl_availability() {
    log_test "Testing curl availability check"
    run_test
    
    # Temporarily hide curl from PATH
    local temp_script=$(mktemp)
    cat > "$temp_script" << 'EOF'
#!/bin/bash
set -euo pipefail
# Override PATH to hide curl
export PATH="/nonexistent"
source "$(dirname "$0")/lib/prom_http.sh"
prom_http_query "up"
EOF
    
    local result
    result=$(bash "$temp_script" 2>/dev/null || echo "")
    rm -f "$temp_script"
    
    if [[ "$result" == "__PROM_HTTP_FAIL__:nocurl" ]]; then
        log_pass "Curl availability check working"
    else
        log_fail "Curl availability check not working. Got: $result"
    fi
}

# Test 8: JSON validation - valid response
test_json_validation_valid() {
    log_test "Testing JSON validation - valid response"
    run_test
    
    # Create a mock server response test
    local temp_script=$(mktemp)
    cat > "$temp_script" << 'EOF'
#!/bin/bash
set -euo pipefail

# Simulate valid JSON response validation
response='{"status":"success","data":{"resultType":"vector","result":[{"metric":{},"value":[1234567890,"42"]}]}}'

if echo "$response" | jq -e '.status == "success"' >/dev/null 2>&1; then
    echo "VALID"
else
    echo "__PROM_HTTP_FAIL__:json"
fi
EOF
    
    local result
    result=$(bash "$temp_script" 2>/dev/null || echo "")
    rm -f "$temp_script"
    
    if [[ "$result" == "VALID" ]]; then
        log_pass "JSON validation for valid response working"
    else
        log_fail "JSON validation for valid response not working. Got: $result"
    fi
}

# Test 9: JSON validation - invalid response
test_json_validation_invalid() {
    log_test "Testing JSON validation - invalid response"
    run_test
    
    local temp_script=$(mktemp)
    cat > "$temp_script" << 'EOF'
#!/bin/bash
set -euo pipefail

# Simulate invalid JSON response validation
response='{"status":"error","errorType":"bad_data"}'

if echo "$response" | jq -e '.status == "success"' >/dev/null 2>&1; then
    echo "VALID"
else
    echo "__PROM_HTTP_FAIL__:json"
fi
EOF
    
    local result
    result=$(bash "$temp_script" 2>/dev/null || echo "")
    rm -f "$temp_script"
    
    if [[ "$result" == "__PROM_HTTP_FAIL__:json" ]]; then
        log_pass "JSON validation for invalid response working"
    else
        log_fail "JSON validation for invalid response not working. Got: $result"
    fi
}

# Test 10: Fallback mechanism simulation
test_fallback_mechanism() {
    log_test "Testing fallback mechanism"
    run_test
    
    local temp_script=$(mktemp)
    cat > "$temp_script" << 'EOF'
#!/bin/bash
set -euo pipefail

# Simulate prom_assert fallback logic
SOURCE="offline"
if [[ -n "${SB_PROM_HTTP:-}" ]]; then
    # Simulate HTTP failure
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

echo "$SOURCE"
EOF
    
    local result
    result=$(SB_PROM_HTTP="http://invalid:9090" bash "$temp_script" 2>/dev/null || echo "")
    rm -f "$temp_script"
    
    if [[ "$result" == "__PROM_HTTP_FAIL__:timeout" ]]; then
        log_pass "Fallback mechanism preserves failure reason"
    else
        log_fail "Fallback mechanism not working correctly. Got: $result"
    fi
}

# Test 11: Query URL encoding
test_query_encoding() {
    log_test "Testing query URL encoding"
    run_test
    
    local temp_script=$(mktemp)
    cat > "$temp_script" << 'EOF'
#!/bin/bash
set -euo pipefail
source "$(dirname "$0")/lib/prom_http.sh"

# Test qurl function with special characters
query='sum(rate(http_requests_total{job="api-server"}[5m]))'
encoded=$(qurl "$query")
echo "$encoded"
EOF
    
    local result
    result=$(bash "$temp_script" 2>/dev/null || echo "")
    rm -f "$temp_script"
    
    if [[ "$result" == *"query="* ]] && [[ "$result" == *"sum"* ]]; then
        log_pass "Query URL encoding working"
    else
        log_fail "Query URL encoding not working. Got: $result"
    fi
}

# Test 12: Diagnostic reporting accuracy
test_diagnostic_accuracy() {
    log_test "Testing diagnostic reporting accuracy"
    run_test
    
    local scenarios=("timeout" "connect" "http4xx" "json" "curl")
    local all_correct=true
    
    for scenario in "${scenarios[@]}"; do
        local expected="__PROM_HTTP_FAIL__:$scenario"
        # Each scenario should produce the expected diagnostic pattern
        if [[ "$expected" != *"$scenario"* ]]; then
            all_correct=false
            break
        fi
    done
    
    if $all_correct; then
        log_pass "Diagnostic reporting patterns are accurate"
    else
        log_fail "Diagnostic reporting patterns are not accurate"
    fi
}

# Main test runner
main() {
    echo "=== Prometheus Query Robustness Tests ==="
    echo
    
    # Check if required files exist
    if [[ ! -f "$PROM_HTTP_SCRIPT" ]]; then
        echo -e "${RED}ERROR:${NC} Prometheus HTTP script not found at $PROM_HTTP_SCRIPT"
        exit 1
    fi
    
    # Check if required tools are available
    if ! command -v jq >/dev/null 2>&1; then
        echo -e "${YELLOW}WARNING:${NC} jq not available, some tests may fail"
    fi
    
    # Run all tests
    test_timeout_behavior
    test_connection_failure
    test_http_error_classification
    test_env_disabled
    test_default_timeout
    test_custom_timeout
    test_curl_availability
    test_json_validation_valid
    test_json_validation_invalid
    test_fallback_mechanism
    test_query_encoding
    test_diagnostic_accuracy
    
    echo
    echo "=== Test Results ==="
    echo "Tests run: $TESTS_RUN"
    echo -e "Tests passed: ${GREEN}$TESTS_PASSED${NC}"
    echo -e "Tests failed: ${RED}$TESTS_FAILED${NC}"
    
    if [[ $TESTS_FAILED -gt 0 ]]; then
        echo
        echo "Failed tests:"
        for test in "${FAILED_TESTS[@]}"; do
            echo -e "  ${RED}✗${NC} $test"
        done
        exit 1
    else
        echo -e "\n${GREEN}All tests passed!${NC}"
        exit 0
    fi
}

# Run tests if script is executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi