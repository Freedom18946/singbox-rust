#!/bin/bash
# A4: Prometheus noise reduction regression testing
#
# Exit codes:
# 0 - All noise reduction tests passed
# 1 - Some tests failed but system functional
# 2 - Critical failure or setup error
# 77 - Skipped (metrics feature not available)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Configuration
E2E_DIR="$PROJECT_ROOT/.e2e"
RUST_BIN="$PROJECT_ROOT/target/debug/app"
RESULTS_FILE="$E2E_DIR/noise_regression_results.json"
METRICS_PORT=${SB_METRICS_PORT:-29093}
NOISE_TEST_DURATION=${NOISE_TEST_DURATION:-15}

echo "=== A4: Prometheus Noise Reduction Regression Test ==="

# Check dependencies
if [[ ! -x "$RUST_BIN" ]]; then
    echo "ERROR: Rust binary not found at $RUST_BIN"
    exit 2
fi

if ! command -v curl >/dev/null 2>&1; then
    echo "SKIP: curl not available for metrics testing"
    echo '{"status":"skipped","reason":"curl_not_available","timestamp":"'$(date -u +%Y-%m-%dT%H:%M:%SZ)'"}' > "$RESULTS_FILE"
    exit 77
fi

# Test configuration with metrics enabled
METRICS_CONFIG=$(cat <<EOF
{
  "log": {"level": "warn"},
  "experimental": {
    "cache_file": {"enabled": false}
  },
  "inbounds": [
    {
      "type": "socks",
      "listen": "127.0.0.1",
      "port": 22080
    }
  ],
  "outbounds": [
    {
      "type": "direct"
    }
  ]
}
EOF
)

# Results tracking
declare -A test_results
total_tests=0
tests_passed=0
tests_failed=0

echo "Setting up noise reduction test environment..."

# Create temporary config
config_file=$(mktemp)
echo "$METRICS_CONFIG" > "$config_file"
trap "rm -f '$config_file'" EXIT

# Test 1: Baseline metrics collection
echo "Test 1: Baseline metrics availability"
total_tests=$((total_tests + 1))

# Start singbox with metrics
export SB_METRICS_ADDR="127.0.0.1:$METRICS_PORT"
"$RUST_BIN" run -c "$config_file" &
singbox_pid=$!
trap "kill $singbox_pid 2>/dev/null || true; rm -f '$config_file'" EXIT

# Wait for startup
sleep 3

# Verify singbox is running
if ! kill -0 $singbox_pid 2>/dev/null; then
    echo "ERROR: Singbox failed to start"
    exit 2
fi

# Check metrics endpoint
if baseline_metrics=$(curl -s "http://127.0.0.1:$METRICS_PORT/metrics" 2>/dev/null); then
    test_results["baseline_metrics"]="PASS"
    tests_passed=$((tests_passed + 1))
    echo "  PASS: Metrics endpoint accessible"

    # Count available metrics
    metric_count=$(echo "$baseline_metrics" | grep -c "^[a-zA-Z]" || echo "0")
    echo "  Baseline metrics count: $metric_count"
else
    test_results["baseline_metrics"]="FAIL"
    tests_failed=$((tests_failed + 1))
    echo "  FAIL: Metrics endpoint not accessible"
fi

# Test 2: Error rate limiting behavior
echo "Test 2: Error rate limiting verification"
total_tests=$((total_tests + 1))

# Simulate error conditions by making rapid invalid requests
echo "  Generating error conditions..."

# Create burst of invalid connections to trigger accept/connection errors
error_trigger_pids=()
for i in $(seq 1 10); do
    {
        # Try to connect to non-existent port to trigger connection errors
        timeout 1 nc 127.0.0.1 99999 >/dev/null 2>&1 || true
        # Try invalid SOCKS requests to trigger protocol errors
        echo -e "\x00\x00\x00\x00" | timeout 1 nc 127.0.0.1 22080 >/dev/null 2>&1 || true
    } &
    error_trigger_pids+=($!)
done

# Wait for error generation
sleep 2

# Check that errors are being rate limited (metrics should not be flooded)
if stress_metrics=$(curl -s "http://127.0.0.1:$METRICS_PORT/metrics" 2>/dev/null); then
    # Look for error-related metrics that should be rate limited
    error_metrics=$(echo "$stress_metrics" | grep -E "(error|fail)" | wc -l || echo "0")

    if [[ $error_metrics -lt 50 ]]; then  # Reasonable threshold for rate limiting
        test_results["error_rate_limiting"]="PASS"
        tests_passed=$((tests_passed + 1))
        echo "  PASS: Error metrics appear rate limited ($error_metrics error metrics)"
    else
        test_results["error_rate_limiting"]="PARTIAL"
        tests_failed=$((tests_failed + 1))
        echo "  PARTIAL: High error metric count ($error_metrics), may not be rate limited"
    fi
else
    test_results["error_rate_limiting"]="FAIL"
    tests_failed=$((tests_failed + 1))
    echo "  FAIL: Could not collect metrics during error test"
fi

# Clean up error trigger processes
for pid in "${error_trigger_pids[@]}"; do
    kill $pid 2>/dev/null || true
done
wait 2>/dev/null || true

# Test 3: Metrics stability under sustained load
echo "Test 3: Metrics stability under sustained load"
total_tests=$((total_tests + 1))

echo "  Running sustained load test for ${NOISE_TEST_DURATION}s..."

# Create sustained background load
load_pid=""
{
    for i in $(seq 1 $NOISE_TEST_DURATION); do
        # Valid SOCKS connections
        echo "test" | timeout 1 nc 127.0.0.1 22080 >/dev/null 2>&1 || true
        # Small delay between requests
        sleep 0.5
    done
} &
load_pid=$!

# Monitor metrics periodically during load
metrics_samples=()
for sample in $(seq 1 3); do
    sleep $((NOISE_TEST_DURATION / 3))
    if sample_metrics=$(curl -s "http://127.0.0.1:$METRICS_PORT/metrics" 2>/dev/null); then
        sample_count=$(echo "$sample_metrics" | grep -c "^[a-zA-Z]" || echo "0")
        metrics_samples+=($sample_count)
        echo "  Sample $sample: $sample_count metrics"
    else
        metrics_samples+=(0)
        echo "  Sample $sample: FAILED"
    fi
done

# Wait for load test completion
wait $load_pid 2>/dev/null || true

# Analyze metrics stability
if [[ ${#metrics_samples[@]} -eq 3 ]]; then
    # Check that metric counts are stable (within reasonable variance)
    max_sample=$(printf '%s\n' "${metrics_samples[@]}" | sort -n | tail -1)
    min_sample=$(printf '%s\n' "${metrics_samples[@]}" | sort -n | head -1)
    variance=$((max_sample - min_sample))

    if [[ $variance -le 10 ]]; then  # Allow small variance
        test_results["metrics_stability"]="PASS"
        tests_passed=$((tests_passed + 1))
        echo "  PASS: Metrics stable (variance: $variance)"
    else
        test_results["metrics_stability"]="PARTIAL"
        tests_failed=$((tests_failed + 1))
        echo "  PARTIAL: High metrics variance ($variance)"
    fi
else
    test_results["metrics_stability"]="FAIL"
    tests_failed=$((tests_failed + 1))
    echo "  FAIL: Could not collect sufficient samples"
fi

# Test 4: Memory leak detection in metrics system
echo "Test 4: Memory leak detection"
total_tests=$((total_tests + 1))

if command -v ps >/dev/null 2>&1; then
    # Get initial memory usage
    initial_rss=$(ps -p $singbox_pid -o rss --no-headers 2>/dev/null || echo "0")

    # Generate additional load to test for memory leaks
    echo "  Testing for memory leaks..."
    for i in $(seq 1 20); do
        curl -s "http://127.0.0.1:$METRICS_PORT/metrics" >/dev/null 2>&1 || true
        sleep 0.1
    done

    # Check final memory usage
    final_rss=$(ps -p $singbox_pid -o rss --no-headers 2>/dev/null || echo "0")
    memory_growth=$((final_rss - initial_rss))

    if [[ $memory_growth -lt 1024 ]]; then  # Less than 1MB growth
        test_results["memory_leak"]="PASS"
        tests_passed=$((tests_passed + 1))
        echo "  PASS: Memory stable (growth: ${memory_growth}KB)"
    else
        test_results["memory_leak"]="PARTIAL"
        tests_failed=$((tests_failed + 1))
        echo "  PARTIAL: Memory growth detected (${memory_growth}KB)"
    fi
else
    test_results["memory_leak"]="SKIP"
    echo "  SKIP: ps command not available"
fi

# Test 5: Noise reduction regression check
echo "Test 5: Noise reduction regression verification"
total_tests=$((total_tests + 1))

# This test verifies that the rate limiting implementation is working
# by checking that repeated errors don't flood the metrics
rapid_error_start=$(date +%s)

# Generate rapid error conditions
for i in $(seq 1 50); do
    timeout 0.1 nc 127.0.0.1 99999 >/dev/null 2>&1 || true
done

rapid_error_end=$(date +%s)
error_duration=$((rapid_error_end - rapid_error_start))

# Check that the system remained responsive during error burst
if post_error_metrics=$(curl -s "http://127.0.0.1:$METRICS_PORT/metrics" 2>/dev/null); then
    response_time=$(timeout 5 time curl -s "http://127.0.0.1:$METRICS_PORT/metrics" >/dev/null 2>&1 && echo "OK" || echo "TIMEOUT")

    if [[ "$response_time" = "OK" ]]; then
        test_results["noise_regression"]="PASS"
        tests_passed=$((tests_passed + 1))
        echo "  PASS: System responsive after error burst (${error_duration}s)"
    else
        test_results["noise_regression"]="FAIL"
        tests_failed=$((tests_failed + 1))
        echo "  FAIL: System unresponsive after error burst"
    fi
else
    test_results["noise_regression"]="FAIL"
    tests_failed=$((tests_failed + 1))
    echo "  FAIL: Metrics endpoint failed after error burst"
fi

# Generate comprehensive results
{
    echo "{"
    echo "  \"timestamp\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\","
    echo "  \"test_config\": {"
    echo "    \"noise_test_duration\": $NOISE_TEST_DURATION,"
    echo "    \"metrics_port\": $METRICS_PORT"
    echo "  },"
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
    echo "  },"
    echo "  \"performance_notes\": {"
    echo "    \"baseline_metric_count\": $(echo "$baseline_metrics" | grep -c "^[a-zA-Z]" || echo "0"),"
    echo "    \"metrics_stability_samples\": [$(IFS=','; echo "${metrics_samples[*]}")],"
    echo "    \"memory_growth_kb\": $memory_growth,"
    echo "    \"error_burst_duration_s\": $error_duration"
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

# Cleanup
kill $singbox_pid 2>/dev/null || true

# Determine exit code
if [[ $tests_failed -eq 0 ]]; then
    echo "SUCCESS: All noise reduction tests passed"
    exit 0
else
    echo "PARTIAL: $tests_failed tests failed"
    exit 1
fi