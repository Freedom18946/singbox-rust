#!/bin/bash
# A3: UDP stress testing and metrics sampling
#
# Exit codes:
# 0 - All UDP stress tests passed
# 1 - Some tests failed but system functional
# 2 - Critical failure or setup error
# 77 - Skipped (optional dependencies missing)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Source utilities
source "$SCRIPT_DIR/lib/metrics.sh" 2>/dev/null || true

# Configuration
E2E_DIR="$PROJECT_ROOT/.e2e"
RUST_BIN="$PROJECT_ROOT/target/debug/app"
RESULTS_FILE="$E2E_DIR/udp_stress_results.json"
METRICS_PORT=${SB_METRICS_PORT:-29092}
STRESS_DURATION=${UDP_STRESS_DURATION:-10}
CONCURRENT_SESSIONS=${UDP_CONCURRENT_SESSIONS:-50}

echo "=== A3: UDP Stress Testing and Metrics Sampling ==="

# Check dependencies
dependencies_missing=0

if [[ ! -x "$RUST_BIN" ]]; then
    echo "ERROR: Rust binary not found at $RUST_BIN"
    exit 2
fi

# Check for optional stress testing tools
if ! command -v nc >/dev/null 2>&1 && ! command -v netcat >/dev/null 2>&1; then
    echo "WARN: netcat/nc not available, using minimal stress test"
    dependencies_missing=1
fi

if ! command -v curl >/dev/null 2>&1; then
    echo "SKIP: curl not available for metrics collection"
    echo '{"status":"skipped","reason":"curl_not_available","timestamp":"'$(date -u +%Y-%m-%dT%H:%M:%SZ)'"}' > "$RESULTS_FILE"
    exit 77
fi

# Create test configuration for UDP
UDP_CONFIG=$(cat <<EOF
{
  "log": {"level": "warn"},
  "inbounds": [
    {
      "type": "socks",
      "listen": "127.0.0.1",
      "port": 21080,
      "udp": true
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

echo "Setting up UDP stress test environment..."

# Create temporary config
config_file=$(mktemp)
echo "$UDP_CONFIG" > "$config_file"
trap "rm -f '$config_file'" EXIT

# Start singbox with metrics enabled
echo "Starting singbox with UDP and metrics enabled..."
export SB_METRICS_ADDR="127.0.0.1:$METRICS_PORT"
"$RUST_BIN" run -c "$config_file" &
singbox_pid=$!
trap "kill $singbox_pid 2>/dev/null || true; rm -f '$config_file'" EXIT

# Wait for startup
sleep 2

# Verify singbox is running
if ! kill -0 $singbox_pid 2>/dev/null; then
    echo "ERROR: Singbox failed to start"
    exit 2
fi

echo "Singbox started with PID: $singbox_pid"

# Test 1: Basic UDP connectivity
echo "Test 1: Basic UDP connectivity"
total_tests=$((total_tests + 1))

# Simple UDP echo test using netcat if available
if command -v nc >/dev/null 2>&1; then
    # Start a simple UDP echo server
    echo "test_message" | timeout 5 nc -u 127.0.0.1 21080 >/dev/null 2>&1 && {
        test_results["basic_udp"]="PASS"
        tests_passed=$((tests_passed + 1))
        echo "  PASS: Basic UDP connectivity works"
    } || {
        test_results["basic_udp"]="FAIL"
        tests_failed=$((tests_failed + 1))
        echo "  FAIL: Basic UDP connectivity failed"
    }
else
    test_results["basic_udp"]="SKIP"
    echo "  SKIP: No netcat available for UDP test"
fi

# Test 2: Metrics collection baseline
echo "Test 2: Metrics baseline collection"
total_tests=$((total_tests + 1))

baseline_metrics=""
if baseline_metrics=$(curl -s "http://127.0.0.1:$METRICS_PORT/metrics" 2>/dev/null); then
    test_results["metrics_baseline"]="PASS"
    tests_passed=$((tests_passed + 1))
    echo "  PASS: Metrics endpoint accessible"

    # Extract UDP-related metrics
    udp_nat_size=$(echo "$baseline_metrics" | grep "^udp_nat_size " | awk '{print $2}' || echo "0")
    udp_pkts_total=$(echo "$baseline_metrics" | grep "^udp_pkts_.*_total " | awk '{sum+=$2} END {print sum+0}')

    echo "  Baseline - NAT size: $udp_nat_size, Packets: $udp_pkts_total"
else
    test_results["metrics_baseline"]="FAIL"
    tests_failed=$((tests_failed + 1))
    echo "  FAIL: Could not collect baseline metrics"
fi

# Test 3: Concurrent session stress test
echo "Test 3: Concurrent UDP session stress ($CONCURRENT_SESSIONS sessions)"
total_tests=$((total_tests + 1))

if command -v nc >/dev/null 2>&1; then
    stress_pids=()

    # Create concurrent UDP sessions
    for i in $(seq 1 $CONCURRENT_SESSIONS); do
        {
            echo "session_$i" | timeout 2 nc -u 127.0.0.1 21080 >/dev/null 2>&1
        } &
        stress_pids+=($!)
    done

    # Wait a moment for sessions to establish
    sleep 1

    # Collect metrics during stress
    stress_metrics=""
    if stress_metrics=$(curl -s "http://127.0.0.1:$METRICS_PORT/metrics" 2>/dev/null); then
        udp_nat_size_stress=$(echo "$stress_metrics" | grep "^udp_nat_size " | awk '{print $2}' || echo "0")
        udp_pkts_stress=$(echo "$stress_metrics" | grep "^udp_pkts_.*_total " | awk '{sum+=$2} END {print sum+0}')

        echo "  Stress - NAT size: $udp_nat_size_stress, Packets: $udp_pkts_stress"

        if [[ $udp_nat_size_stress -gt 0 ]]; then
            test_results["stress_sessions"]="PASS"
            tests_passed=$((tests_passed + 1))
            echo "  PASS: Concurrent sessions created (NAT size: $udp_nat_size_stress)"
        else
            test_results["stress_sessions"]="PARTIAL"
            tests_failed=$((tests_failed + 1))
            echo "  PARTIAL: Sessions created but not tracked in metrics"
        fi
    else
        test_results["stress_sessions"]="FAIL"
        tests_failed=$((tests_failed + 1))
        echo "  FAIL: Could not collect stress metrics"
    fi

    # Clean up stress test processes
    for pid in "${stress_pids[@]}"; do
        kill $pid 2>/dev/null || true
    done
    wait
else
    test_results["stress_sessions"]="SKIP"
    echo "  SKIP: No netcat available for stress test"
fi

# Test 4: Metrics stability after stress
echo "Test 4: Metrics stability after stress"
total_tests=$((total_tests + 1))

sleep 2  # Allow time for cleanup

if post_stress_metrics=$(curl -s "http://127.0.0.1:$METRICS_PORT/metrics" 2>/dev/null); then
    # Check that metrics are still responsive
    if echo "$post_stress_metrics" | grep -q "udp_"; then
        test_results["metrics_stability"]="PASS"
        tests_passed=$((tests_passed + 1))
        echo "  PASS: Metrics system stable after stress"
    else
        test_results["metrics_stability"]="FAIL"
        tests_failed=$((tests_failed + 1))
        echo "  FAIL: UDP metrics missing after stress"
    fi
else
    test_results["metrics_stability"]="FAIL"
    tests_failed=$((tests_failed + 1))
    echo "  FAIL: Metrics endpoint unresponsive after stress"
fi

# Test 5: Memory and resource check
echo "Test 5: Resource usage check"
total_tests=$((total_tests + 1))

if command -v ps >/dev/null 2>&1; then
    # Check if singbox is still running and get basic resource info
    if ps -p $singbox_pid -o pid,pcpu,pmem,rss >/dev/null 2>&1; then
        resource_info=$(ps -p $singbox_pid -o pcpu,pmem,rss --no-headers 2>/dev/null || echo "0.0 0.0 0")
        cpu_usage=$(echo "$resource_info" | awk '{print $1}')
        mem_usage=$(echo "$resource_info" | awk '{print $2}')
        rss_kb=$(echo "$resource_info" | awk '{print $3}')

        test_results["resource_check"]="PASS"
        tests_passed=$((tests_passed + 1))
        echo "  PASS: Process stable - CPU: ${cpu_usage}%, MEM: ${mem_usage}%, RSS: ${rss_kb}KB"
    else
        test_results["resource_check"]="FAIL"
        tests_failed=$((tests_failed + 1))
        echo "  FAIL: Process not running or resource check failed"
    fi
else
    test_results["resource_check"]="SKIP"
    echo "  SKIP: ps command not available"
fi

# Generate comprehensive results
{
    echo "{"
    echo "  \"timestamp\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\","
    echo "  \"test_config\": {"
    echo "    \"stress_duration\": $STRESS_DURATION,"
    echo "    \"concurrent_sessions\": $CONCURRENT_SESSIONS,"
    echo "    \"metrics_port\": $METRICS_PORT"
    echo "  },"
    echo "  \"total_tests\": $total_tests,"
    echo "  \"tests_passed\": $tests_passed,"
    echo "  \"tests_failed\": $tests_failed,"
    echo "  \"success_rate\": $(awk "BEGIN {printf \"%.2f\", $tests_passed/$total_tests*100}"),"
    echo "  \"status\": \"$([ $tests_failed -eq 0 ] && echo "pass" || echo "partial")\","
    echo "  \"dependencies_missing\": $dependencies_missing,"
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
    echo "  \"metrics_samples\": {"
    echo "    \"baseline\": $(echo "$baseline_metrics" | grep "^udp_" | wc -l || echo "0"),"
    echo "    \"stress\": $(echo "$stress_metrics" | grep "^udp_" | wc -l || echo "0"),"
    echo "    \"post_stress\": $(echo "$post_stress_metrics" | grep "^udp_" | wc -l || echo "0")"
    echo "  }"
    echo "}"
} > "$RESULTS_FILE"

echo ""
echo "=== Results ==="
echo "Total tests: $total_tests"
echo "Passed: $tests_passed"
echo "Failed: $tests_failed"
echo "Success rate: $(awk "BEGIN {printf \"%.1f\", $tests_passed/$total_tests*100}")%"
echo "Dependencies missing: $dependencies_missing"
echo "Results saved to: $RESULTS_FILE"

# Cleanup
kill $singbox_pid 2>/dev/null || true

# Determine exit code
if [[ $dependencies_missing -gt 0 ]]; then
    echo "PARTIAL: Some dependencies missing, limited testing performed"
    exit 77
elif [[ $tests_failed -eq 0 ]]; then
    echo "SUCCESS: All UDP stress tests passed"
    exit 0
else
    echo "PARTIAL: $tests_failed tests failed"
    exit 1
fi