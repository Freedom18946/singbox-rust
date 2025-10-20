#!/bin/bash
# A1: Go vs Rust `route --explain` compatibility replay testing
#
# Exit codes:
# 0 - All tests passed
# 1 - Some tests failed but system is functional
# 2 - Critical failure or setup error
# 77 - Skipped (GO_SINGBOX_BIN not available)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Source common utilities
source "$SCRIPT_DIR/lib/prom_http.sh"

# Configuration
E2E_DIR="$PROJECT_ROOT/.e2e"
RUST_BIN="$PROJECT_ROOT/target/debug/app"
GO_BIN="${GO_SINGBOX_BIN:-}"

# Output files
RESULTS_FILE="$E2E_DIR/explain_replay_results.json"
COMPAT_FILE="$E2E_DIR/compat_subset.json"

echo "=== A1: Go vs Rust route --explain Replay Test ==="

# Check if rust binary exists
if [[ ! -x "$RUST_BIN" ]]; then
    echo "ERROR: Rust binary not found at $RUST_BIN"
    echo "Run 'cargo build' first"
    exit 2
fi

# Check for Go binary
if [[ -z "$GO_BIN" ]]; then
    echo "SKIP: GO_SINGBOX_BIN not set, Go compatibility test skipped"
    echo '{"status":"skipped","reason":"no_go_binary","timestamp":"'$(date -u +%Y-%m-%dT%H:%M:%SZ)'"}' > "$RESULTS_FILE"
    exit 77
fi

if [[ ! -x "$GO_BIN" ]]; then
    echo "SKIP: GO_SINGBOX_BIN ($GO_BIN) not executable"
    echo '{"status":"skipped","reason":"go_binary_not_executable","timestamp":"'$(date -u +%Y-%m-%dT%H:%M:%SZ)'"}' > "$RESULTS_FILE"
    exit 77
fi

# Create test configuration
TEST_CONFIG=$(cat <<'EOF'
{
  "route": {
    "rules": [
      {"domain": ["example.com"], "outbound": "proxy"},
      {"ip_cidr": ["192.168.1.0/24"], "outbound": "direct"},
      {"port": [80, 443], "outbound": "proxy"},
      {"protocol": ["tcp"], "outbound": "direct"}
    ],
    "default": "direct"
  },
  "outbounds": [
    {"tag": "direct", "type": "direct"},
    {"tag": "proxy", "type": "socks", "server": "127.0.0.1", "server_port": 1080}
  ]
}
EOF
)

# Test targets for explain
TEST_TARGETS=(
    "example.com:80"
    "192.168.1.10:443"
    "google.com:53"
    "192.168.2.1:8080"
)

# Results tracking
declare -A rust_results
declare -A go_results
compatibility_issues=0
total_tests=0

# Create temporary config file
config_file=$(mktemp)
echo "$TEST_CONFIG" > "$config_file"
trap "rm -f '$config_file'" EXIT

echo "Testing route explain compatibility..."

for target in "${TEST_TARGETS[@]}"; do
    echo "Testing target: $target"
    total_tests=$((total_tests + 1))

    # Test Rust implementation
    if rust_output=$("$RUST_BIN" route explain -c "$config_file" --target "$target" --format json 2>/dev/null); then
        rust_results["$target"]="$rust_output"
        echo "  Rust: OK"
    else
        rust_results["$target"]='{"error":"rust_failed"}'
        echo "  Rust: FAILED"
    fi

    # Test Go implementation
    if go_output=$("$GO_BIN" route explain -c "$config_file" --target "$target" --format json 2>/dev/null); then
        go_results["$target"]="$go_output"
        echo "  Go: OK"
    else
        go_results["$target"]='{"error":"go_failed"}'
        echo "  Go: FAILED"
    fi

    # Compare results (simplified compatibility check)
    rust_dest=$(echo "${rust_results["$target"]}" | jq -r '.dest // "unknown"' 2>/dev/null || echo "parse_error")
    go_dest=$(echo "${go_results["$target"]}" | jq -r '.dest // "unknown"' 2>/dev/null || echo "parse_error")

    if [[ "$rust_dest" != "$go_dest" ]]; then
        compatibility_issues=$((compatibility_issues + 1))
        echo "  COMPAT: ISSUE - Rust dest: $rust_dest, Go dest: $go_dest"
    else
        echo "  COMPAT: OK"
    fi
done

# Generate compatibility report
{
    echo "{"
    echo "  \"timestamp\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\","
    echo "  \"total_tests\": $total_tests,"
    echo "  \"compatibility_issues\": $compatibility_issues,"
    echo "  \"status\": \"$([ $compatibility_issues -eq 0 ] && echo "pass" || echo "partial")\","
    echo "  \"targets\": ["
    first=true
    for target in "${TEST_TARGETS[@]}"; do
        if [[ "$first" = true ]]; then
            first=false
        else
            echo ","
        fi
        echo "    {"
        echo "      \"target\": \"$target\","
        echo "      \"rust_result\": $(echo "${rust_results["$target"]}" | jq -c .),"
        echo "      \"go_result\": $(echo "${go_results["$target"]}" | jq -c .)"
        echo -n "    }"
    done
    echo ""
    echo "  ]"
    echo "}"
} > "$RESULTS_FILE"

# Create subset compatibility file for further analysis
{
    echo "{"
    echo "  \"format_version\": \"1.0\","
    echo "  \"comparison_results\": ["
    first=true
    for target in "${TEST_TARGETS[@]}"; do
        if [[ "$first" = true ]]; then
            first=false
        else
            echo ","
        fi
        echo "    {"
        echo "      \"target\": \"$target\","
        echo "      \"rust\": $(echo "${rust_results["$target"]}" | jq -c .),"
        echo "      \"go\": $(echo "${go_results["$target"]}" | jq -c .)"
        echo -n "    }"
    done
    echo ""
    echo "  ]"
    echo "}"
} > "$COMPAT_FILE"

echo ""
echo "=== Results ==="
echo "Total tests: $total_tests"
echo "Compatibility issues: $compatibility_issues"
echo "Results saved to: $RESULTS_FILE"
echo "Compatibility data: $COMPAT_FILE"

# Determine exit code
if [[ $compatibility_issues -eq 0 ]]; then
    echo "SUCCESS: All compatibility tests passed"
    exit 0
else
    echo "PARTIAL: $compatibility_issues compatibility issues found"
    exit 1
fi