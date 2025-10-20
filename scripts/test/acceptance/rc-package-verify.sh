#!/bin/bash
# A5: RC package verification and release readiness check
#
# Exit codes:
# 0 - All verification checks passed, RC ready
# 1 - Some checks failed, manual review needed
# 2 - Critical failure, RC not viable
# 77 - Skipped (build artifacts not available)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Configuration
E2E_DIR="$PROJECT_ROOT/.e2e"
RUST_BIN="$PROJECT_ROOT/target/debug/app"
RELEASE_BIN="$PROJECT_ROOT/target/release/app"
RESULTS_FILE="$E2E_DIR/rc_verification_results.json"

echo "=== A5: RC Package Verification ==="

# Create results directory
mkdir -p "$E2E_DIR"

# Results tracking
declare -A verification_results
total_checks=0
checks_passed=0
checks_failed=0
critical_failures=0

# Check 1: Build artifact availability
echo "Check 1: Build artifact availability"
total_checks=$((total_checks + 1))

if [[ -x "$RUST_BIN" ]]; then
    verification_results["debug_binary"]="PASS"
    checks_passed=$((checks_passed + 1))
    echo "  PASS: Debug binary available"
else
    verification_results["debug_binary"]="FAIL"
    checks_failed=$((checks_failed + 1))
    critical_failures=$((critical_failures + 1))
    echo "  FAIL: Debug binary missing"
fi

# Check for release binary (optional but recommended)
if [[ -x "$RELEASE_BIN" ]]; then
    verification_results["release_binary"]="PASS"
    echo "  INFO: Release binary available"
else
    verification_results["release_binary"]="SKIP"
    echo "  INFO: Release binary not built (optional)"
fi

# Early exit if no binary available
if [[ $critical_failures -gt 0 ]]; then
    echo "CRITICAL: No executable binary found"
    echo '{"status":"critical","reason":"no_binary","timestamp":"'$(date -u +%Y-%m-%dT%H:%M:%SZ)'"}' > "$RESULTS_FILE"
    exit 2
fi

# Check 2: Version consistency
echo "Check 2: Version information consistency"
total_checks=$((total_checks + 1))

if version_output=$("$RUST_BIN" version --format json 2>/dev/null); then
    version_string=$(echo "$version_output" | jq -r '.version // "unknown"' 2>/dev/null || echo "parse_error")
    build_info=$(echo "$version_output" | jq -r '.build_info // "unknown"' 2>/dev/null || echo "parse_error")

    if [[ "$version_string" != "unknown" && "$version_string" != "parse_error" ]]; then
        verification_results["version_info"]="PASS"
        checks_passed=$((checks_passed + 1))
        echo "  PASS: Version info available ($version_string)"
        echo "  Build: $build_info"
    else
        verification_results["version_info"]="FAIL"
        checks_failed=$((checks_failed + 1))
        echo "  FAIL: Version info malformed"
    fi
else
    verification_results["version_info"]="FAIL"
    checks_failed=$((checks_failed + 1))
    echo "  FAIL: Version command failed"
fi

# Check 3: CLI contract validation
echo "Check 3: CLI JSON contract validation"
total_checks=$((total_checks + 1))

# Create minimal test config
test_config=$(cat <<'EOF'
{
  "inbounds": [
    {"type": "socks", "listen": "127.0.0.1", "port": 23080}
  ],
  "outbounds": [
    {"type": "direct"}
  ]
}
EOF
)

config_file=$(mktemp)
echo "$test_config" > "$config_file"
trap "rm -f '$config_file'" EXIT

# Test check command
if check_output=$("$RUST_BIN" check -c "$config_file" --format json 2>/dev/null); then
    if echo "$check_output" | jq -e '.status' >/dev/null 2>&1; then
        verification_results["cli_check"]="PASS"
        checks_passed=$((checks_passed + 1))
        echo "  PASS: CLI check command works"
    else
        verification_results["cli_check"]="PARTIAL"
        checks_failed=$((checks_failed + 1))
        echo "  PARTIAL: CLI check output not properly formatted"
    fi
else
    verification_results["cli_check"]="FAIL"
    checks_failed=$((checks_failed + 1))
    echo "  FAIL: CLI check command failed"
fi

# Test route explain command
if explain_output=$("$RUST_BIN" route explain -c "$config_file" --target "example.com:80" --format json 2>/dev/null); then
    if echo "$explain_output" | jq -e '.dest' >/dev/null 2>&1; then
        verification_results["cli_explain"]="PASS"
        checks_passed=$((checks_passed + 1))
        echo "  PASS: CLI explain command works"
    else
        verification_results["cli_explain"]="PARTIAL"
        checks_failed=$((checks_failed + 1))
        echo "  PARTIAL: CLI explain output not properly formatted"
    fi
else
    verification_results["cli_explain"]="FAIL"
    checks_failed=$((checks_failed + 1))
    echo "  FAIL: CLI explain command failed"
fi

# Check 4: Dependencies and feature availability
echo "Check 4: Feature completeness check"
total_checks=$((total_checks + 1))

# Check help output for key features
if help_output=$("$RUST_BIN" --help 2>/dev/null); then
    expected_commands=("run" "check" "route" "version")
    missing_commands=()

    for cmd in "${expected_commands[@]}"; do
        if ! echo "$help_output" | grep -q "$cmd"; then
            missing_commands+=("$cmd")
        fi
    done

    if [[ ${#missing_commands[@]} -eq 0 ]]; then
        verification_results["feature_completeness"]="PASS"
        checks_passed=$((checks_passed + 1))
        echo "  PASS: All expected commands available"
    else
        verification_results["feature_completeness"]="FAIL"
        checks_failed=$((checks_failed + 1))
        echo "  FAIL: Missing commands: ${missing_commands[*]}"
    fi
else
    verification_results["feature_completeness"]="FAIL"
    checks_failed=$((checks_failed + 1))
    echo "  FAIL: Help command failed"
fi

# Check 5: Runtime stability test
echo "Check 5: Runtime stability verification"
total_checks=$((total_checks + 1))

echo "  Starting runtime stability test..."

# Start singbox with test config
"$RUST_BIN" run -c "$config_file" &
runtime_pid=$!
trap "kill $runtime_pid 2>/dev/null || true; rm -f '$config_file'" EXIT

# Give it time to start
sleep 2

# Verify it's running
if kill -0 $runtime_pid 2>/dev/null; then
    verification_results["runtime_stability"]="PASS"
    checks_passed=$((checks_passed + 1))
    echo "  PASS: Runtime starts and remains stable"

    # Get basic process info
    if command -v ps >/dev/null 2>&1; then
        process_info=$(ps -p $runtime_pid -o pcpu,pmem,rss --no-headers 2>/dev/null || echo "0.0 0.0 0")
        echo "  Runtime info: $process_info"
    fi
else
    verification_results["runtime_stability"]="FAIL"
    checks_failed=$((checks_failed + 1))
    critical_failures=$((critical_failures + 1))
    echo "  FAIL: Runtime failed to start or crashed"
fi

# Stop the runtime
kill $runtime_pid 2>/dev/null || true
wait $runtime_pid 2>/dev/null || true

# Check 6: Integration with acceptance tests
echo "Check 6: Acceptance test integration status"
total_checks=$((total_checks + 1))

acceptance_scripts=("A1_explain_replay.sh" "A2_schema_v2_acceptance.sh" "A3_udp_stress_metrics.sh" "A4_prom_noise_regression.sh")
available_scripts=0

for script in "${acceptance_scripts[@]}"; do
    if [[ -x "$SCRIPT_DIR/$script" ]]; then
        available_scripts=$((available_scripts + 1))
    fi
done

if [[ $available_scripts -eq ${#acceptance_scripts[@]} ]]; then
    verification_results["acceptance_integration"]="PASS"
    checks_passed=$((checks_passed + 1))
    echo "  PASS: All acceptance scripts available ($available_scripts/${#acceptance_scripts[@]})"
else
    verification_results["acceptance_integration"]="PARTIAL"
    checks_failed=$((checks_failed + 1))
    echo "  PARTIAL: Missing acceptance scripts ($available_scripts/${#acceptance_scripts[@]})"
fi

# Check 7: Build reproducibility
echo "Check 7: Build configuration verification"
total_checks=$((total_checks + 1))

if [[ -f "$PROJECT_ROOT/rust-toolchain.toml" ]]; then
    toolchain_version=$(grep -E '^channel.*=.*' "$PROJECT_ROOT/rust-toolchain.toml" | cut -d'"' -f2 2>/dev/null || echo "unknown")
    if [[ "$toolchain_version" == "1.90.0" ]]; then
        verification_results["build_config"]="PASS"
        checks_passed=$((checks_passed + 1))
        echo "  PASS: Rust toolchain locked to $toolchain_version"
    else
        verification_results["build_config"]="FAIL"
        checks_failed=$((checks_failed + 1))
        echo "  FAIL: Unexpected toolchain version: $toolchain_version"
    fi
else
    verification_results["build_config"]="FAIL"
    checks_failed=$((checks_failed + 1))
    echo "  FAIL: No rust-toolchain.toml found"
fi

# Check 8: Documentation completeness
echo "Check 8: Essential documentation check"
total_checks=$((total_checks + 1))

essential_docs=("README.md" "Cargo.toml")
missing_docs=()

for doc in "${essential_docs[@]}"; do
    if [[ ! -f "$PROJECT_ROOT/$doc" ]]; then
        missing_docs+=("$doc")
    fi
done

if [[ ${#missing_docs[@]} -eq 0 ]]; then
    verification_results["documentation"]="PASS"
    checks_passed=$((checks_passed + 1))
    echo "  PASS: Essential documentation present"
else
    verification_results["documentation"]="PARTIAL"
    checks_failed=$((checks_failed + 1))
    echo "  PARTIAL: Missing docs: ${missing_docs[*]}"
fi

# Aggregate previous test results if available
echo "Check 9: Previous acceptance test aggregation"
total_checks=$((total_checks + 1))

previous_results=()
for result_file in "$E2E_DIR"/*_results.json; do
    if [[ -f "$result_file" && "$result_file" != "$RESULTS_FILE" ]]; then
        if result_status=$(jq -r '.status // "unknown"' "$result_file" 2>/dev/null); then
            previous_results+=("$(basename "$result_file"):$result_status")
        fi
    fi
done

if [[ ${#previous_results[@]} -gt 0 ]]; then
    failed_tests=$(printf '%s\n' "${previous_results[@]}" | grep -c "fail\|partial" || echo "0")
    if [[ $failed_tests -eq 0 ]]; then
        verification_results["previous_tests"]="PASS"
        checks_passed=$((checks_passed + 1))
        echo "  PASS: All previous acceptance tests passed"
    else
        verification_results["previous_tests"]="PARTIAL"
        checks_failed=$((checks_failed + 1))
        echo "  PARTIAL: $failed_tests previous tests had issues"
    fi
    echo "  Previous results: ${previous_results[*]}"
else
    verification_results["previous_tests"]="SKIP"
    echo "  SKIP: No previous test results found"
fi

# Calculate overall RC readiness score
readiness_score=$(awk "BEGIN {printf \"%.1f\", $checks_passed/$total_checks*100}")
critical_score=$(awk "BEGIN {printf \"%.1f\", ($total_checks-$critical_failures)/$total_checks*100}")

# Determine RC status
rc_status="unknown"
if [[ $critical_failures -gt 0 ]]; then
    rc_status="critical"
elif [[ $checks_failed -eq 0 ]]; then
    rc_status="ready"
elif [[ $readiness_score > 80 ]]; then
    rc_status="conditional"
else
    rc_status="not_ready"
fi

# Generate comprehensive verification report
{
    echo "{"
    echo "  \"timestamp\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\","
    echo "  \"rc_verification\": {"
    echo "    \"total_checks\": $total_checks,"
    echo "    \"checks_passed\": $checks_passed,"
    echo "    \"checks_failed\": $checks_failed,"
    echo "    \"critical_failures\": $critical_failures,"
    echo "    \"readiness_score\": $readiness_score,"
    echo "    \"critical_score\": $critical_score,"
    echo "    \"rc_status\": \"$rc_status\""
    echo "  },"
    echo "  \"verification_results\": {"
    first=true
    for check in "${!verification_results[@]}"; do
        if [[ "$first" = true ]]; then
            first=false
        else
            echo ","
        fi
        echo "    \"$check\": \"${verification_results[$check]}\""
    done
    echo ""
    echo "  },"
    echo "  \"build_info\": {"
    echo "    \"version\": \"$version_string\","
    echo "    \"build_details\": \"$build_info\","
    echo "    \"toolchain\": \"$toolchain_version\","
    echo "    \"debug_binary\": $([ -x "$RUST_BIN" ] && echo "true" || echo "false"),"
    echo "    \"release_binary\": $([ -x "$RELEASE_BIN" ] && echo "true" || echo "false")"
    echo "  },"
    echo "  \"recommendations\": ["
    if [[ $critical_failures -gt 0 ]]; then
        echo "    \"Critical failures must be resolved before RC release\","
    fi
    if [[ $checks_failed -gt 0 ]]; then
        echo "    \"Review failed checks and address before final release\","
    fi
    if [[ ! -x "$RELEASE_BIN" ]]; then
        echo "    \"Consider building release binary for performance verification\","
    fi
    echo "    \"Run full acceptance test suite (A1-A4) before release\""
    echo "  ]"
    echo "}"
} > "$RESULTS_FILE"

echo ""
echo "=== RC Verification Results ==="
echo "Total checks: $total_checks"
echo "Passed: $checks_passed"
echo "Failed: $checks_failed"
echo "Critical failures: $critical_failures"
echo "Readiness score: ${readiness_score}%"
echo "RC Status: $rc_status"
echo "Results saved to: $RESULTS_FILE"

# Cleanup
rm -f "$config_file"

# Determine exit code based on RC status
case "$rc_status" in
    "ready")
        echo "SUCCESS: RC package verification passed - Ready for release"
        exit 0
        ;;
    "conditional")
        echo "CONDITIONAL: RC package mostly ready - Minor issues need review"
        exit 1
        ;;
    "not_ready")
        echo "NOT READY: RC package has significant issues"
        exit 1
        ;;
    "critical")
        echo "CRITICAL: RC package has critical failures"
        exit 2
        ;;
    *)
        echo "UNKNOWN: RC verification status unclear"
        exit 2
        ;;
esac