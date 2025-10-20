#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

# Performance baseline recorder and regression guard
# Usage: scripts/bench-guard.sh record|check

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
BASELINE_FILE="$ROOT_DIR/baseline.json"
TOLERANCE="${BENCH_GUARD_TOL:-0.10}"

usage() {
    echo "Usage: $0 record|check [--features FEATURES]"
    echo ""
    echo "  record    Record new baseline to baseline.json"
    echo "  check     Check current performance against baseline"
    echo ""
    echo "Environment variables:"
    echo "  BENCH_GUARD_TOL    Tolerance threshold (default: 0.10 = ±10%)"
    echo ""
    echo "Exit codes:"
    echo "  0: Success (check: within tolerance)"
    echo "  1: General error"
    echo "  2: Parsing/setup failure"
    echo "  3: Performance regression (check only)"
    exit 1
}

if [ $# -lt 1 ]; then
    usage
fi

MODE="$1"
shift

# Parse additional arguments
EXTRA_FEATURES=""
while [ $# -gt 0 ]; do
    case $1 in
        --features)
            EXTRA_FEATURES="$2"
            shift 2
            ;;
        *)
            echo "Unknown option: $1" >&2
            usage
            ;;
    esac
done

if [ "$MODE" != "record" ] && [ "$MODE" != "check" ]; then
    echo "Error: Mode must be 'record' or 'check'" >&2
    usage
fi

# Gather system information
get_machine_info() {
    local cpu_model cores mem_gb

    if command -v sysctl >/dev/null 2>&1; then
        # macOS
        cpu_model=$(sysctl -n machdep.cpu.brand_string 2>/dev/null || echo "unknown")
        cores=$(sysctl -n hw.ncpu 2>/dev/null || echo "unknown")
        mem_bytes=$(sysctl -n hw.memsize 2>/dev/null || echo "0")
        mem_gb=$((mem_bytes / 1024 / 1024 / 1024))
    elif [ -f /proc/cpuinfo ] && [ -f /proc/meminfo ]; then
        # Linux
        cpu_model=$(grep "model name" /proc/cpuinfo | head -1 | cut -d: -f2 | sed 's/^ *//' || echo "unknown")
        cores=$(nproc 2>/dev/null || echo "unknown")
        mem_kb=$(grep "MemTotal" /proc/meminfo | awk '{print $2}' || echo "0")
        mem_gb=$((mem_kb / 1024 / 1024))
    else
        cpu_model="unknown"
        cores="unknown"
        mem_gb="unknown"
    fi

    echo "\"$cpu_model\",$cores,$mem_gb"
}

get_git_info() {
    local git_sha
    if command -v git >/dev/null 2>&1 && [ -d "$ROOT_DIR/.git" ]; then
        git_sha=$(cd "$ROOT_DIR" && git rev-parse --short HEAD 2>/dev/null || echo "unknown")
    else
        git_sha="unknown"
    fi
    echo "$git_sha"
}

get_rustc_version() {
    rustc --version 2>/dev/null || echo "rustc unknown"
}

# Run cargo bench and parse bencher format output
run_bench() {
    echo "[bench-guard] Running cargo bench..." >&2

    local temp_output bench_features
    temp_output=$(mktemp)

    # Build feature flags - use minimal features for benchmarks
    local bench_cmd
    if [ -n "$EXTRA_FEATURES" ]; then
        bench_cmd="cargo bench --features \"router,$EXTRA_FEATURES\" -- --output-format bencher"
    else
        bench_cmd="cargo bench --features router -- --output-format bencher"
    fi

    # Run cargo bench with bencher output format
    if ! (cd "$ROOT_DIR" && eval "$bench_cmd") > "$temp_output" 2>&1; then
        echo "[bench-guard] Error: cargo bench failed" >&2
        cat "$temp_output" >&2
        rm -f "$temp_output"
        exit 2
    fi

    # Parse bencher output for key metrics
    # Format: test bench_name ... bench: 1,234 ns/iter (+/- 56)
    local cases_json=""
    while read -r line; do
        if [[ "$line" =~ test.*bench:.*ns/iter ]]; then
            local name value unit
            name=$(echo "$line" | sed 's/test \([^ ]*\).*/\1/')
            value=$(echo "$line" | sed 's/.*bench:[[:space:]]*\([0-9,]*\).*/\1/' | tr -d ',')
            unit="ns/iter"

            if [ -n "$cases_json" ]; then
                cases_json="$cases_json,"
            fi
            cases_json="$cases_json{\"name\":\"$name\",\"value\":$value,\"unit\":\"$unit\"}"
        fi
    done < "$temp_output"

    rm -f "$temp_output"

    if [ -z "$cases_json" ]; then
        echo "[bench-guard] Error: No benchmark results found" >&2
        exit 2
    fi

    echo "[$cases_json]"
}

# Record baseline with metadata
record_baseline() {
    echo "[bench-guard] Recording baseline..." >&2

    local machine_info git_sha rustc_ver cases_json date_utc
    machine_info=$(get_machine_info)
    git_sha=$(get_git_info)
    rustc_ver=$(get_rustc_version)
    cases_json=$(run_bench)
    date_utc=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

    # Split machine info
    local cpu_model cores mem_gb
    IFS=',' read -r cpu_model cores mem_gb <<< "$machine_info"

    # Generate baseline JSON
    cat > "$BASELINE_FILE" << EOF
{
  "machine": {
    "cpu_model": $cpu_model,
    "cores": $cores,
    "mem_gb": $mem_gb
  },
  "date": "$date_utc",
  "git_short_sha": "$git_sha",
  "rustc_ver": "$rustc_ver",
  "cases": $cases_json
}
EOF

    echo "[bench-guard] Baseline recorded to: $BASELINE_FILE" >&2
    echo "[bench-guard] Recorded $(echo "$cases_json" | jq length) benchmark cases" >&2
}

# Check current performance against baseline
check_baseline() {
    echo "[bench-guard] Checking against baseline..." >&2

    if [ ! -f "$BASELINE_FILE" ]; then
        echo "[bench-guard] Error: baseline file not found: $BASELINE_FILE" >&2
        echo "[bench-guard] Run 'record' first to create baseline" >&2
        exit 2
    fi

    local current_cases baseline_cases
    current_cases=$(run_bench)

    if ! command -v jq >/dev/null 2>&1; then
        echo "[bench-guard] Error: jq is required for baseline comparison" >&2
        exit 2
    fi

    baseline_cases=$(jq -c '.cases' "$BASELINE_FILE" 2>/dev/null || {
        echo "[bench-guard] Error: Failed to parse baseline file" >&2
        exit 2
    })

    echo "[bench-guard] Comparing results (tolerance: ±$(echo "$TOLERANCE * 100" | bc -l)%)" >&2

    local failures=0
    local total_checks=0

    # Compare each case
    echo "$current_cases" | jq -c '.[]' | while read -r current_case; do
        local name current_value baseline_case baseline_value
        name=$(echo "$current_case" | jq -r '.name')
        current_value=$(echo "$current_case" | jq -r '.value')

        baseline_case=$(echo "$baseline_cases" | jq --arg name "$name" '.[] | select(.name == $name)' 2>/dev/null)
        if [ -z "$baseline_case" ]; then
            echo "[SKIP] $name: not found in baseline" >&2
            continue
        fi

        baseline_value=$(echo "$baseline_case" | jq -r '.value')

        if [ "$baseline_value" = "0" ] || [ "$baseline_value" = "null" ]; then
            echo "[SKIP] $name: baseline value is zero/null" >&2
            continue
        fi

        # Calculate percentage difference
        local diff_pct
        diff_pct=$(echo "scale=4; (($current_value - $baseline_value) / $baseline_value)" | bc -l)
        local abs_diff_pct
        abs_diff_pct=$(echo "$diff_pct" | sed 's/^-//')

        total_checks=$((total_checks + 1))

        if (( $(echo "$abs_diff_pct > $TOLERANCE" | bc -l) )); then
            echo "[FAIL] $name: baseline=$baseline_value current=$current_value diff=$(echo "$diff_pct * 100" | bc -l)%" >&2
            failures=$((failures + 1))
        else
            echo "[PASS] $name: baseline=$baseline_value current=$current_value diff=$(echo "$diff_pct * 100" | bc -l)%" >&2
        fi
    done

    # Check results (this runs in a subshell due to the pipe, so we need to return status differently)
    # We'll re-run the comparison in the main shell to get the actual count
    local actual_failures=0
    local actual_total=0

    while read -r current_case; do
        local name current_value baseline_case baseline_value
        name=$(echo "$current_case" | jq -r '.name')
        current_value=$(echo "$current_case" | jq -r '.value')

        baseline_case=$(echo "$baseline_cases" | jq --arg name "$name" '.[] | select(.name == $name)' 2>/dev/null)
        if [ -z "$baseline_case" ] || [ "$baseline_case" = "null" ]; then
            continue
        fi

        baseline_value=$(echo "$baseline_case" | jq -r '.value')
        if [ "$baseline_value" = "0" ] || [ "$baseline_value" = "null" ]; then
            continue
        fi

        local diff_pct abs_diff_pct
        diff_pct=$(echo "scale=4; (($current_value - $baseline_value) / $baseline_value)" | bc -l)
        abs_diff_pct=$(echo "$diff_pct" | sed 's/^-//')

        actual_total=$((actual_total + 1))

        if (( $(echo "$abs_diff_pct > $TOLERANCE" | bc -l) )); then
            actual_failures=$((actual_failures + 1))
        fi
    done <<< "$(echo "$current_cases" | jq -c '.[]')"

    if [ $actual_total -eq 0 ]; then
        echo "[bench-guard] Warning: No comparable benchmarks found" >&2
        exit 0
    fi

    if [ $actual_failures -gt 0 ]; then
        echo "[bench-guard] ❌ Performance regression detected! ($actual_failures/$actual_total checks failed)" >&2
        exit 3
    else
        echo "[bench-guard] ✅ All metrics within tolerance ($actual_total checks passed)" >&2
        exit 0
    fi
}

# Main execution
case "$MODE" in
    record)
        record_baseline
        ;;
    check)
        check_baseline
        ;;
esac