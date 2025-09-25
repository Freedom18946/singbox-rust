#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

# Performance baseline recorder and regression guard
# Records baseline.json and checks against it with tolerance thresholds

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
BASELINE_FILE="$ROOT_DIR/target/bench/baseline.json"
BASELINE_DIR="$(dirname "$BASELINE_FILE")"

usage() {
    echo "Usage: $0 --record|--check [--url URL] [--requests N] [--concurrency C]"
    echo ""
    echo "  --record        Record new baseline to target/bench/baseline.json"
    echo "  --check         Check current performance against baseline"
    echo "  --url URL       Override benchmark URL (default: https://httpbin.org/get)"
    echo "  --requests N    Override requests count (default: 100)"
    echo "  --concurrency C Override concurrency (default: 8)"
    echo ""
    echo "Exit codes:"
    echo "  0: Success (--check: within tolerance)"
    echo "  1: General error"
    echo "  3: Performance regression detected (--check only)"
    exit 1
}

MODE=""
URL="https://httpbin.org/get"
REQUESTS="100"
CONCURRENCY="8"

while [[ $# -gt 0 ]]; do
    case $1 in
        --record)
            MODE="record"
            shift
            ;;
        --check)
            MODE="check"
            shift
            ;;
        --url)
            URL="$2"
            shift 2
            ;;
        --requests)
            REQUESTS="$2"
            shift 2
            ;;
        --concurrency)
            CONCURRENCY="$2"
            shift 2
            ;;
        -h|--help)
            usage
            ;;
        *)
            echo "Unknown option: $1"
            usage
            ;;
    esac
done

if [[ -z "$MODE" ]]; then
    usage
fi

# Ensure benchmark binary is built
echo "[bench-guard] Building benchmark binary..."
cd "$ROOT_DIR"
cargo build --release --bin app --features reqwest

BENCH_BIN="$ROOT_DIR/target/release/app"
if [[ ! -x "$BENCH_BIN" ]]; then
    echo "[bench-guard] Error: failed to build benchmark binary"
    exit 1
fi

# Run benchmark and capture results
run_benchmark() {
    local temp_result
    temp_result=$(mktemp)

    echo "[bench-guard] Running benchmark: $URL (requests=$REQUESTS, concurrency=$CONCURRENCY)"
    if ! "$BENCH_BIN" bench io --url "$URL" --requests "$REQUESTS" --concurrency "$CONCURRENCY" --h2 --json --keepalive > "$temp_result"; then
        echo "[bench-guard] Error: benchmark failed"
        rm -f "$temp_result"
        exit 1
    fi

    echo "$temp_result"
}

# Tolerance checks: p50/p90/p99 ±8%, rps/throughput ±5%
check_tolerance() {
    local baseline="$1"
    local current="$2"

    # Extract values using jq
    local baseline_p50 baseline_p90 baseline_p99 baseline_rps baseline_throughput
    local current_p50 current_p90 current_p99 current_rps current_throughput

    baseline_p50=$(jq -r '.p50' "$baseline")
    baseline_p90=$(jq -r '.p90' "$baseline")
    baseline_p99=$(jq -r '.p99' "$baseline")
    baseline_rps=$(jq -r '.rps' "$baseline")
    baseline_throughput=$(jq -r '.throughput_bps' "$baseline")

    current_p50=$(jq -r '.p50' "$current")
    current_p90=$(jq -r '.p90' "$current")
    current_p99=$(jq -r '.p99' "$current")
    current_rps=$(jq -r '.rps' "$current")
    current_throughput=$(jq -r '.throughput_bps' "$current")

    # Check percentiles (±8% tolerance)
    local percentile_tolerance="8"
    local throughput_tolerance="5"
    local failures=0

    check_metric() {
        local name="$1"
        local baseline_val="$2"
        local current_val="$3"
        local tolerance="$4"

        local diff_pct
        if [[ "$baseline_val" == "0" ]] || [[ "$baseline_val" == "0.0" ]]; then
            diff_pct=0
        else
            diff_pct=$(echo "scale=2; (($current_val - $baseline_val) / $baseline_val) * 100" | bc -l)
        fi

        local abs_diff_pct
        abs_diff_pct=$(echo "${diff_pct#-}")  # Remove negative sign for abs

        if (( $(echo "$abs_diff_pct > $tolerance" | bc -l) )); then
            echo "[FAIL] $name: baseline=$baseline_val current=$current_val diff=${diff_pct}% (exceeds ±${tolerance}%)"
            return 1
        else
            echo "[PASS] $name: baseline=$baseline_val current=$current_val diff=${diff_pct}% (within ±${tolerance}%)"
            return 0
        fi
    }

    check_metric "p50" "$baseline_p50" "$current_p50" "$percentile_tolerance" || failures=$((failures + 1))
    check_metric "p90" "$baseline_p90" "$current_p90" "$percentile_tolerance" || failures=$((failures + 1))
    check_metric "p99" "$baseline_p99" "$current_p99" "$percentile_tolerance" || failures=$((failures + 1))
    check_metric "rps" "$baseline_rps" "$current_rps" "$throughput_tolerance" || failures=$((failures + 1))
    check_metric "throughput_bps" "$baseline_throughput" "$current_throughput" "$throughput_tolerance" || failures=$((failures + 1))

    return $failures
}

if [[ "$MODE" == "record" ]]; then
    echo "[bench-guard] Recording baseline..."

    # Create baseline directory
    mkdir -p "$BASELINE_DIR"

    # Run benchmark
    result_file=$(run_benchmark)

    # Save as baseline
    cp "$result_file" "$BASELINE_FILE"
    rm -f "$result_file"

    echo "[bench-guard] Baseline recorded to: $BASELINE_FILE"
    echo "[bench-guard] Baseline data:"
    jq '.' "$BASELINE_FILE"

elif [[ "$MODE" == "check" ]]; then
    echo "[bench-guard] Checking against baseline..."

    if [[ ! -f "$BASELINE_FILE" ]]; then
        echo "[bench-guard] Error: baseline file not found: $BASELINE_FILE"
        echo "[bench-guard] Run with --record first to create baseline"
        exit 1
    fi

    # Run current benchmark
    result_file=$(run_benchmark)

    echo "[bench-guard] Comparing results..."
    echo "[bench-guard] Baseline: $(jq -c '.' "$BASELINE_FILE")"
    echo "[bench-guard] Current:  $(jq -c '.' "$result_file")"

    # Check tolerance
    if check_tolerance "$BASELINE_FILE" "$result_file"; then
        echo "[bench-guard] ✅ All metrics within tolerance - no regression detected"
        rm -f "$result_file"
        exit 0
    else
        echo "[bench-guard] ❌ Performance regression detected!"
        rm -f "$result_file"
        exit 3
    fi
fi