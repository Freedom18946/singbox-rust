#!/usr/bin/env bash
# Performance benchmark comparison script: Rust vs Go sing-box
# Usage: ./scripts/bench_vs_go.sh [--quick] [--output-dir DIR]
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
OUTPUT_DIR="${OUTPUT_DIR:-$PROJECT_ROOT/bench_results}"
REPORT_DIR="$PROJECT_ROOT/reports/benchmarks"
CSV_FILE="$REPORT_DIR/go_vs_rust_throughput.csv"
QUICK_MODE=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        --quick)
            QUICK_MODE=true
            shift
            ;;
        --output-dir)
            OUTPUT_DIR="$2"
            shift 2
            ;;
        *)
            echo "Unknown option: $1"
            echo "Usage: $0 [--quick] [--output-dir DIR]"
            exit 1
            ;;
    esac
done

mkdir -p "$OUTPUT_DIR" "$REPORT_DIR"
cd "$PROJECT_ROOT"

echo "[bench-vs-go] building Rust app release..."
cargo build --release -p app 2>&1 | tee "$OUTPUT_DIR/rust_build.log"

if [ "$QUICK_MODE" = true ]; then
    BENCH_ARGS=(--sample-size 20 --measurement-time 5)
else
    BENCH_ARGS=(--sample-size 50 --measurement-time 10)
fi

declare -A RUST_BENCHES=(
    [socks5]=socks5_throughput
    [shadowsocks]=shadowsocks_throughput
    [trojan]=trojan_throughput
)

for protocol in socks5 shadowsocks trojan; do
    bench="${RUST_BENCHES[$protocol]}"
    log_file="$OUTPUT_DIR/rust_${protocol}.log"
    echo "[bench-vs-go] running Rust bench: $bench"
    cargo bench -p sb-benches --bench "$bench" -- "${BENCH_ARGS[@]}" 2>&1 | tee "$log_file" || true
done

GO_SRC_DIR="$PROJECT_ROOT/go_fork_source/sing-box-1.12.14"
GO_BINARY="$GO_SRC_DIR/sing-box"
GO_STATUS="env_limited"
GO_REASON="go_benchmark_unavailable"

if [ -d "$GO_SRC_DIR" ] && command -v go >/dev/null 2>&1; then
    if [ ! -f "$GO_BINARY" ]; then
        echo "[bench-vs-go] building Go sing-box binary..."
        (cd "$GO_SRC_DIR" && go build -o sing-box ./cmd/sing-box) 2>&1 | tee "$OUTPUT_DIR/go_build.log" || true
    fi

    if [ -f "$GO_BINARY" ]; then
        if "$GO_BINARY" version >/dev/null 2>&1; then
            GO_REASON="go_binary_built_no_protocol_bench_suite"
        else
            GO_REASON="go_binary_run_failed"
        fi
    else
        GO_REASON="go_binary_build_failed"
    fi

    if rg -n "^func Benchmark" "$GO_SRC_DIR" -g "*_test.go" >/dev/null 2>&1; then
        GO_REASON="go_bench_exists_but_not_mapped_to_protocol_throughput"
    fi
else
    GO_REASON="go_toolchain_or_source_missing"
fi

export OUTPUT_DIR CSV_FILE GO_STATUS GO_REASON
python3 - << 'PYTHON_SCRIPT'
import csv
import datetime
import os
import re

output_dir = os.environ["OUTPUT_DIR"]
csv_file = os.environ["CSV_FILE"]
go_status = os.environ["GO_STATUS"]
go_reason = os.environ["GO_REASON"]
timestamp = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")

protocols = ["socks5", "shadowsocks", "trojan"]

def to_ms(val, unit):
    unit = unit.lower()
    if unit == "ns":
        return val / 1_000_000.0
    if unit in ("us", "µs"):
        return val / 1_000.0
    if unit == "ms":
        return val
    if unit == "s":
        return val * 1000.0
    return val

rows = []
time_pat = re.compile(r"time:\s+\[([0-9.]+)\s*([a-zA-Zµ]+)\s+([0-9.]+)\s*([a-zA-Zµ]+)\s+([0-9.]+)\s*([a-zA-Zµ]+)\]")
thrpt_pat = re.compile(r"thrpt:\s+\[([0-9.]+)\s+([A-Za-z/]+)\s+([0-9.]+)\s+([A-Za-z/]+)\s+([0-9.]+)\s+([A-Za-z/]+)\]")

for protocol in protocols:
    log_path = os.path.join(output_dir, f"rust_{protocol}.log")
    throughput_mbps = 0.0
    p50_ms = 0.0
    p95_ms = 0.0
    status = "env_limited"
    reason = "missing_rust_bench_log"

    if os.path.isfile(log_path):
        with open(log_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()

        time_matches = list(time_pat.finditer(content))
        thrpt_matches = list(thrpt_pat.finditer(content))
        if time_matches:
            m = time_matches[-1]
            mid = float(m.group(3))
            mid_unit = m.group(4)
            high = float(m.group(5))
            high_unit = m.group(6)
            p50_ms = to_ms(mid, mid_unit)
            p95_ms = to_ms(high, high_unit)
        if thrpt_matches:
            m = thrpt_matches[-1]
            # Assume middle value is representative and unit is MiB/s
            mid = float(m.group(3))
            throughput_mbps = mid * 8.388608

        if time_matches and thrpt_matches:
            status = "pass"
            reason = ""
        else:
            status = "env_limited"
            reason = "unable_to_parse_rust_benchmark_metrics"

    rows.append({
        "protocol": protocol,
        "core": "rust",
        "throughput_mbps": round(throughput_mbps, 3),
        "latency_p50_ms": round(p50_ms, 3),
        "latency_p95_ms": round(p95_ms, 3),
        "status": status,
        "reason": reason,
        "timestamp": timestamp,
    })

    rows.append({
        "protocol": protocol,
        "core": "go",
        "throughput_mbps": 0.0,
        "latency_p50_ms": 0.0,
        "latency_p95_ms": 0.0,
        "status": go_status,
        "reason": go_reason,
        "timestamp": timestamp,
    })

os.makedirs(os.path.dirname(csv_file), exist_ok=True)
with open(csv_file, "w", newline="", encoding="utf-8") as f:
    writer = csv.DictWriter(
        f,
        fieldnames=[
            "protocol",
            "core",
            "throughput_mbps",
            "latency_p50_ms",
            "latency_p95_ms",
            "status",
            "reason",
            "timestamp",
        ],
    )
    writer.writeheader()
    writer.writerows(rows)

print(f"Wrote {len(rows)} rows to {csv_file}")
PYTHON_SCRIPT

echo "[bench-vs-go] CSV written: $CSV_FILE"
echo "[bench-vs-go] completed"
