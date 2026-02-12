#!/usr/bin/env bash
# Benchmark comparison script: compare current run against baseline
# Usage: ./scripts/bench_compare.sh <bench_output.txt> <baseline.json> [status_file.json]
# Exit codes:
#   0 = pass / skipped
#   1 = warn (>5% regression)
#   2 = fail (>10% regression)
set -euo pipefail

BENCH_OUTPUT="${1:-bench_output.txt}"
BASELINE="${2:-reports/benchmarks/baseline.json}"
STATUS_FILE="${3:-reports/benchmarks/bench_regression_status.json}"

mkdir -p "$(dirname "$STATUS_FILE")"

if [ ! -f "$BENCH_OUTPUT" ]; then
    echo "WARN: Benchmark output not found: $BENCH_OUTPUT"
    cat > "$STATUS_FILE" << EOF
{"status":"warn","reason":"missing_bench_output","compared":0}
EOF
    exit 0
fi

if [ ! -f "$BASELINE" ]; then
    echo "WARN: Baseline not found: $BASELINE"
    cat > "$STATUS_FILE" << EOF
{"status":"warn","reason":"missing_baseline","compared":0}
EOF
    exit 0
fi

export BENCH_OUTPUT BASELINE STATUS_FILE
python3 - << 'PYTHON_SCRIPT'
import json
import os
import re
import sys
from datetime import datetime, timezone

bench_output = os.environ["BENCH_OUTPUT"]
baseline_file = os.environ["BASELINE"]
status_file = os.environ["STATUS_FILE"]

def unit_to_ns(value: float, unit: str) -> float:
    m = {
        "ns": 1.0,
        "us": 1000.0,
        "µs": 1000.0,
        "ms": 1_000_000.0,
        "s": 1_000_000_000.0,
    }
    return value * m.get(unit, 1.0)

try:
    with open(baseline_file, "r", encoding="utf-8") as f:
        baseline = json.load(f)
except Exception as e:
    print(f"WARN: Failed to parse baseline: {e}")
    with open(status_file, "w", encoding="utf-8") as f:
        json.dump({"status": "warn", "reason": "invalid_baseline", "compared": 0}, f)
    sys.exit(0)

baseline_benchmarks = baseline.get("benchmarks", {})
if not baseline_benchmarks:
    print("INFO: baseline has no benchmark entries")
    with open(status_file, "w", encoding="utf-8") as f:
        json.dump({"status": "warn", "reason": "empty_baseline", "compared": 0}, f)
    sys.exit(0)

try:
    with open(bench_output, "r", encoding="utf-8") as f:
        lines = f.readlines()
except Exception as e:
    print(f"WARN: Failed to read bench output: {e}")
    with open(status_file, "w", encoding="utf-8") as f:
        json.dump({"status": "warn", "reason": "invalid_bench_output", "compared": 0}, f)
    sys.exit(0)

# Example: "dns_query_parse         time:   [49.650 ns 49.856 ns 50.072 ns]"
line_pat = re.compile(
    r"^([^\s].*?)\s+time:\s+\[([0-9.]+)\s*([a-zA-Zµ]+)\s+([0-9.]+)\s*([a-zA-Zµ]+)\s+([0-9.]+)\s*([a-zA-Zµ]+)\]"
)

current = {}
for raw in lines:
    line = raw.strip()
    m = line_pat.match(line)
    if not m:
        continue
    name = m.group(1).strip()
    mid_val = float(m.group(4))
    mid_unit = m.group(5)
    current[name] = unit_to_ns(mid_val, mid_unit)

print("=== Benchmark Regression Check ===")
print(f"Output: {bench_output}")
print(f"Baseline: {baseline_file}")
print("")
print(f"{'Benchmark':<60} {'Baseline':>12} {'Current':>12} {'Change':>8} {'Status':>8}")
print("-" * 108)

warnings = 0
regressions = 0
improvements = 0
compared = 0

for name, base in sorted(baseline_benchmarks.items()):
    baseline_ns = float(base.get("mean_ns", 0) or 0)
    if baseline_ns <= 0:
        continue
    if name not in current:
        continue
    curr = current[name]
    compared += 1
    change_pct = ((curr - baseline_ns) / baseline_ns) * 100.0

    if change_pct > 10:
        st = "FAIL"
        regressions += 1
    elif change_pct > 5:
        st = "WARN"
        warnings += 1
    elif change_pct < -5:
        st = "IMPROVE"
        improvements += 1
    else:
        st = "OK"

    print(f"{name:<60} {baseline_ns:>10.0f}ns {curr:>10.0f}ns {change_pct:>+7.1f}% {st:>8}")

if compared == 0:
    status = "warn"
    reason = "no_comparable_rows"
    exit_code = 0
elif regressions > 0:
    status = "fail"
    reason = "regression_gt_10pct"
    exit_code = 2
elif warnings > 0:
    status = "warn"
    reason = "regression_gt_5pct"
    exit_code = 1
else:
    status = "pass"
    reason = "within_threshold"
    exit_code = 0

print("")
print(f"Summary: compared={compared}, improved={improvements}, warnings={warnings}, regressions={regressions}")
print(f"Gate status: {status} ({reason})")

status_payload = {
    "status": status,
    "reason": reason,
    "generated": datetime.now(timezone.utc).isoformat(),
    "summary": {
        "compared": compared,
        "improved": improvements,
        "warnings": warnings,
        "regressions": regressions,
    },
}

with open(status_file, "w", encoding="utf-8") as f:
    json.dump(status_payload, f, indent=2)

sys.exit(exit_code)
PYTHON_SCRIPT
