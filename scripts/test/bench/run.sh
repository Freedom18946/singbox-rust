#!/usr/bin/env bash
set -euo pipefail

root_dir=$(cd "$(dirname "$0")/../../.." && pwd)
cd "$root_dir"

mkdir -p target/bench
summary=target/bench/summary.csv
echo "bench,metric,value" > "$summary"

echo "[bench] running criterion benches (dev-only)"
cargo bench --package sb-benches --bench socks5_throughput --quiet

parse_estimates() {
  local file="$1"; local name="$2"; local key="$3"
  if [[ -f "$file" ]]; then
    local val=""
    if command -v jq >/dev/null 2>&1; then
      if [[ "$key" == "mean_ns" ]]; then
        val=$(jq -r '.mean.point_estimate // empty' "$file" 2>/dev/null || true)
      else
        val=$(jq -r '.median.point_estimate // empty' "$file" 2>/dev/null || true)
      fi
      if [[ -n "${val:-}" ]]; then
        val=$(awk -v x="$val" 'BEGIN {printf "%.0f", x}')
      fi
    else
      val=$(grep -E '"point_estimate"\s*:\s*[0-9]+' -m1 "$file" | sed -E 's/.*: *([0-9]+).*/\1/') || true
    fi
    if [[ -n "${val:-}" ]]; then
      echo "$name,$key,$val" >> "$summary"
    fi
  fi
}

# Try to collect median/mean from criterion outputs if present
for dir in target/criterion/*; do
  [[ -d "$dir" ]] || continue
  bench_name=$(basename "$dir")
  est_json="$dir/new/estimates.json"
  parse_estimates "$est_json" "$bench_name" mean_ns
  # median if available
  parse_estimates "$est_json" "$bench_name" median_ns
done

echo "[bench] summary written: $summary"
