#!/usr/bin/env bash
set -euo pipefail

root_dir=$(cd "$(dirname "$0")/.." && pwd)
cd "$root_dir"

mkdir -p target/bench
summary=target/bench/summary.csv
echo "bench,metric,value" > "$summary"

echo "[bench] running criterion benches (dev-only)"
cargo bench --bench selector_score --bench dns_cache --quiet || true

parse_estimates() {
  local file="$1"; local name="$2"; local key="$3"
  if [[ -f "$file" ]]; then
    local val
    val=$(grep -E '"point_estimate"\s*:\s*[0-9]+' -m1 "$file" | sed -E 's/.*: *([0-9]+).*/\1/') || true
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
  if [[ -f "$est_json" ]]; then
    med=$(grep -A3 '"median"' "$est_json" | grep -E '"point_estimate"' -m1 | sed -E 's/.*: *([0-9]+).*/\1/') || true
    if [[ -n "${med:-}" ]]; then echo "$bench_name,median_ns,$med" >> "$summary"; fi
  fi
done

echo "[bench] summary written: $summary"

