#!/usr/bin/env bash
set -euo pipefail

fetch_metrics() { curl -s "http://${1}/metrics" 2>/dev/null || true; }

# Extract metric lines for a key (supports labeled and unlabeled lines)
metric_value() {
  local text="$1"; local key="$2"
  echo "$text" | awk -v k="$key" '$1 ~ "^"k"\\{" || $1 == k { print $0 }'
}

# Sum all numeric values (last field) for a metric key across labels
metric_sum() {
  local text="$1"; local key="$2"; local s=0
  while read -r line; do
    [[ -z "$line" ]] && continue
    local v="${line##* }"
    [[ "$v" =~ ^[0-9.eE+-]+$ ]] || continue
    s=$(awk -v a="$s" -v b="$v" 'BEGIN{printf "%.6f", a+b}')
  done < <(metric_value "$text" "$key")
  echo "$s"
}

# Sum with label filter (ERE). Example: code="405" or backend="dot"
metric_sum_label() {
  local text="$1"; local key="$2"; local label_re="$3"; local s=0
  while read -r line; do
    [[ -z "$line" ]] && continue
    [[ "$line" =~ ^${key}(\{[^}]*\})?\  ]] || continue
    [[ "$line" =~ $label_re ]] || continue
    local v="${line##* }"
    [[ "$v" =~ ^[0-9.eE+-]+$ ]] || continue
    s=$(awk -v a="$s" -v b="$v" 'BEGIN{printf "%.6f", a+b}')
  done < <(echo "$text")
  echo "$s"
}
