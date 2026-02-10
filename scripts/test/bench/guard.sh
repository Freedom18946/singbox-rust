#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
BASELINE_FILE="$SCRIPT_DIR/baseline.json"
SUMMARY_FILE="$REPO_ROOT/target/bench/summary.csv"
TOLERANCE="${BENCH_GUARD_TOL:-0.60}"

usage() {
  echo "Usage: $0 record|check" >&2
  echo "" >&2
  echo "  record    Run benches and record baseline" >&2
  echo "  check     Run benches and compare against baseline" >&2
  echo "" >&2
  echo "Environment:" >&2
  echo "  BENCH_GUARD_TOL  Relative tolerance (default: 0.60 = 60%)" >&2
  echo "" >&2
  echo "Exit codes:" >&2
  echo "  0: success" >&2
  echo "  1: usage/general error" >&2
  echo "  2: setup/parsing error" >&2
  echo "  3: regression detected" >&2
  exit 1
}

require_cmd() {
  local cmd="$1"
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "[bench-guard] Error: missing required command: $cmd" >&2
    exit 2
  fi
}

collect_cases_json() {
  echo "[bench-guard] Running benchmark suite..." >&2
  "$SCRIPT_DIR/run.sh" >&2

  if [[ ! -f "$SUMMARY_FILE" ]]; then
    echo "[bench-guard] Error: summary not found: $SUMMARY_FILE" >&2
    exit 2
  fi

  local rows
  rows=$(awk -F',' 'NR>1 && $1!="" && $2!="" && $3 ~ /^[0-9]+(\.[0-9]+)?$/ {print $1","$2","$3}' "$SUMMARY_FILE")
  if [[ -z "$rows" ]]; then
    echo "[bench-guard] Error: no benchmark rows found in $SUMMARY_FILE" >&2
    exit 2
  fi

  printf '%s\n' "$rows" \
    | awk -F',' '{printf "{\"name\":\"%s.%s\",\"value\":%s,\"unit\":\"ns\"}\n", $1, $2, $3}' \
    | jq -s '.'
}

get_machine_json() {
  local cpu_model="unknown"
  local cores="unknown"
  local mem_gb="unknown"

  if command -v sysctl >/dev/null 2>&1; then
    cpu_model=$(sysctl -n machdep.cpu.brand_string 2>/dev/null || echo "unknown")
    cores=$(sysctl -n hw.ncpu 2>/dev/null || echo "unknown")
    local mem_bytes
    mem_bytes=$(sysctl -n hw.memsize 2>/dev/null || echo "0")
    mem_gb=$((mem_bytes / 1024 / 1024 / 1024))
  elif [[ -f /proc/cpuinfo && -f /proc/meminfo ]]; then
    cpu_model=$(grep "model name" /proc/cpuinfo | head -1 | cut -d: -f2 | sed 's/^ *//' || echo "unknown")
    cores=$(nproc 2>/dev/null || echo "unknown")
    local mem_kb
    mem_kb=$(grep "MemTotal" /proc/meminfo | awk '{print $2}' || echo "0")
    mem_gb=$((mem_kb / 1024 / 1024))
  fi

  jq -n \
    --arg cpu_model "$cpu_model" \
    --arg cores "$cores" \
    --arg mem_gb "$mem_gb" \
    '{cpu_model:$cpu_model, cores:$cores, mem_gb:$mem_gb}'
}

get_git_sha() {
  (cd "$REPO_ROOT" && git rev-parse --short HEAD 2>/dev/null) || echo "unknown"
}

record_baseline() {
  local cases machine git_sha rustc_ver date_utc
  cases=$(collect_cases_json)
  machine=$(get_machine_json)
  git_sha=$(get_git_sha)
  rustc_ver=$(rustc --version 2>/dev/null || echo "rustc unknown")
  date_utc=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

  jq -n \
    --arg date "$date_utc" \
    --arg git_short_sha "$git_sha" \
    --arg rustc_ver "$rustc_ver" \
    --argjson machine "$machine" \
    --argjson cases "$cases" \
    '{machine:$machine, date:$date, git_short_sha:$git_short_sha, rustc_ver:$rustc_ver, cases:$cases}' \
    > "$BASELINE_FILE"

  echo "[bench-guard] Baseline recorded: $BASELINE_FILE" >&2
  echo "[bench-guard] Cases: $(jq length <<<"$cases")" >&2
}

check_baseline() {
  if [[ ! -f "$BASELINE_FILE" ]]; then
    echo "[bench-guard] Error: baseline file not found: $BASELINE_FILE" >&2
    exit 2
  fi

  local baseline_cases current_cases
  baseline_cases=$(jq -c '.cases' "$BASELINE_FILE" 2>/dev/null) || {
    echo "[bench-guard] Error: failed to parse baseline JSON" >&2
    exit 2
  }
  current_cases=$(collect_cases_json)

  local checked=0
  local failures=0

  while IFS= read -r row; do
    local name current baseline diff abs_diff
    name=$(jq -r '.name' <<<"$row")
    current=$(jq -r '.value' <<<"$row")
    baseline=$(jq -r --arg name "$name" '.[] | select(.name == $name) | .value' <<<"$baseline_cases" | head -1)

    if [[ -z "$baseline" || "$baseline" == "null" || "$baseline" == "0" ]]; then
      echo "[SKIP] $name: no baseline" >&2
      continue
    fi

    diff=$(awk -v c="$current" -v b="$baseline" 'BEGIN {printf "%.6f", (c-b)/b}')
    abs_diff=$(awk -v d="$diff" 'BEGIN {if (d < 0) d = -d; printf "%.6f", d}')
    checked=$((checked + 1))

    if awk -v a="$abs_diff" -v t="$TOLERANCE" 'BEGIN {exit !(a > t)}'; then
      echo "[FAIL] $name: baseline=$baseline current=$current diff=$(awk -v d="$diff" 'BEGIN {printf "%.2f", d*100}')%" >&2
      failures=$((failures + 1))
    else
      echo "[PASS] $name: baseline=$baseline current=$current diff=$(awk -v d="$diff" 'BEGIN {printf "%.2f", d*100}')%" >&2
    fi
  done < <(jq -c '.[]' <<<"$current_cases")

  if [[ $checked -eq 0 ]]; then
    echo "[bench-guard] Error: no comparable benchmark cases" >&2
    exit 2
  fi

  if [[ $failures -gt 0 ]]; then
    echo "[bench-guard] Regression detected ($failures/$checked over tolerance ${TOLERANCE})" >&2
    exit 3
  fi

  echo "[bench-guard] All checks within tolerance ($checked/$checked)" >&2
}

if [[ $# -ne 1 ]]; then
  usage
fi

require_cmd jq
require_cmd awk
require_cmd cargo

case "$1" in
  record)
    record_baseline
    ;;
  check)
    check_baseline
    ;;
  *)
    usage
    ;;
esac
