#!/usr/bin/env bash
set -euo pipefail

# Aggregate trend report: runs cases and produces trend_summary.json
# Usage: ITERATIONS=3 KERNEL=rust bash scripts/aggregate_trend_report.sh [CASE_ID]

CASE_ID="${1:-}"
ITERATIONS="${ITERATIONS:-3}"
KERNEL="${KERNEL:-rust}"
ARTIFACTS_DIR="${ARTIFACTS_DIR:-labs/interop-lab/artifacts}"
RUN_PRIORITY="${RUN_PRIORITY:-}"
RUN_ENV_CLASS="${RUN_ENV_CLASS:-}"

if ! command -v jq >/dev/null 2>&1; then
  echo "error: jq is required by aggregate_trend_report.sh"
  exit 2
fi

# Build the base run command
build_run_cmd() {
  local cmd=(cargo run -p interop-lab -- case run)
  if [[ -n "${CASE_ID}" && "${CASE_ID}" != "ALL" ]]; then
    cmd+=("${CASE_ID}")
  fi
  cmd+=(--kernel "${KERNEL}")
  if [[ -n "${RUN_PRIORITY}" ]]; then
    cmd+=(--priority "${RUN_PRIORITY}")
  fi
  if [[ -n "${RUN_ENV_CLASS}" ]]; then
    cmd+=(--env-class "${RUN_ENV_CLASS}")
  fi
  echo "${cmd[@]}"
}

echo "aggregate-trend case=${CASE_ID:-ALL} iterations=${ITERATIONS} kernel=${KERNEL}"

# Collect results per case across iterations
declare -A case_scores

for ((i = 1; i <= ITERATIONS; i++)); do
  echo
  echo "=== iteration ${i}/${ITERATIONS} ==="

  run_cmd=$(build_run_cmd)
  run_output=$(eval "${run_cmd}")
  echo "${run_output}"

  # Extract all run_dir lines
  while IFS= read -r line; do
    run_dir="${line#run_dir=}"
    if [[ -z "${run_dir}" || ! -d "${run_dir}" ]]; then
      continue
    fi

    rust_snapshot="${run_dir}/rust.snapshot.json"
    if [[ ! -f "${rust_snapshot}" ]]; then
      continue
    fi

    cid=$(jq -r '.case_id' "${rust_snapshot}")
    rust_errors=$(jq '.errors | length' "${rust_snapshot}")
    failed_traffic=$(jq '[.traffic_results[]? | select(.success != true)] | length' "${rust_snapshot}")
    score=$((rust_errors + failed_traffic))

    # Accumulate scores
    if [[ -v "case_scores[${cid}]" ]]; then
      case_scores["${cid}"]="${case_scores[${cid}]},${score}"
    else
      case_scores["${cid}"]="${score}"
    fi

    echo "  case=${cid} iteration=${i} score=${score} (errors=${rust_errors}, failed=${failed_traffic})"

  done < <(printf '%s\n' "${run_output}" | grep '^run_dir=' | sed 's/^run_dir=//')
done

# Build JSON output
echo
echo "=== generating trend_summary.json ==="

json_cases="[]"

for cid in $(printf '%s\n' "${!case_scores[@]}" | sort); do
  scores="${case_scores[${cid}]}"
  IFS=',' read -r -a score_arr <<<"${scores}"

  # Determine trend
  trend="stable"
  if (( ${#score_arr[@]} >= 2 )); then
    first="${score_arr[0]}"
    last="${score_arr[-1]}"
    if (( last < first )); then
      trend="improving"
    elif (( last > first )); then
      trend="degrading"
    fi
  fi

  # Build scores JSON array
  scores_json=$(printf '%s\n' "${score_arr[@]}" | jq -s '.')

  # Build case entry
  case_json=$(jq -n \
    --arg id "${cid}" \
    --argjson scores "${scores_json}" \
    --arg trend "${trend}" \
    '{ id: $id, scores: $scores, trend: $trend, env_attributions: [] }')

  json_cases=$(echo "${json_cases}" | jq --argjson c "${case_json}" '. + [$c]')
done

summary=$(jq -n \
  --argjson cases "${json_cases}" \
  --arg generated_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --arg kernel "${KERNEL}" \
  --argjson iterations "${ITERATIONS}" \
  '{ generated_at: $generated_at, kernel: $kernel, iterations: $iterations, cases: $cases }')

output_file="${ARTIFACTS_DIR}/trend_summary.json"
mkdir -p "$(dirname "${output_file}")"
echo "${summary}" | jq '.' > "${output_file}"

echo "trend_summary written to ${output_file}"
echo "${summary}" | jq '.cases[] | "\(.id): trend=\(.trend) scores=\(.scores)"' -r

# Append to history (JSONL format)
history_file="${ARTIFACTS_DIR}/trend_history.jsonl"
history_entry=$(jq -c --arg ts "$(date -u +%Y-%m-%dT%H:%M:%SZ)" '. + {timestamp: $ts}' <<< "${summary}")
echo "${history_entry}" >> "${history_file}"
echo "trend_history appended to ${history_file}"

# Regression detection: check if strict cases degraded >10% over last 5 runs
if [[ -f "${history_file}" ]]; then
  recent_count=$(wc -l < "${history_file}" | tr -d ' ')
  if (( recent_count >= 2 )); then
    echo
    echo "=== regression check (last ${recent_count} runs, max 5) ==="

    # Get last 5 entries' per-case scores
    tail -5 "${history_file}" | jq -r '.cases[]? | "\(.id) \(.scores | add)"' 2>/dev/null | \
    awk '{
      case_id = $1
      score = $2 + 0
      if (!(case_id in first_score)) {
        first_score[case_id] = score
      }
      last_score[case_id] = score
      count[case_id]++
    }
    END {
      regression_found = 0
      for (id in first_score) {
        if (count[id] >= 2) {
          first = first_score[id]
          last = last_score[id]
          if (first == 0 && last > 0) {
            printf "REGRESSION_WARNING: case=%s score %d -> %d (was zero)\n", id, first, last
            regression_found = 1
          } else if (first > 0) {
            pct_change = (last - first) * 100 / first
            if (pct_change > 10) {
              printf "REGRESSION_WARNING: case=%s score %d -> %d (%.0f%% degradation)\n", id, first, last, pct_change
              regression_found = 1
            }
          }
        }
      }
      if (!regression_found) {
        print "regression check: no degradation detected"
      }
    }'
  fi
fi
