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
INTEROP_SKIP_APP_BUILD="${INTEROP_SKIP_APP_BUILD:-0}"

if ! command -v jq >/dev/null 2>&1; then
  echo "error: jq is required by aggregate_trend_report.sh"
  exit 2
fi

if [[ "${INTEROP_SKIP_APP_BUILD}" != "1" ]]; then
  echo "prebuild: cargo build -p app --features acceptance --bin app"
  cargo build -p app --features acceptance --bin app >/dev/null
fi

echo "aggregate-trend case=${CASE_ID:-ALL} iterations=${ITERATIONS} kernel=${KERNEL} artifacts_dir=${ARTIFACTS_DIR}"

# JSON map: { "case_id": [score1, score2, ...] }
scores_map='{}'

for ((i = 1; i <= ITERATIONS; i++)); do
  echo
  echo "=== iteration ${i}/${ITERATIONS} ==="

  run_cmd=(cargo run -p interop-lab -- --artifacts-dir "${ARTIFACTS_DIR}" case run)
  if [[ -n "${CASE_ID}" && "${CASE_ID}" != "ALL" ]]; then
    run_cmd+=("${CASE_ID}")
  fi
  run_cmd+=(--kernel "${KERNEL}")
  if [[ -n "${RUN_PRIORITY}" ]]; then
    run_cmd+=(--priority "${RUN_PRIORITY}")
  fi
  if [[ -n "${RUN_ENV_CLASS}" ]]; then
    run_cmd+=(--env-class "${RUN_ENV_CLASS}")
  fi

  run_output="$("${run_cmd[@]}")"
  echo "${run_output}"

  while IFS= read -r run_dir; do
    if [[ -z "${run_dir}" || ! -d "${run_dir}" ]]; then
      continue
    fi

    rust_snapshot="${run_dir}/rust.snapshot.json"
    if [[ ! -f "${rust_snapshot}" ]]; then
      continue
    fi

    cid="$(jq -r '.case_id // empty' "${rust_snapshot}")"
    if [[ -z "${cid}" ]]; then
      cid="$(basename "$(dirname "${run_dir}")")"
    fi

    rust_errors="$(jq '.errors | length' "${rust_snapshot}")"
    failed_traffic="$(jq '[.traffic_results[]? | select(.success != true)] | length' "${rust_snapshot}")"
    score=$((rust_errors + failed_traffic))

    scores_map="$(jq \
      --arg id "${cid}" \
      --argjson score "${score}" \
      '.[$id] = ((.[$id] // []) + [$score])' \
      <<< "${scores_map}")"

    echo "  case=${cid} iteration=${i} score=${score} (errors=${rust_errors}, failed=${failed_traffic})"
  done < <(printf '%s\n' "${run_output}" | sed -n 's/^run_dir=//p')
done

echo
echo "=== generating trend_summary.json ==="

json_cases="$(jq -n --argjson m "${scores_map}" '
  [
    $m
    | to_entries[]
    | {
        id: .key,
        scores: .value,
        trend: (
          if (.value | length) < 2 then "stable"
          elif .value[-1] < .value[0] then "improving"
          elif .value[-1] > .value[0] then "degrading"
          else "stable"
          end
        ),
        env_attributions: []
      }
  ]
  | sort_by(.id)
')"

summary="$(jq -n \
  --argjson cases "${json_cases}" \
  --arg generated_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --arg kernel "${KERNEL}" \
  --argjson iterations "${ITERATIONS}" \
  '{ generated_at: $generated_at, kernel: $kernel, iterations: $iterations, cases: $cases }')"

output_file="${ARTIFACTS_DIR}/trend_summary.json"
mkdir -p "$(dirname "${output_file}")"
echo "${summary}" | jq '.' > "${output_file}"

echo "trend_summary written to ${output_file}"
echo "${summary}" | jq '.cases[] | "\(.id): trend=\(.trend) scores=\(.scores)"' -r

# Append to history (JSONL format)
history_file="${ARTIFACTS_DIR}/trend_history.jsonl"
history_entry="$(jq -c --arg ts "$(date -u +%Y-%m-%dT%H:%M:%SZ)" '. + {timestamp: $ts}' <<< "${summary}")"
echo "${history_entry}" >> "${history_file}"
echo "trend_history appended to ${history_file}"

# Regression detection: check if strict cases degraded >10% over last 5 runs
if [[ -f "${history_file}" ]]; then
  recent_count="$(wc -l < "${history_file}" | tr -d ' ')"
  if (( recent_count >= 2 )); then
    echo
    echo "=== regression check (last ${recent_count} runs, max 5) ==="

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
