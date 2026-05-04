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
CLASSIFY_ENV_LIMITED="${CLASSIFY_ENV_LIMITED:-1}"
TREND_ALLOWLIST_FILE="${TREND_ALLOWLIST_FILE:-labs/interop-lab/configs/trend_gate_allowlist.json}"
MANAGE_GO_ORACLE="${MANAGE_GO_ORACLE:-0}"
GO_ORACLE_BIN="${GO_ORACLE_BIN:-go_fork_source/sing-box-1.12.14/sing-box}"
GO_ORACLE_CONFIG="${GO_ORACLE_CONFIG:-labs/interop-lab/configs/l18_gui_go.json}"
GO_ORACLE_API_URL="${GO_ORACLE_API_URL:-http://127.0.0.1:9090}"
GO_ORACLE_API_SECRET="${GO_ORACLE_API_SECRET:-test-secret}"
GO_ORACLE_BUILD_IF_MISSING="${GO_ORACLE_BUILD_IF_MISSING:-1}"
GO_ORACLE_LOG="${GO_ORACLE_LOG:-/tmp/interop-go-oracle-aggregate.log}"
GO_ORACLE_PID=""

# shellcheck source=lib_go_oracle.sh
source "$(dirname "$0")/lib_go_oracle.sh"
# shellcheck source=lib_env_classify.sh
source "$(dirname "$0")/lib_env_classify.sh"

if ! command -v jq >/dev/null 2>&1; then
  echo "error: jq is required by aggregate_trend_report.sh"
  exit 2
fi

if [[ "${INTEROP_SKIP_APP_BUILD}" != "1" ]]; then
  echo "prebuild: cargo build -p app --features acceptance,clash_api,service_ssmapi --bin app"
  cargo build -p app --features acceptance,clash_api,service_ssmapi --bin app >/dev/null
fi

echo "aggregate-trend case=${CASE_ID:-ALL} iterations=${ITERATIONS} kernel=${KERNEL} artifacts_dir=${ARTIFACTS_DIR}"

cleanup() {
  stop_managed_go_oracle
}
trap cleanup EXIT

collect_selected_both_kernel_cases() {
  local case_list_output
  case_list_output="$(cargo run -q -p interop-lab -- case list)"

  while IFS=$'\t' read -r case_id priority kernel_mode env_class _tags; do
    [[ -z "${case_id}" ]] && continue
    if [[ -n "${CASE_ID}" && "${CASE_ID}" != "ALL" && "${case_id}" != "${CASE_ID}" ]]; then
      continue
    fi
    if [[ -n "${RUN_PRIORITY}" && "${priority}" != "${RUN_PRIORITY}" ]]; then
      continue
    fi

    local kernel_mode_lc env_class_lc
    kernel_mode_lc="$(_to_lower "${kernel_mode}")"
    env_class_lc="$(_to_lower "${env_class}")"
    if [[ "${env_class_lc}" == "envlimited" ]]; then
      env_class_lc="env_limited"
    fi
    if [[ -n "${RUN_ENV_CLASS}" && "${env_class_lc}" != "$(_to_lower "${RUN_ENV_CLASS}")" ]]; then
      continue
    fi
    if [[ "${kernel_mode_lc}" != "both" ]]; then
      continue
    fi
    printf '%s\n' "${case_id}"
  done <<< "${case_list_output}"
}

prepare_managed_go_oracle() {
  if [[ "${KERNEL}" != "both" || "${MANAGE_GO_ORACLE}" != "1" ]]; then
    return 0
  fi

  local selected_cases=()
  local selected_case
  while IFS= read -r selected_case; do
    [[ -z "${selected_case}" ]] && continue
    selected_cases+=("${selected_case}")
  done < <(collect_selected_both_kernel_cases)
  if [[ ${#selected_cases[@]} -eq 0 ]]; then
    echo "go-oracle: no selected both-kernel cases require evaluation"
    return 0
  fi

  local external_cases=()
  local managed_cases=()
  local case_id
  for case_id in "${selected_cases[@]}"; do
    if case_needs_external_go_oracle "${case_id}"; then
      external_cases+=("${case_id}")
    else
      managed_cases+=("${case_id}")
    fi
  done

  if [[ ${#external_cases[@]} -gt 0 && ${#managed_cases[@]} -gt 0 ]]; then
    echo "error: MANAGE_GO_ORACLE=1 selection mixes external-go and self-managed go cases" >&2
    echo "error: external-go cases: ${external_cases[*]}" >&2
    echo "error: self-managed cases: ${managed_cases[*]}" >&2
    echo "error: narrow CASE_ID / RUN_PRIORITY / RUN_ENV_CLASS, or disable MANAGE_GO_ORACLE" >&2
    return 1
  fi

  if [[ ${#external_cases[@]} -gt 0 ]]; then
    echo "go-oracle: managing external oracle for cases: ${external_cases[*]}"
    start_managed_go_oracle
  else
    echo "go-oracle: selected cases self-manage Go bootstrap; no external oracle needed"
  fi
}

prepare_managed_go_oracle

_case_allowlist_tag() {
  local case_id="$1"
  if [[ ! -f "${TREND_ALLOWLIST_FILE}" ]]; then
    return 1
  fi

  local entry
  entry="$(jq -c --arg id "${case_id}" '.cases[$id] // empty' "${TREND_ALLOWLIST_FILE}" 2>/dev/null || true)"
  if [[ -z "${entry}" ]]; then
    return 1
  fi

  local expires_on
  expires_on="$(jq -r '.expires_on // empty' <<< "${entry}")"
  if [[ -z "${expires_on}" ]]; then
    return 1
  fi

  local today
  today="$(date -u +%F)"
  if [[ "${expires_on}" < "${today}" ]]; then
    return 1
  fi

  printf 'allowlist:%s' "${expires_on}"
  return 0
}

# JSON map: { "case_id": [score1, score2, ...] }
scores_map='{}'
# JSON map: { "case_id": ["network", "rate_limit", ...] }
env_attr_map='{}'

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

  run_dir_count=0
  while IFS= read -r run_dir; do
    if [[ -z "${run_dir}" || ! -d "${run_dir}" ]]; then
      continue
    fi
    run_dir_count=$((run_dir_count + 1))

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

    env_error_count=0
    env_traffic_count=0
    env_categories=""
    if [[ "${CLASSIFY_ENV_LIMITED}" == "1" ]]; then
      IFS=$'\t' read -r env_error_count env_traffic_count _unknown_env_count env_categories \
        <<< "$(_collect_env_limited_counts "${rust_snapshot}")"
    fi

    functional_errors=$((rust_errors - env_error_count))
    functional_failed=$((failed_traffic - env_traffic_count))
    if (( functional_errors < 0 )); then
      functional_errors=0
    fi
    if (( functional_failed < 0 )); then
      functional_failed=0
    fi

    score=$((functional_errors + functional_failed))

    scores_map="$(jq \
      --arg id "${cid}" \
      --argjson score "${score}" \
      '.[$id] = ((.[$id] // []) + [$score])' \
      <<< "${scores_map}")"

    attrs_json='[]'
    if [[ -n "${env_categories}" ]]; then
      attrs_json="$(printf '%s' "${env_categories}" | tr ',' '\n' | sed '/^$/d' | jq -Rsc 'split("\n") | map(select(length > 0)) | unique')"
    fi

    if allowlist_tag="$(_case_allowlist_tag "${cid}")"; then
      attrs_json="$(jq --arg tag "${allowlist_tag}" '. + [$tag] | unique' <<< "${attrs_json}")"
    fi

    env_attr_map="$(jq \
      --arg id "${cid}" \
      --argjson attrs "${attrs_json}" \
      '.[$id] = ((.[$id] // []) + $attrs | unique)' \
      <<< "${env_attr_map}")"

    echo "  case=${cid} iteration=${i} score=${score} (functional_errors=${functional_errors}, functional_failed=${functional_failed}, raw_errors=${rust_errors}, raw_failed=${failed_traffic}, env_errors=${env_error_count}, env_failed=${env_traffic_count})"
  done < <(printf '%s\n' "${run_output}" | sed -n 's/^run_dir=//p')

  if (( run_dir_count == 0 )); then
    echo "error: no run_dir found from case run output"
    exit 1
  fi
done

echo
echo "=== generating trend_summary.json ==="

json_cases="$(jq -n --argjson m "${scores_map}" --argjson attr "${env_attr_map}" '
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
        env_attributions: ($attr[.key] // [])
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
echo "${summary}" | jq '.cases[] | "\(.id): trend=\(.trend) scores=\(.scores) env=\(.env_attributions)"' -r

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
