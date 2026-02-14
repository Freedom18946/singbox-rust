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

if ! command -v jq >/dev/null 2>&1; then
  echo "error: jq is required by aggregate_trend_report.sh"
  exit 2
fi

if [[ "${INTEROP_SKIP_APP_BUILD}" != "1" ]]; then
  echo "prebuild: cargo build -p app --features acceptance --bin app"
  cargo build -p app --features acceptance --bin app >/dev/null
fi

echo "aggregate-trend case=${CASE_ID:-ALL} iterations=${ITERATIONS} kernel=${KERNEL} artifacts_dir=${ARTIFACTS_DIR}"

_to_lower() {
  printf '%s' "$1" | tr '[:upper:]' '[:lower:]'
}

_classify_env_limited_category() {
  local text_lc
  text_lc="$(_to_lower "$1")"

  if [[ "${text_lc}" == *'"status":403'* || "${text_lc}" == *'"status":429'* || "${text_lc}" == *'"status":503'* || \
        "${text_lc}" == *'status=403'* || "${text_lc}" == *'status=429'* || "${text_lc}" == *'status=503'* || \
        "${text_lc}" == *'rate limit'* || "${text_lc}" == *'too many requests'* ]]; then
    printf 'rate_limit'
    return
  fi

  if [[ "${text_lc}" == *'tls'* || "${text_lc}" == *'handshake'* || "${text_lc}" == *'certificate'* || "${text_lc}" == *'ssl'* ]]; then
    printf 'tls'
    return
  fi

  if [[ "${text_lc}" == *'kernel not ready'* ]]; then
    printf 'unknown'
    return
  fi

  if [[ "${text_lc}" == *'connection refused'* || "${text_lc}" == *'connect error'* || \
        "${text_lc}" == *'network unreachable'* || "${text_lc}" == *'no route to host'* || \
        "${text_lc}" == *'connection reset'* || "${text_lc}" == *'timeout'* || "${text_lc}" == *'timed out'* ]]; then
    printf 'network'
    return
  fi

  printf 'unknown'
}

_collect_env_limited_counts() {
  local snapshot="$1"
  local env_error_count=0
  local env_traffic_count=0
  local categories_csv=""

  while IFS= read -r msg; do
    [[ -z "${msg}" ]] && continue
    local category
    category="$(_classify_env_limited_category "${msg}")"
    case "${category}" in
      rate_limit|network|tls)
        env_error_count=$((env_error_count + 1))
        categories_csv="${categories_csv}${category},"
        ;;
      *) ;;
    esac
  done < <(jq -r '.errors[]?.message // empty' "${snapshot}")

  while IFS= read -r detail; do
    [[ -z "${detail}" ]] && continue
    local category
    category="$(_classify_env_limited_category "${detail}")"
    case "${category}" in
      rate_limit|network|tls)
        env_traffic_count=$((env_traffic_count + 1))
        categories_csv="${categories_csv}${category},"
        ;;
      *) ;;
    esac
  done < <(jq -rc '.traffic_results[]? | select(.success != true) | .detail' "${snapshot}")

  categories_csv="${categories_csv%,}"
  printf '%s\t%s\t%s\n' "${env_error_count}" "${env_traffic_count}" "${categories_csv}"
}

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
      IFS=$'\t' read -r env_error_count env_traffic_count env_categories \
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
