#!/usr/bin/env bash
set -euo pipefail

CASE_ID="${1:-p2_connections_ws_soak_suite}"
ITERATIONS="${ITERATIONS:-3}"
KERNEL="${KERNEL:-rust}"
ARTIFACTS_DIR="${ARTIFACTS_DIR:-labs/interop-lab/artifacts}"
RUN_PRIORITY="${RUN_PRIORITY:-}"
RUN_TAGS="${RUN_TAGS:-}"
RUN_EXCLUDE_TAGS="${RUN_EXCLUDE_TAGS:-}"
RUN_ENV_CLASS="${RUN_ENV_CLASS:-}"

MAX_RUST_ERRORS="${MAX_RUST_ERRORS:-0}"
MAX_FAILED_TRAFFIC="${MAX_FAILED_TRAFFIC:-0}"
MAX_HTTP_MISMATCHES="${MAX_HTTP_MISMATCHES:-0}"
MAX_WS_MISMATCHES="${MAX_WS_MISMATCHES:-0}"
MAX_SUB_MISMATCHES="${MAX_SUB_MISMATCHES:-0}"
MAX_TRAFFIC_MISMATCHES="${MAX_TRAFFIC_MISMATCHES:-0}"

ALLOW_MISSING_DIFF="${ALLOW_MISSING_DIFF:-1}"
ENFORCE_NON_INCREASING_SCORE="${ENFORCE_NON_INCREASING_SCORE:-1}"

if ! command -v jq >/dev/null 2>&1; then
  echo "error: jq is required by run_case_trend_gate.sh"
  exit 2
fi

echo "trend-gate case=${CASE_ID} iterations=${ITERATIONS} kernel=${KERNEL} priority=${RUN_PRIORITY:-none} env_class=${RUN_ENV_CLASS:-none}"

prev_score=-1

for ((i = 1; i <= ITERATIONS; i++)); do
  echo
  echo "=== iteration ${i}/${ITERATIONS}: case run ${CASE_ID} ==="
  run_cmd=(cargo run -p interop-lab -- case run)
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
  if [[ -n "${RUN_TAGS}" ]]; then
    IFS=',' read -r -a _tags <<<"${RUN_TAGS}"
    for _tag in "${_tags[@]}"; do
      if [[ -n "${_tag}" ]]; then
        run_cmd+=(--tag "${_tag}")
      fi
    done
  fi
  if [[ -n "${RUN_EXCLUDE_TAGS}" ]]; then
    IFS=',' read -r -a _ex_tags <<<"${RUN_EXCLUDE_TAGS}"
    for _tag in "${_ex_tags[@]}"; do
      if [[ -n "${_tag}" ]]; then
        run_cmd+=(--exclude-tag "${_tag}")
      fi
    done
  fi
  run_output="$("${run_cmd[@]}")"
  echo "${run_output}"

  run_dir="$(printf '%s\n' "${run_output}" | sed -n 's/^run_dir=//p' | tail -n 1)"
  if [[ -z "${run_dir}" ]]; then
    echo "error: run_dir not found in case run output"
    exit 1
  fi

  rust_snapshot="${run_dir}/rust.snapshot.json"
  if [[ ! -f "${rust_snapshot}" ]]; then
    echo "error: missing rust snapshot: ${rust_snapshot}"
    exit 1
  fi

  rust_errors="$(jq '.errors | length' "${rust_snapshot}")"
  failed_traffic="$(jq '[.traffic_results[]? | select(.success != true)] | length' "${rust_snapshot}")"

  if (( rust_errors > MAX_RUST_ERRORS )); then
    echo "error: rust errors ${rust_errors} exceed gate ${MAX_RUST_ERRORS}"
    exit 1
  fi
  if (( failed_traffic > MAX_FAILED_TRAFFIC )); then
    echo "error: failed traffic ${failed_traffic} exceed gate ${MAX_FAILED_TRAFFIC}"
    exit 1
  fi

  http_mismatches=0
  ws_mismatches=0
  sub_mismatches=0
  traffic_mismatches=0

  echo "=== iteration ${i}/${ITERATIONS}: case diff ${CASE_ID} ==="
  diff_output_file="$(mktemp)"
  if cargo run -p interop-lab -- case diff "${CASE_ID}" >"${diff_output_file}" 2>&1; then
    cat "${diff_output_file}"
    http_mismatches="$(awk -F= '/^http_mismatches=/{print $2}' "${diff_output_file}" | tail -n 1)"
    ws_mismatches="$(awk -F= '/^ws_mismatches=/{print $2}' "${diff_output_file}" | tail -n 1)"
    sub_mismatches="$(awk -F= '/^subscription_mismatches=/{print $2}' "${diff_output_file}" | tail -n 1)"
    traffic_mismatches="$(awk -F= '/^traffic_mismatches=/{print $2}' "${diff_output_file}" | tail -n 1)"
  else
    cat "${diff_output_file}"
    if [[ "${ALLOW_MISSING_DIFF}" != "1" ]]; then
      echo "error: case diff failed and ALLOW_MISSING_DIFF=0"
      rm -f "${diff_output_file}"
      exit 1
    fi
    echo "warn: case diff unavailable, skipping mismatch gates for this iteration"
  fi
  rm -f "${diff_output_file}"

  if (( http_mismatches > MAX_HTTP_MISMATCHES )); then
    echo "error: http mismatches ${http_mismatches} exceed gate ${MAX_HTTP_MISMATCHES}"
    exit 1
  fi
  if (( ws_mismatches > MAX_WS_MISMATCHES )); then
    echo "error: ws mismatches ${ws_mismatches} exceed gate ${MAX_WS_MISMATCHES}"
    exit 1
  fi
  if (( sub_mismatches > MAX_SUB_MISMATCHES )); then
    echo "error: subscription mismatches ${sub_mismatches} exceed gate ${MAX_SUB_MISMATCHES}"
    exit 1
  fi
  if (( traffic_mismatches > MAX_TRAFFIC_MISMATCHES )); then
    echo "error: traffic mismatches ${traffic_mismatches} exceed gate ${MAX_TRAFFIC_MISMATCHES}"
    exit 1
  fi

  score=$((rust_errors + failed_traffic + http_mismatches + ws_mismatches + sub_mismatches + traffic_mismatches))
  echo "iteration ${i} score=${score} (errors=${rust_errors}, failed_traffic=${failed_traffic}, http=${http_mismatches}, ws=${ws_mismatches}, sub=${sub_mismatches}, traffic=${traffic_mismatches})"

  if [[ "${ENFORCE_NON_INCREASING_SCORE}" == "1" ]] && (( prev_score >= 0 )) && (( score > prev_score )); then
    echo "error: trend gate violated (score increased ${prev_score} -> ${score})"
    exit 1
  fi
  prev_score="${score}"
done

echo
echo "trend-gate passed for case=${CASE_ID} iterations=${ITERATIONS}"
