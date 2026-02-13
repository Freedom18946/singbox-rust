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
INTEROP_SKIP_APP_BUILD="${INTEROP_SKIP_APP_BUILD:-0}"

# --- Threshold configuration ---
# If THRESHOLD_CONFIG points to a YAML file and THRESHOLD_TEMPLATE names a
# section (strict / env_limited / development), thresholds are read from that
# file. Otherwise the hardcoded defaults below are used. Individual env-var
# overrides still win when set explicitly.

THRESHOLD_CONFIG="${THRESHOLD_CONFIG:-}"
THRESHOLD_TEMPLATE="${THRESHOLD_TEMPLATE:-}"

# Helper: read a value from the YAML config under the chosen template section.
# Uses plain grep+sed so we don't require yq on the runner.
# Usage: _yaml_val <key> <default>
_yaml_val() {
  local key="$1" default="$2"
  if [[ -z "${THRESHOLD_CONFIG}" || -z "${THRESHOLD_TEMPLATE}" ]]; then
    printf '%s' "${default}"
    return
  fi
  if [[ ! -f "${THRESHOLD_CONFIG}" ]]; then
    echo "warn: THRESHOLD_CONFIG=${THRESHOLD_CONFIG} not found, using defaults" >&2
    printf '%s' "${default}"
    return
  fi
  local value
  value="$(sed -n "/^${THRESHOLD_TEMPLATE}:/,/^[^ ]/{
    s/^[[:space:]]*${key}:[[:space:]]*//p
  }" "${THRESHOLD_CONFIG}" | head -n 1)"
  if [[ -z "${value}" ]]; then
    printf '%s' "${default}"
    return
  fi
  case "${value}" in
    true|True|TRUE) printf '1' ;;
    false|False|FALSE) printf '0' ;;
    *) printf '%s' "${value}" ;;
  esac
}

MAX_RUST_ERRORS="${MAX_RUST_ERRORS:-$(_yaml_val max_rust_errors 0)}"
MAX_FAILED_TRAFFIC="${MAX_FAILED_TRAFFIC:-$(_yaml_val max_failed_traffic 0)}"
MAX_HTTP_MISMATCHES="${MAX_HTTP_MISMATCHES:-$(_yaml_val max_http_mismatches 0)}"
MAX_WS_MISMATCHES="${MAX_WS_MISMATCHES:-$(_yaml_val max_ws_mismatches 0)}"
MAX_SUB_MISMATCHES="${MAX_SUB_MISMATCHES:-$(_yaml_val max_sub_mismatches 0)}"
MAX_TRAFFIC_MISMATCHES="${MAX_TRAFFIC_MISMATCHES:-$(_yaml_val max_traffic_mismatches 0)}"

ALLOW_MISSING_DIFF="${ALLOW_MISSING_DIFF:-$(_yaml_val allow_missing_diff 1)}"
ENFORCE_NON_INCREASING_SCORE="${ENFORCE_NON_INCREASING_SCORE:-$(_yaml_val enforce_non_increasing_score 1)}"

if [[ -n "${THRESHOLD_CONFIG}" && -n "${THRESHOLD_TEMPLATE}" && -f "${THRESHOLD_CONFIG}" ]]; then
  echo "threshold-config: file=${THRESHOLD_CONFIG} template=${THRESHOLD_TEMPLATE}"
fi

if ! command -v jq >/dev/null 2>&1; then
  echo "error: jq is required by run_case_trend_gate.sh"
  exit 2
fi

if [[ "${INTEROP_SKIP_APP_BUILD}" != "1" ]]; then
  echo "prebuild: cargo build -p app --features acceptance --bin app"
  cargo build -p app --features acceptance --bin app >/dev/null
fi

echo "trend-gate case=${CASE_ID} iterations=${ITERATIONS} kernel=${KERNEL} priority=${RUN_PRIORITY:-none} env_class=${RUN_ENV_CLASS:-none} artifacts_dir=${ARTIFACTS_DIR}"

prev_score=-1

for ((i = 1; i <= ITERATIONS; i++)); do
  echo
  echo "=== iteration ${i}/${ITERATIONS}: case run ${CASE_ID} ==="

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

  run_dirs=()
  while IFS= read -r run_dir; do
    if [[ -n "${run_dir}" ]]; then
      run_dirs+=("${run_dir}")
    fi
  done < <(printf '%s\n' "${run_output}" | sed -n 's/^run_dir=//p')

  if [[ ${#run_dirs[@]} -eq 0 ]]; then
    echo "error: run_dir not found in case run output"
    exit 1
  fi

  iteration_score=0

  for run_dir in "${run_dirs[@]}"; do
    rust_snapshot="${run_dir}/rust.snapshot.json"
    if [[ ! -f "${rust_snapshot}" ]]; then
      echo "error: missing rust snapshot: ${rust_snapshot}"
      exit 1
    fi

    case_id="$(jq -r '.case_id // empty' "${rust_snapshot}")"
    if [[ -z "${case_id}" ]]; then
      case_id="$(basename "$(dirname "${run_dir}")")"
    fi

    rust_errors="$(jq '.errors | length' "${rust_snapshot}")"
    failed_traffic="$(jq '[.traffic_results[]? | select(.success != true)] | length' "${rust_snapshot}")"

    if (( rust_errors > MAX_RUST_ERRORS )); then
      echo "error: case=${case_id} rust errors ${rust_errors} exceed gate ${MAX_RUST_ERRORS}"
      exit 1
    fi
    if (( failed_traffic > MAX_FAILED_TRAFFIC )); then
      echo "error: case=${case_id} failed traffic ${failed_traffic} exceed gate ${MAX_FAILED_TRAFFIC}"
      exit 1
    fi

    http_mismatches=0
    ws_mismatches=0
    sub_mismatches=0
    traffic_mismatches=0

    diff_case_id="${case_id}"
    if [[ -n "${CASE_ID}" && "${CASE_ID}" != "ALL" ]]; then
      diff_case_id="${CASE_ID}"
    fi

    echo "=== iteration ${i}/${ITERATIONS}: case diff ${diff_case_id} ==="
    diff_output_file="$(mktemp)"
    if cargo run -p interop-lab -- --artifacts-dir "${ARTIFACTS_DIR}" case diff "${diff_case_id}" >"${diff_output_file}" 2>&1; then
      cat "${diff_output_file}"
      http_mismatches="$(awk -F= '/^http_mismatches=/{print $2}' "${diff_output_file}" | tail -n 1)"
      ws_mismatches="$(awk -F= '/^ws_mismatches=/{print $2}' "${diff_output_file}" | tail -n 1)"
      sub_mismatches="$(awk -F= '/^subscription_mismatches=/{print $2}' "${diff_output_file}" | tail -n 1)"
      traffic_mismatches="$(awk -F= '/^traffic_mismatches=/{print $2}' "${diff_output_file}" | tail -n 1)"
    else
      cat "${diff_output_file}"
      if [[ "${ALLOW_MISSING_DIFF}" != "1" ]]; then
        echo "error: case=${diff_case_id} case diff failed and ALLOW_MISSING_DIFF=0"
        rm -f "${diff_output_file}"
        exit 1
      fi
      echo "warn: case=${diff_case_id} case diff unavailable, skipping mismatch gates for this iteration"
    fi
    rm -f "${diff_output_file}"

    http_mismatches="${http_mismatches:-0}"
    ws_mismatches="${ws_mismatches:-0}"
    sub_mismatches="${sub_mismatches:-0}"
    traffic_mismatches="${traffic_mismatches:-0}"

    if (( http_mismatches > MAX_HTTP_MISMATCHES )); then
      echo "error: case=${case_id} http mismatches ${http_mismatches} exceed gate ${MAX_HTTP_MISMATCHES}"
      exit 1
    fi
    if (( ws_mismatches > MAX_WS_MISMATCHES )); then
      echo "error: case=${case_id} ws mismatches ${ws_mismatches} exceed gate ${MAX_WS_MISMATCHES}"
      exit 1
    fi
    if (( sub_mismatches > MAX_SUB_MISMATCHES )); then
      echo "error: case=${case_id} subscription mismatches ${sub_mismatches} exceed gate ${MAX_SUB_MISMATCHES}"
      exit 1
    fi
    if (( traffic_mismatches > MAX_TRAFFIC_MISMATCHES )); then
      echo "error: case=${case_id} traffic mismatches ${traffic_mismatches} exceed gate ${MAX_TRAFFIC_MISMATCHES}"
      exit 1
    fi

    case_score=$((rust_errors + failed_traffic + http_mismatches + ws_mismatches + sub_mismatches + traffic_mismatches))
    iteration_score=$((iteration_score + case_score))

    echo "iteration ${i} case=${case_id} score=${case_score} (errors=${rust_errors}, failed_traffic=${failed_traffic}, http=${http_mismatches}, ws=${ws_mismatches}, sub=${sub_mismatches}, traffic=${traffic_mismatches})"
  done

  echo "iteration ${i} total_score=${iteration_score}"

  if [[ "${ENFORCE_NON_INCREASING_SCORE}" == "1" ]] && (( prev_score >= 0 )) && (( iteration_score > prev_score )); then
    echo "error: trend gate violated (total score increased ${prev_score} -> ${iteration_score})"
    exit 1
  fi
  prev_score="${iteration_score}"
done

echo
echo "trend-gate passed for case=${CASE_ID} iterations=${ITERATIONS}"
