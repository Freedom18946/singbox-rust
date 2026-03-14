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
MANAGE_GO_ORACLE="${MANAGE_GO_ORACLE:-0}"
GO_ORACLE_BIN="${GO_ORACLE_BIN:-go_fork_source/sing-box-1.12.14/sing-box}"
GO_ORACLE_CONFIG="${GO_ORACLE_CONFIG:-labs/interop-lab/configs/l18_gui_go.json}"
GO_ORACLE_API_URL="${GO_ORACLE_API_URL:-http://127.0.0.1:9090}"
GO_ORACLE_API_SECRET="${GO_ORACLE_API_SECRET:-test-secret}"
GO_ORACLE_BUILD_IF_MISSING="${GO_ORACLE_BUILD_IF_MISSING:-1}"
GO_ORACLE_LOG="${GO_ORACLE_LOG:-/tmp/interop-go-oracle.log}"
GO_ORACLE_PID=""

# --- Threshold configuration ---
THRESHOLD_CONFIG="${THRESHOLD_CONFIG:-}"
THRESHOLD_TEMPLATE="${THRESHOLD_TEMPLATE:-}"

# Optional case-level allowlist (with expiry) for known blockers in ALL mode.
TREND_ALLOWLIST_FILE="${TREND_ALLOWLIST_FILE:-labs/interop-lab/configs/trend_gate_allowlist.json}"

# Enable environment-limited classification and subtract from functional gates.
CLASSIFY_ENV_LIMITED="${CLASSIFY_ENV_LIMITED:-1}"

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
MAX_CONNECTION_MISMATCHES="${MAX_CONNECTION_MISMATCHES:-$(_yaml_val max_connection_mismatches 0)}"
MAX_MEMORY_MISMATCHES="${MAX_MEMORY_MISMATCHES:-$(_yaml_val max_memory_mismatches 0)}"

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
  echo "prebuild: cargo build -p app --features acceptance,clash_api --bin app"
  cargo build -p app --features acceptance,clash_api --bin app >/dev/null
fi

if [[ -f "${TREND_ALLOWLIST_FILE}" ]]; then
  echo "trend-allowlist: ${TREND_ALLOWLIST_FILE}"
fi

echo "trend-gate case=${CASE_ID} iterations=${ITERATIONS} kernel=${KERNEL} priority=${RUN_PRIORITY:-none} env_class=${RUN_ENV_CLASS:-none} artifacts_dir=${ARTIFACTS_DIR}"

check_port_free() {
  local port="$1"
  ! lsof -nP -iTCP:"${port}" -sTCP:LISTEN >/dev/null 2>&1
}

api_port_from_url() {
  local url="$1"
  python3 - "$url" <<'PY'
import sys
from urllib.parse import urlparse

u = urlparse(sys.argv[1])
print(u.port or "")
PY
}

ensure_go_oracle_binary() {
  if [[ -x "${GO_ORACLE_BIN}" ]]; then
    return 0
  fi
  if [[ "${GO_ORACLE_BUILD_IF_MISSING}" != "1" ]]; then
    echo "error: go oracle binary missing and auto-build disabled: ${GO_ORACLE_BIN}" >&2
    return 1
  fi
  if ! command -v go >/dev/null 2>&1; then
    echo "error: go command not found; cannot auto-build oracle" >&2
    return 1
  fi
  local go_src
  go_src="$(dirname "${GO_ORACLE_BIN}")"
  if [[ ! -d "${go_src}" ]]; then
    echo "error: go oracle source dir missing: ${go_src}" >&2
    return 1
  fi
  echo "go-oracle: building ${GO_ORACLE_BIN}"
  (
    cd "${go_src}"
    go build -tags with_clash_api -ldflags "-s -w" -o "$(basename "${GO_ORACLE_BIN}")" ./cmd/sing-box
  )
}

stop_managed_go_oracle() {
  if [[ -n "${GO_ORACLE_PID}" ]] && kill -0 "${GO_ORACLE_PID}" >/dev/null 2>&1; then
    kill "${GO_ORACLE_PID}" >/dev/null 2>&1 || true
    sleep 0.5
    kill -0 "${GO_ORACLE_PID}" >/dev/null 2>&1 && kill -9 "${GO_ORACLE_PID}" >/dev/null 2>&1 || true
  fi
}

start_managed_go_oracle() {
  local api_port
  api_port="$(api_port_from_url "${GO_ORACLE_API_URL}")"
  if [[ -z "${api_port}" ]]; then
    echo "error: failed to parse go oracle api port from ${GO_ORACLE_API_URL}" >&2
    return 1
  fi
  if ! check_port_free "${api_port}"; then
    echo "error: go oracle port already in use: ${api_port}" >&2
    lsof -nP -iTCP:"${api_port}" -sTCP:LISTEN >&2 || true
    return 1
  fi
  if [[ ! -f "${GO_ORACLE_CONFIG}" ]]; then
    echo "error: go oracle config missing: ${GO_ORACLE_CONFIG}" >&2
    return 1
  fi
  ensure_go_oracle_binary
  echo "go-oracle: starting bin=${GO_ORACLE_BIN} config=${GO_ORACLE_CONFIG} api=${GO_ORACLE_API_URL}"
  : > "${GO_ORACLE_LOG}"
  "${GO_ORACLE_BIN}" run -c "${GO_ORACLE_CONFIG}" >"${GO_ORACLE_LOG}" 2>&1 &
  GO_ORACLE_PID="$!"
  for _ in $(seq 1 120); do
    local code
    code="$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer ${GO_ORACLE_API_SECRET}" "${GO_ORACLE_API_URL}/version" || true)"
    if [[ "${code}" == "200" || "${code}" == "204" || "${code}" == "401" ]]; then
      echo "go-oracle: ready pid=${GO_ORACLE_PID} api=${GO_ORACLE_API_URL}"
      return 0
    fi
    sleep 0.25
  done
  echo "error: go oracle health check failed: ${GO_ORACLE_API_URL}" >&2
  [[ -f "${GO_ORACLE_LOG}" ]] && tail -n 50 "${GO_ORACLE_LOG}" >&2 || true
  stop_managed_go_oracle
  return 1
}

cleanup() {
  stop_managed_go_oracle
}
trap cleanup EXIT

if [[ "${KERNEL}" == "both" && "${MANAGE_GO_ORACLE}" == "1" ]]; then
  start_managed_go_oracle
fi

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

  # Keep launch-kernel readiness failures as functional by default.
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
  local unknown_count=0
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
      *)
        unknown_count=$((unknown_count + 1))
        ;;
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
      *)
        unknown_count=$((unknown_count + 1))
        ;;
    esac
  done < <(jq -rc '.traffic_results[]? | select(.success != true) | .detail' "${snapshot}")

  categories_csv="${categories_csv%,}"
  printf '%s\t%s\t%s\t%s\n' "${env_error_count}" "${env_traffic_count}" "${unknown_count}" "${categories_csv}"
}

_case_allowlisted() {
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
    echo "warn: allowlist expired case=${case_id} expires_on=${expires_on}"
    return 1
  fi

  local reason
  reason="$(jq -r '.reason // "allowlisted temporary waiver"' <<< "${entry}")"
  echo "warn: allowlist suppress case=${case_id} until=${expires_on} reason=${reason}"
  return 0
}

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
    IFS=',' read -r -a _tags <<< "${RUN_TAGS}"
    for _tag in "${_tags[@]}"; do
      if [[ -n "${_tag}" ]]; then
        run_cmd+=(--tag "${_tag}")
      fi
    done
  fi
  if [[ -n "${RUN_EXCLUDE_TAGS}" ]]; then
    IFS=',' read -r -a _ex_tags <<< "${RUN_EXCLUDE_TAGS}"
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
  iteration_failed=0
  iteration_waived=0
  total_raw_errors=0
  total_raw_failed_traffic=0
  total_env_errors=0
  total_env_failed_traffic=0

  for run_dir in "${run_dirs[@]}"; do
    rust_snapshot="${run_dir}/rust.snapshot.json"
    if [[ ! -f "${rust_snapshot}" ]]; then
      echo "error: missing rust snapshot: ${rust_snapshot}"
      exit 1
    fi
    go_snapshot="${run_dir}/go.snapshot.json"

    case_id="$(jq -r '.case_id // empty' "${rust_snapshot}")"
    if [[ -z "${case_id}" ]]; then
      case_id="$(basename "$(dirname "${run_dir}")")"
    fi

    rust_errors="$(jq '.errors | length' "${rust_snapshot}")"
    failed_traffic="$(jq '[.traffic_results[]? | select(.success != true)] | length' "${rust_snapshot}")"

    functional_rust_errors="${rust_errors}"
    functional_failed_traffic="${failed_traffic}"
    env_error_count=0
    env_traffic_count=0
    unknown_env_count=0
    env_categories=""

    if [[ "${CLASSIFY_ENV_LIMITED}" == "1" ]]; then
      IFS=$'\t' read -r env_error_count env_traffic_count unknown_env_count env_categories \
        <<< "$(_collect_env_limited_counts "${rust_snapshot}")"
      functional_rust_errors=$((rust_errors - env_error_count))
      functional_failed_traffic=$((failed_traffic - env_traffic_count))
      if (( functional_rust_errors < 0 )); then
        functional_rust_errors=0
      fi
      if (( functional_failed_traffic < 0 )); then
        functional_failed_traffic=0
      fi
    fi

    total_raw_errors=$((total_raw_errors + rust_errors))
    total_raw_failed_traffic=$((total_raw_failed_traffic + failed_traffic))
    total_env_errors=$((total_env_errors + env_error_count))
    total_env_failed_traffic=$((total_env_failed_traffic + env_traffic_count))

    http_mismatches=0
    ws_mismatches=0
    sub_mismatches=0
    traffic_mismatches=0
    connection_mismatches=0
    memory_mismatches=0

    diff_case_id="${case_id}"
    if [[ -n "${CASE_ID}" && "${CASE_ID}" != "ALL" ]]; then
      diff_case_id="${CASE_ID}"
    fi

    case_failed=0
    case_failure_reasons=""

    if [[ ! -f "${go_snapshot}" ]]; then
      echo "warn: case=${diff_case_id} go snapshot missing, skip case diff for single-kernel run"
    else
      echo "=== iteration ${i}/${ITERATIONS}: case diff ${diff_case_id} ==="
      diff_output_file="$(mktemp)"
      if cargo run -p interop-lab -- --artifacts-dir "${ARTIFACTS_DIR}" case diff "${diff_case_id}" >"${diff_output_file}" 2>&1; then
        cat "${diff_output_file}"
        http_mismatches="$(awk -F= '/^http_mismatches=/{print $2}' "${diff_output_file}" | tail -n 1)"
        ws_mismatches="$(awk -F= '/^ws_mismatches=/{print $2}' "${diff_output_file}" | tail -n 1)"
        sub_mismatches="$(awk -F= '/^subscription_mismatches=/{print $2}' "${diff_output_file}" | tail -n 1)"
        traffic_mismatches="$(awk -F= '/^traffic_mismatches=/{print $2}' "${diff_output_file}" | tail -n 1)"
        connection_mismatches="$(awk -F= '/^connection_mismatches=/{print $2}' "${diff_output_file}" | tail -n 1)"
        memory_mismatches="$(awk -F= '/^memory_mismatches=/{print $2}' "${diff_output_file}" | tail -n 1)"
      else
        cat "${diff_output_file}"
        if [[ "${ALLOW_MISSING_DIFF}" != "1" ]]; then
          case_failed=1
          case_failure_reasons+="diff unavailable and ALLOW_MISSING_DIFF=0\n"
        else
          echo "warn: case=${diff_case_id} case diff unavailable, skipping mismatch gates for this iteration"
        fi
      fi
      rm -f "${diff_output_file}"
    fi

    http_mismatches="${http_mismatches:-0}"
    ws_mismatches="${ws_mismatches:-0}"
    sub_mismatches="${sub_mismatches:-0}"
    traffic_mismatches="${traffic_mismatches:-0}"
    connection_mismatches="${connection_mismatches:-0}"
    memory_mismatches="${memory_mismatches:-0}"

    if (( functional_rust_errors > MAX_RUST_ERRORS )); then
      case_failed=1
      case_failure_reasons+="functional rust errors ${functional_rust_errors} exceed gate ${MAX_RUST_ERRORS} (raw=${rust_errors}, env_limited=${env_error_count})\n"
    fi
    if (( functional_failed_traffic > MAX_FAILED_TRAFFIC )); then
      case_failed=1
      case_failure_reasons+="functional failed traffic ${functional_failed_traffic} exceed gate ${MAX_FAILED_TRAFFIC} (raw=${failed_traffic}, env_limited=${env_traffic_count})\n"
    fi
    if (( http_mismatches > MAX_HTTP_MISMATCHES )); then
      case_failed=1
      case_failure_reasons+="http mismatches ${http_mismatches} exceed gate ${MAX_HTTP_MISMATCHES}\n"
    fi
    if (( ws_mismatches > MAX_WS_MISMATCHES )); then
      case_failed=1
      case_failure_reasons+="ws mismatches ${ws_mismatches} exceed gate ${MAX_WS_MISMATCHES}\n"
    fi
    if (( sub_mismatches > MAX_SUB_MISMATCHES )); then
      case_failed=1
      case_failure_reasons+="subscription mismatches ${sub_mismatches} exceed gate ${MAX_SUB_MISMATCHES}\n"
    fi
    if (( traffic_mismatches > MAX_TRAFFIC_MISMATCHES )); then
      case_failed=1
      case_failure_reasons+="traffic mismatches ${traffic_mismatches} exceed gate ${MAX_TRAFFIC_MISMATCHES}\n"
    fi
    if (( connection_mismatches > MAX_CONNECTION_MISMATCHES )); then
      case_failed=1
      case_failure_reasons+="connection mismatches ${connection_mismatches} exceed gate ${MAX_CONNECTION_MISMATCHES}\n"
    fi
    if (( memory_mismatches > MAX_MEMORY_MISMATCHES )); then
      case_failed=1
      case_failure_reasons+="memory mismatches ${memory_mismatches} exceed gate ${MAX_MEMORY_MISMATCHES}\n"
    fi

    case_score=$((functional_rust_errors + functional_failed_traffic + http_mismatches + ws_mismatches + sub_mismatches + traffic_mismatches + connection_mismatches + memory_mismatches))

    if (( case_failed == 1 )); then
      if _case_allowlisted "${case_id}"; then
        iteration_waived=$((iteration_waived + 1))
        echo "warn: case=${case_id} failure suppressed by allowlist"
        printf '%b' "${case_failure_reasons}" | sed 's/^/warn:   /'
      else
        iteration_failed=1
        printf '%b' "${case_failure_reasons}" | sed "s/^/error: case=${case_id} /"
      fi
    else
      iteration_score=$((iteration_score + case_score))
    fi

    echo "iteration ${i} case=${case_id} score=${case_score} (functional_errors=${functional_rust_errors}, functional_failed_traffic=${functional_failed_traffic}, http=${http_mismatches}, ws=${ws_mismatches}, sub=${sub_mismatches}, traffic=${traffic_mismatches}, connections=${connection_mismatches}, memory=${memory_mismatches}, raw_errors=${rust_errors}, raw_failed_traffic=${failed_traffic}, env_errors=${env_error_count}, env_failed_traffic=${env_traffic_count}, env_unknown=${unknown_env_count}, env_categories=${env_categories:-none})"
  done

  echo "iteration ${i} total_score=${iteration_score} waived_cases=${iteration_waived}"
  echo "iteration ${i} totals raw_errors=${total_raw_errors} raw_failed_traffic=${total_raw_failed_traffic} env_errors=${total_env_errors} env_failed_traffic=${total_env_failed_traffic}"

  if [[ "${ENFORCE_NON_INCREASING_SCORE}" == "1" ]] && (( prev_score >= 0 )) && (( iteration_score > prev_score )); then
    echo "error: trend gate violated (total score increased ${prev_score} -> ${iteration_score})"
    exit 1
  fi

  if (( iteration_failed == 1 )); then
    echo "error: trend gate failed for iteration ${i}"
    exit 1
  fi

  prev_score="${iteration_score}"
done

echo
echo "trend-gate passed for case=${CASE_ID} iterations=${ITERATIONS}"
