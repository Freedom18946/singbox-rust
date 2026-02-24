#!/usr/bin/env bash
set -u -o pipefail

usage() {
  cat <<'USAGE'
Usage:
  scripts/l18/l18_capstone.sh [--profile daily|nightly|certify] [--api-url URL] [--pid-file PATH] [--status-file PATH] [--go-api URL] [--go-token TOKEN] [--gui-app PATH] [--gui-sandbox-root PATH] [--allow-existing-system-proxy 0|1] [--allow-real-proxy-coexist 0|1] [--require-docker 0|1] [--fail-fast]

Profiles:
  daily: canary 1h
  nightly: canary 24h
  certify: canary 7d (168h)
USAGE
}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"

PROFILE="${L18_PROFILE:-daily}"
API_URL="${L18_CANARY_API_URL:-http://127.0.0.1:19090}"
PID_FILE="${L18_CANARY_PID_FILE:-}"
STATUS_FILE="${L18_STATUS_FILE:-${ROOT_DIR}/reports/l18/l18_capstone_status.json}"
GO_API="${INTEROP_GO_API_BASE:-}"
GO_TOKEN="${INTEROP_GO_API_TOKEN:-}"
GUI_APP="${L18_GUI_APP:-}"
GUI_SANDBOX_ROOT="${L18_GUI_SANDBOX_ROOT:-}"
ALLOW_EXISTING_SYSTEM_PROXY="${L18_ALLOW_EXISTING_SYSTEM_PROXY:-0}"
ALLOW_REAL_PROXY_COEXIST="${L18_ALLOW_REAL_PROXY_COEXIST:-0}"
REQUIRE_DOCKER="${L18_REQUIRE_DOCKER:-0}"
FAIL_FAST="${L18_FAIL_FAST:-0}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --profile)
      PROFILE="$2"
      shift 2
      ;;
    --api-url)
      API_URL="$2"
      shift 2
      ;;
    --pid-file)
      PID_FILE="$2"
      shift 2
      ;;
    --status-file)
      STATUS_FILE="$2"
      shift 2
      ;;
    --go-api)
      GO_API="$2"
      shift 2
      ;;
    --go-token)
      GO_TOKEN="$2"
      shift 2
      ;;
    --gui-app)
      GUI_APP="$2"
      shift 2
      ;;
    --gui-sandbox-root)
      GUI_SANDBOX_ROOT="$2"
      shift 2
      ;;
    --allow-existing-system-proxy)
      ALLOW_EXISTING_SYSTEM_PROXY="$2"
      shift 2
      ;;
    --allow-real-proxy-coexist)
      ALLOW_REAL_PROXY_COEXIST="$2"
      shift 2
      ;;
    --require-docker)
      REQUIRE_DOCKER="$2"
      shift 2
      ;;
    --fail-fast)
      FAIL_FAST=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      usage
      exit 2
      ;;
  esac
done

if [[ "$ALLOW_EXISTING_SYSTEM_PROXY" != "0" && "$ALLOW_EXISTING_SYSTEM_PROXY" != "1" ]]; then
  echo "--allow-existing-system-proxy must be 0 or 1" >&2
  exit 2
fi
if [[ "$ALLOW_REAL_PROXY_COEXIST" != "0" && "$ALLOW_REAL_PROXY_COEXIST" != "1" ]]; then
  echo "--allow-real-proxy-coexist must be 0 or 1" >&2
  exit 2
fi
if [[ "$REQUIRE_DOCKER" != "0" && "$REQUIRE_DOCKER" != "1" ]]; then
  echo "--require-docker must be 0 or 1" >&2
  exit 2
fi
if [[ "$FAIL_FAST" != "0" && "$FAIL_FAST" != "1" ]]; then
  echo "--fail-fast must be 0 or 1" >&2
  exit 2
fi

case "$PROFILE" in
  daily)
    HOT_ITER=20
    SIGNAL_ITER=5
    CANARY_HOURS=1
    CANARY_INTERVAL=300
    DUAL_PROFILE="daily"
    ;;
  nightly)
    HOT_ITER=100
    SIGNAL_ITER=10
    CANARY_HOURS=24
    CANARY_INTERVAL=900
    DUAL_PROFILE="nightly"
    ;;
  certify)
    HOT_ITER=100
    SIGNAL_ITER=10
    CANARY_HOURS=168
    CANARY_INTERVAL=3600
    DUAL_PROFILE="nightly"
    ;;
  *)
    echo "--profile must be daily|nightly|certify" >&2
    exit 2
    ;;
esac

mkdir -p "$(dirname "$STATUS_FILE")" "${ROOT_DIR}/reports/l18/stability"

PREFLIGHT_STATUS="NOT_RUN"
ORACLE_STATUS="NOT_RUN"
BOUNDARIES_STATUS="NOT_RUN"
PARITY_STATUS="NOT_RUN"
WORKSPACE_TEST_STATUS="NOT_RUN"
FMT_STATUS="NOT_RUN"
CLIPPY_STATUS="NOT_RUN"
HOT_RELOAD_STATUS="NOT_RUN"
SIGNAL_STATUS="NOT_RUN"
DOCKER_STATUS="NOT_RUN"
GUI_STATUS="NOT_RUN"
CANARY_STATUS="NOT_RUN"
DUAL_KERNEL_DIFF_STATUS="NOT_RUN"
PERF_GATE_STATUS="NOT_RUN"

HAS_FAIL=0

set_gate_status() {
  local key="$1"
  local value="$2"
  case "$key" in
    PREFLIGHT) PREFLIGHT_STATUS="$value" ;;
    ORACLE) ORACLE_STATUS="$value" ;;
    BOUNDARIES) BOUNDARIES_STATUS="$value" ;;
    PARITY) PARITY_STATUS="$value" ;;
    WORKSPACE_TEST) WORKSPACE_TEST_STATUS="$value" ;;
    FMT) FMT_STATUS="$value" ;;
    CLIPPY) CLIPPY_STATUS="$value" ;;
    HOT_RELOAD) HOT_RELOAD_STATUS="$value" ;;
    SIGNAL) SIGNAL_STATUS="$value" ;;
    DOCKER) DOCKER_STATUS="$value" ;;
    GUI) GUI_STATUS="$value" ;;
    CANARY) CANARY_STATUS="$value" ;;
    DUAL_KERNEL_DIFF) DUAL_KERNEL_DIFF_STATUS="$value" ;;
    PERF_GATE) PERF_GATE_STATUS="$value" ;;
    *)
      echo "unknown gate key: $key" >&2
      return 1
      ;;
  esac
}

finalize_status() {
  local overall="PASS"
  if [[ "$HAS_FAIL" -ne 0 ]]; then
    overall="FAIL"
  fi

  cat > "$STATUS_FILE" <<EOF_JSON
{
  "generated_at": "$(date -u +'%Y-%m-%dT%H:%M:%SZ')",
  "profile": "${PROFILE}",
  "overall": "${overall}",
  "api_url": "${API_URL}",
  "fail_fast": ${FAIL_FAST},
  "require_docker": ${REQUIRE_DOCKER},
  "sandbox_controls": {
    "allow_existing_system_proxy": ${ALLOW_EXISTING_SYSTEM_PROXY},
    "allow_real_proxy_coexist": ${ALLOW_REAL_PROXY_COEXIST}
  },
  "canary": {
    "duration_hours": ${CANARY_HOURS},
    "sample_interval_sec": ${CANARY_INTERVAL}
  },
  "gates": {
    "preflight": "${PREFLIGHT_STATUS}",
    "oracle": "${ORACLE_STATUS}",
    "boundaries": "${BOUNDARIES_STATUS}",
    "parity": "${PARITY_STATUS}",
    "workspace_test": "${WORKSPACE_TEST_STATUS}",
    "fmt": "${FMT_STATUS}",
    "clippy": "${CLIPPY_STATUS}",
    "hot_reload": "${HOT_RELOAD_STATUS}",
    "signal": "${SIGNAL_STATUS}",
    "docker": "${DOCKER_STATUS}",
    "gui_smoke": "${GUI_STATUS}",
    "canary": "${CANARY_STATUS}",
    "dual_kernel_diff": "${DUAL_KERNEL_DIFF_STATUS}",
    "perf_gate": "${PERF_GATE_STATUS}"
  }
}
EOF_JSON

  echo "L18 capstone status: ${overall}"
  echo "status file: ${STATUS_FILE}"

  if [[ "$overall" == "FAIL" ]]; then
    return 1
  fi
  return 0
}

run_gate() {
  local key="$1"
  shift
  echo "==> [${key}] $*"
  if "$@"; then
    set_gate_status "$key" "PASS"
    return 0
  else
    set_gate_status "$key" "FAIL"
    HAS_FAIL=1
    return 1
  fi
}

run_gate_with_fail_fast() {
  local key="$1"
  shift
  if ! run_gate "$key" "$@"; then
    if [[ "$FAIL_FAST" == "1" ]]; then
      echo "[L18 capstone] fail-fast triggered at gate=${key}" >&2
      finalize_status
      exit 1
    fi
  fi
}

run_docker_gate() {
  if docker info >/dev/null 2>&1; then
    set_gate_status "DOCKER" "PASS"
    return 0
  fi

  if [[ "$REQUIRE_DOCKER" == "1" ]]; then
    set_gate_status "DOCKER" "FAIL"
    HAS_FAIL=1
    return 1
  fi

  set_gate_status "DOCKER" "WARN"
  echo "[L18 capstone] docker unavailable but non-blocking in local mode"
  return 0
}

run_canary_gate() {
  local out_jsonl="${ROOT_DIR}/reports/l18/stability/canary_${PROFILE}.jsonl"
  local out_summary="${ROOT_DIR}/reports/l18/stability/canary_${PROFILE}.md"

  local cmd=(
    "${ROOT_DIR}/scripts/canary_7day.sh"
    --duration-hours "${CANARY_HOURS}"
    --sample-interval-sec "${CANARY_INTERVAL}"
    --api-url "${API_URL}"
    --out-jsonl "$out_jsonl"
    --out-summary "$out_summary"
  )
  if [[ -n "$PID_FILE" ]]; then
    cmd+=(--pid-file "$PID_FILE")
  fi

  "${cmd[@]}" || return 1

  export out_jsonl
  python3 - <<'PY'
import json
import os
import sys

path = os.environ["out_jsonl"]
if not os.path.isfile(path):
    print("missing_jsonl")
    sys.exit(1)

samples = 0
bad_health = 0
null_rss = 0
with open(path, "r", encoding="utf-8") as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        samples += 1
        row = json.loads(line)
        if int(row.get("health_code", 0)) != 200:
            bad_health += 1
        if row.get("rss_kb") in (None, "null"):
            null_rss += 1

if samples == 0:
    print("empty_samples")
    sys.exit(1)
if bad_health > 0:
    print(f"bad_health={bad_health}")
    sys.exit(1)
if null_rss > 0:
    print(f"null_rss={null_rss}")
    sys.exit(1)

print("canary_samples_ok")
PY
}

run_gate_with_fail_fast "PREFLIGHT" "${ROOT_DIR}/scripts/l18/preflight_macos.sh" --require-docker "$REQUIRE_DOCKER"
run_gate_with_fail_fast "ORACLE" "${ROOT_DIR}/scripts/l18/build_go_oracle.sh"
run_gate_with_fail_fast "BOUNDARIES" bash "${ROOT_DIR}/agents-only/06-scripts/check-boundaries.sh"
run_gate_with_fail_fast "PARITY" cargo check -p app --features parity
run_gate_with_fail_fast "WORKSPACE_TEST" cargo test --workspace
run_gate_with_fail_fast "FMT" cargo fmt --all -- --check
run_gate_with_fail_fast "CLIPPY" cargo clippy --workspace --all-features --all-targets -- -D warnings
run_gate_with_fail_fast "HOT_RELOAD" env SINGBOX_HOT_RELOAD_ITERATIONS="${HOT_ITER}" cargo test -p app --test hot_reload_stability --features long_tests -- --nocapture
run_gate_with_fail_fast "SIGNAL" env SINGBOX_SIGNAL_ITERATIONS="${SIGNAL_ITER}" cargo test -p app --test signal_reliability --features long_tests -- --nocapture
if ! run_docker_gate; then
  if [[ "$FAIL_FAST" == "1" ]]; then
    echo "[L18 capstone] fail-fast triggered at gate=DOCKER" >&2
    finalize_status
    exit 1
  fi
fi

if [[ -z "$GUI_APP" ]]; then
  echo "L18_GUI_APP/--gui-app is required for GUI gate" >&2
  set_gate_status "GUI" "FAIL"
  HAS_FAIL=1
  if [[ "$FAIL_FAST" == "1" ]]; then
    finalize_status
    exit 1
  fi
else
  GUI_CMD=("${ROOT_DIR}/scripts/l18/gui_real_cert.sh" --gui-app "$GUI_APP" --allow-existing-system-proxy "$ALLOW_EXISTING_SYSTEM_PROXY" --allow-real-proxy-coexist "$ALLOW_REAL_PROXY_COEXIST")
  if [[ -n "$GUI_SANDBOX_ROOT" ]]; then
    GUI_CMD+=(--sandbox-root "$GUI_SANDBOX_ROOT")
  fi
  run_gate_with_fail_fast "GUI" "${GUI_CMD[@]}"
fi

run_gate_with_fail_fast "CANARY" run_canary_gate

DUAL_CMD=("${ROOT_DIR}/scripts/l18/run_dual_kernel_cert.sh" --profile "$DUAL_PROFILE")
if [[ -n "$GO_API" ]]; then
  DUAL_CMD+=(--go-api "$GO_API")
fi
if [[ -n "$GO_TOKEN" ]]; then
  DUAL_CMD+=(--go-token "$GO_TOKEN")
fi
run_gate_with_fail_fast "DUAL_KERNEL_DIFF" "${DUAL_CMD[@]}"

run_gate_with_fail_fast "PERF_GATE" "${ROOT_DIR}/scripts/l18/perf_gate.sh"

finalize_status
