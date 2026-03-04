#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage:
  scripts/l18/run_capstone_fixed_profile.sh \
    --profile daily|nightly|certify \
    --gui-app <abs_path_to_gui_app> \
    [--batch-root DIR] \
    [--run-name NAME] \
    [--require-docker 0|1] \
    [--workspace-test-threads N] \
    [--allow-existing-system-proxy 0|1] \
    [--allow-real-proxy-coexist 0|1] \
    [--go-api URL] \
    [--go-token TOKEN]

Purpose:
  - Freeze the L18 fixed config baseline
  - Isolate all artifacts into one batch/run root
  - Start a dedicated canary runtime on 127.0.0.1:29090
  - Run scripts/l18/l18_capstone.sh with stable env overrides

Notes:
  - This command runs in foreground.
  - For long runs (nightly/certify), use nohup or tmux if needed.
USAGE
}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"

PROFILE="nightly"
GUI_APP=""
BATCH_ROOT=""
RUN_NAME=""
REQUIRE_DOCKER="0"
WORKSPACE_TEST_THREADS="1"
ALLOW_EXISTING_SYSTEM_PROXY="1"
ALLOW_REAL_PROXY_COEXIST="1"
GO_API="${INTEROP_GO_API_BASE:-}"
GO_TOKEN="${INTEROP_GO_API_TOKEN:-}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --profile)
      PROFILE="$2"
      shift 2
      ;;
    --gui-app)
      GUI_APP="$2"
      shift 2
      ;;
    --batch-root)
      BATCH_ROOT="$2"
      shift 2
      ;;
    --run-name)
      RUN_NAME="$2"
      shift 2
      ;;
    --require-docker)
      REQUIRE_DOCKER="$2"
      shift 2
      ;;
    --workspace-test-threads)
      WORKSPACE_TEST_THREADS="$2"
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
    --go-api)
      GO_API="$2"
      shift 2
      ;;
    --go-token)
      GO_TOKEN="$2"
      shift 2
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

case "$PROFILE" in
  daily|nightly|certify) ;;
  *)
    echo "--profile must be daily|nightly|certify" >&2
    exit 2
    ;;
esac

if [[ -z "$GUI_APP" ]]; then
  echo "--gui-app is required" >&2
  exit 2
fi
if [[ ! -e "$GUI_APP" ]]; then
  echo "gui app not found: $GUI_APP" >&2
  exit 1
fi
if [[ "$REQUIRE_DOCKER" != "0" && "$REQUIRE_DOCKER" != "1" ]]; then
  echo "--require-docker must be 0 or 1" >&2
  exit 2
fi
if [[ "$ALLOW_EXISTING_SYSTEM_PROXY" != "0" && "$ALLOW_EXISTING_SYSTEM_PROXY" != "1" ]]; then
  echo "--allow-existing-system-proxy must be 0 or 1" >&2
  exit 2
fi
if [[ "$ALLOW_REAL_PROXY_COEXIST" != "0" && "$ALLOW_REAL_PROXY_COEXIST" != "1" ]]; then
  echo "--allow-real-proxy-coexist must be 0 or 1" >&2
  exit 2
fi
if ! [[ "$WORKSPACE_TEST_THREADS" =~ ^[1-9][0-9]*$ ]]; then
  echo "--workspace-test-threads must be positive integer" >&2
  exit 2
fi

if [[ -z "$BATCH_ROOT" ]]; then
  BATCH_ROOT="${ROOT_DIR}/reports/l18/batches/$(date -u +'%Y%m%dT%H%M%SZ')-l18-${PROFILE}-preflight"
fi
if [[ "$BATCH_ROOT" != /* ]]; then
  BATCH_ROOT="${ROOT_DIR}/${BATCH_ROOT}"
fi

if [[ -z "$RUN_NAME" ]]; then
  RUN_NAME="capstone_${PROFILE}_fixedcfg"
fi

RUN_ROOT="${BATCH_ROOT}/${RUN_NAME}"
RUN_DIR="${RUN_ROOT}/r1"
CANARY_RUNTIME="${RUN_ROOT}/canary_runtime"

mkdir -p "${RUN_DIR}" "${CANARY_RUNTIME}"
printf '%s\n' "${BATCH_ROOT}" > "${BATCH_ROOT}/BATCH_ROOT.txt"

CANARY_API_URL="http://127.0.0.1:29090"
CANARY_CFG="${CANARY_RUNTIME}/canary_rust_29090_nosecret.json"
CANARY_PID_FILE="${CANARY_RUNTIME}/canary.pid"
CANARY_LOG="${CANARY_RUNTIME}/canary.log"

CONFIG_FREEZE_JSON="${RUN_ROOT}/config.freeze.json"
PRECHECK_TXT="${RUN_ROOT}/precheck.txt"
STATUS_FILE="${RUN_DIR}/l18_capstone_status.json"
STDOUT_LOG="${RUN_DIR}/capstone.stdout.log"
STDERR_LOG="${RUN_DIR}/capstone.stderr.log"
SUMMARY_TSV="${RUN_ROOT}/summary.tsv"

GUI_DIR="${RUN_DIR}/gui"

RUST_BIN="${ROOT_DIR}/target/release/run"
RUST_APP_BIN="${ROOT_DIR}/target/release/app"
FROZEN_BIN_DIR="${RUN_ROOT}/runtime_bin"
FROZEN_RUST_BIN="${FROZEN_BIN_DIR}/run"
FROZEN_RUST_APP_BIN="${FROZEN_BIN_DIR}/app"

check_port_free() {
  local port="$1"
  if lsof -nP -iTCP:"${port}" -sTCP:LISTEN >/dev/null 2>&1; then
    echo "port_busy:${port}" >&2
    lsof -nP -iTCP:"${port}" -sTCP:LISTEN >&2 || true
    return 1
  fi
  return 0
}

{
  echo "generated_at=$(date -u +'%Y-%m-%dT%H:%M:%SZ')"
  echo "profile=${PROFILE}"
  echo "gui_app=${GUI_APP}"
  echo "rust_bin=${RUST_BIN}"
  echo "rust_app_bin=${RUST_APP_BIN}"
  echo "frozen_rust_bin=${FROZEN_RUST_BIN}"
  echo "frozen_rust_app_bin=${FROZEN_RUST_APP_BIN}"
  echo "go_oracle_script=${ROOT_DIR}/scripts/l18/build_go_oracle.sh"
  echo "require_docker=${REQUIRE_DOCKER}"
  echo "workspace_test_threads=${WORKSPACE_TEST_THREADS}"
  echo "allow_existing_system_proxy=${ALLOW_EXISTING_SYSTEM_PROXY}"
  echo "allow_real_proxy_coexist=${ALLOW_REAL_PROXY_COEXIST}"
  echo "fixed_env.L18_GUI_TIMEOUT_SEC=120"
  echo "fixed_env.L18_RUST_BUILD_ENABLED=0"
  echo "fixed_env.L18_GUI_GO_BUILD_ENABLED=0"
  echo "fixed_env.L18_GUI_RUST_BUILD_ENABLED=0"
  echo "fixed_env.L18_RUST_BIN=${FROZEN_RUST_BIN}"
  echo "fixed_env.L18_DUAL_RUST_BIN=${FROZEN_RUST_BIN}"
  echo "fixed_env.L18_DUAL_RUST_APP_BIN=${FROZEN_RUST_APP_BIN}"
  echo "check.port.9090=$(check_port_free 9090 && echo free || echo busy)"
  echo "check.port.19090=$(check_port_free 19090 && echo free || echo busy)"
  echo "check.port.11810=$(check_port_free 11810 && echo free || echo busy)"
  echo "check.port.11811=$(check_port_free 11811 && echo free || echo busy)"
  echo "check.port.29090=$(check_port_free 29090 && echo free || echo busy)"
  echo "check.port.12810=$(check_port_free 12810 && echo free || echo busy)"
} > "${PRECHECK_TXT}"

# Hard fail if any critical port is busy.
for p in 9090 19090 11810 11811 29090 12810; do
  check_port_free "$p"
done

echo "[L18 fixed-profile] building rust parity runtime..."
cargo build --release -p app --features parity --bin run --bin app >/dev/null

if [[ ! -x "${RUST_BIN}" ]]; then
  echo "rust binary not executable after parity build: ${RUST_BIN}" >&2
  exit 1
fi
if [[ ! -x "${RUST_APP_BIN}" ]]; then
  echo "rust app binary not executable after parity build: ${RUST_APP_BIN}" >&2
  exit 1
fi
if [[ ! -x "${ROOT_DIR}/scripts/l18/build_go_oracle.sh" ]]; then
  echo "go oracle build script is missing or not executable" >&2
  exit 1
fi

mkdir -p "${FROZEN_BIN_DIR}"
cp "${RUST_BIN}" "${FROZEN_RUST_BIN}"
cp "${RUST_APP_BIN}" "${FROZEN_RUST_APP_BIN}"
chmod +x "${FROZEN_RUST_BIN}" "${FROZEN_RUST_APP_BIN}"

cat > "${CANARY_CFG}" <<'JSON'
{
  "log": {"level": "warn"},
  "experimental": {
    "clash_api": {
      "external_controller": "127.0.0.1:29090",
      "secret": ""
    }
  },
  "inbounds": [
    {
      "type": "socks",
      "name": "socks-in",
      "listen": "127.0.0.1",
      "port": 12810
    }
  ],
  "outbounds": [
    {
      "type": "selector",
      "name": "my-group",
      "outbounds": ["direct", "alt-direct"],
      "default": "direct"
    },
    {"type": "direct", "name": "direct"},
    {"type": "direct", "name": "alt-direct"}
  ],
  "route": {"rules": [], "final": "my-group"}
}
JSON

stop_canary() {
  if [[ -f "${CANARY_PID_FILE}" ]]; then
    local cpid
    cpid="$(cat "${CANARY_PID_FILE}" 2>/dev/null || true)"
    if [[ -n "${cpid:-}" ]] && kill -0 "$cpid" 2>/dev/null; then
      kill "$cpid" 2>/dev/null || true
      sleep 0.5
      kill -0 "$cpid" 2>/dev/null && kill -9 "$cpid" 2>/dev/null || true
    fi
  fi
}
trap stop_canary EXIT

"${RUST_BIN}" --config "${CANARY_CFG}" > "${CANARY_LOG}" 2>&1 &
CANARY_PID="$!"
echo "$CANARY_PID" > "${CANARY_PID_FILE}"

ready=0
for _ in $(seq 1 120); do
  code="$(curl -s -o /dev/null -w '%{http_code}' "${CANARY_API_URL}/services/health" || true)"
  if [[ "$code" == "200" ]]; then
    ready=1
    break
  fi
  sleep 0.25
done
if [[ "$ready" != "1" ]]; then
  echo "canary runtime health check failed: ${CANARY_API_URL}" >&2
  exit 1
fi

export ROOT_DIR GUI_APP RUN_ROOT RUN_DIR STATUS_FILE
export PRECHECK_TXT CONFIG_FREEZE_JSON RUST_BIN REQUIRE_DOCKER WORKSPACE_TEST_THREADS
export ALLOW_EXISTING_SYSTEM_PROXY ALLOW_REAL_PROXY_COEXIST CANARY_API_URL CANARY_PID_FILE
export FROZEN_RUST_BIN FROZEN_RUST_APP_BIN
export FIXED_PROFILE="${PROFILE}"
python3 - <<'PY'
import json
import os
from datetime import datetime, timezone

payload = {
    "generated_at": datetime.now(timezone.utc).isoformat(),
    "profile": os.environ["FIXED_PROFILE"],
    "run_root": os.environ["RUN_ROOT"],
    "run_dir": os.environ["RUN_DIR"],
    "status_file": os.environ["STATUS_FILE"],
    "gui_app": os.environ["GUI_APP"],
    "canary": {
        "api_url": os.environ["CANARY_API_URL"],
        "pid_file": os.environ["CANARY_PID_FILE"],
    },
    "fixed_env": {
        "L18_GUI_TIMEOUT_SEC": "120",
        "L18_RUST_BUILD_ENABLED": "0",
        "L18_GUI_GO_BUILD_ENABLED": "0",
        "L18_GUI_RUST_BUILD_ENABLED": "0",
        "L18_RUST_BIN": os.environ["FROZEN_RUST_BIN"],
        "L18_DUAL_RUST_BIN": os.environ["FROZEN_RUST_BIN"],
        "L18_DUAL_RUST_APP_BIN": os.environ["FROZEN_RUST_APP_BIN"],
    },
    "runtime_policy": {
        "require_docker": int(os.environ["REQUIRE_DOCKER"]),
        "workspace_test_threads": int(os.environ["WORKSPACE_TEST_THREADS"]),
        "allow_existing_system_proxy": int(os.environ["ALLOW_EXISTING_SYSTEM_PROXY"]),
        "allow_real_proxy_coexist": int(os.environ["ALLOW_REAL_PROXY_COEXIST"]),
    },
    "precheck_file": os.environ["PRECHECK_TXT"],
}

with open(os.environ["CONFIG_FREEZE_JSON"], "w", encoding="utf-8") as f:
    json.dump(payload, f, ensure_ascii=True, indent=2)
PY

CAPSTONE_CMD=(
  "${ROOT_DIR}/scripts/l18/l18_capstone.sh"
  --profile "${PROFILE}"
  --api-url "${CANARY_API_URL}"
  --pid-file "${CANARY_PID_FILE}"
  --status-file "${STATUS_FILE}"
  --gui-app "${GUI_APP}"
  --gui-sandbox-root "${GUI_DIR}/sandbox"
  --allow-existing-system-proxy "${ALLOW_EXISTING_SYSTEM_PROXY}"
  --allow-real-proxy-coexist "${ALLOW_REAL_PROXY_COEXIST}"
  --workspace-test-threads "${WORKSPACE_TEST_THREADS}"
  --canary-output-root "${RUN_DIR}/canary"
  --require-docker "${REQUIRE_DOCKER}"
)
if [[ -n "${GO_API}" ]]; then
  CAPSTONE_CMD+=(--go-api "${GO_API}")
fi
if [[ -n "${GO_TOKEN}" ]]; then
  CAPSTONE_CMD+=(--go-token "${GO_TOKEN}")
fi

set +e
env -u PROFILE \
  L18_BASELINE_LOCK="${RUN_DIR}/preflight/baseline.lock.json" \
  L18_GO_ORACLE_OUTPUT_ROOT="${RUN_DIR}/oracle/go" \
  L18_DUAL_REPORT_ROOT="${RUN_DIR}/dual_kernel" \
  L18_DUAL_ARTIFACTS_DIR="${RUN_DIR}/dual_kernel_artifacts" \
  L18_PERF_GATE_LOCK="${RUN_DIR}/perf/perf_gate.lock.json" \
  L18_PERF_GATE_REPORT="${RUN_DIR}/perf/perf_gate.json" \
  L18_PERF_WORK_DIR="${RUN_DIR}/perf/work" \
  L18_RUST_BUILD_ENABLED=0 \
  L18_RUST_BIN="${FROZEN_RUST_BIN}" \
  L18_DUAL_RUST_BIN="${FROZEN_RUST_BIN}" \
  L18_DUAL_RUST_APP_BIN="${FROZEN_RUST_APP_BIN}" \
  L18_GUI_REAL_REPORT_JSON="${GUI_DIR}/gui_real_cert.json" \
  L18_GUI_REAL_REPORT_MD="${GUI_DIR}/gui_real_cert.md" \
  L18_GUI_REAL_RUNTIME_LOG_DIR="${GUI_DIR}/runtime" \
  L18_GUI_TIMEOUT_SEC=120 \
  L18_GUI_GO_BUILD_ENABLED=0 \
  L18_GUI_RUST_BUILD_ENABLED=0 \
  "${CAPSTONE_CMD[@]}" > "${STDOUT_LOG}" 2> "${STDERR_LOG}"
rc=$?
set -e

overall="MISSING"
preflight="MISSING"
workspace="MISSING"
gui="MISSING"
canary="MISSING"
dual="MISSING"
perf="MISSING"
if [[ -f "${STATUS_FILE}" ]]; then
  overall="$(jq -r '.overall // "MISSING"' "${STATUS_FILE}")"
  preflight="$(jq -r '.gates.preflight // "MISSING"' "${STATUS_FILE}")"
  workspace="$(jq -r '.gates.workspace_test // "MISSING"' "${STATUS_FILE}")"
  gui="$(jq -r '.gates.gui_smoke // "MISSING"' "${STATUS_FILE}")"
  canary="$(jq -r '.gates.canary // "MISSING"' "${STATUS_FILE}")"
  dual="$(jq -r '.gates.dual_kernel_diff // "MISSING"' "${STATUS_FILE}")"
  perf="$(jq -r '.gates.perf_gate // "MISSING"' "${STATUS_FILE}")"
fi

proxies_note="NA"
if [[ -f "${GUI_DIR}/gui_real_cert.json" ]]; then
  proxies_note="$(jq -r '"go=" + ((.cores.go.steps[]? | select(.id=="load_config") | .note) // "NA") + " | rust=" + ((.cores.rust.steps[]? | select(.id=="load_config") | .note) // "NA")' "${GUI_DIR}/gui_real_cert.json" 2>/dev/null || echo "NA")"
fi

echo -e "run\tstatus_rc\toverall\tpreflight\tworkspace\tgui\tcanary\tdual\tperf\tproxies_note\treport" > "${SUMMARY_TSV}"
printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
  "r1" "${rc}" "${overall}" "${preflight}" "${workspace}" "${gui}" "${canary}" "${dual}" "${perf}" "${proxies_note}" "${STATUS_FILE}" >> "${SUMMARY_TSV}"

cat "${SUMMARY_TSV}"
echo "batch_root=${BATCH_ROOT}"
echo "run_root=${RUN_ROOT}"
echo "config_freeze=${CONFIG_FREEZE_JSON}"
echo "precheck=${PRECHECK_TXT}"
echo "stdout_log=${STDOUT_LOG}"
echo "stderr_log=${STDERR_LOG}"
echo "status_file=${STATUS_FILE}"
exit "${rc}"
