#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage:
  scripts/l18/run_capstone_fixed_profile.sh \
    --profile daily|nightly|certify \
    [--gui-mode core|host-gui] \
    [--gui-app <abs_path_to_gui_app>] \
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
GUI_MODE="core"
GUI_APP=""
BATCH_ROOT=""
RUN_NAME=""
REQUIRE_DOCKER="0"
WORKSPACE_TEST_THREADS="1"
ALLOW_EXISTING_SYSTEM_PROXY="1"
ALLOW_REAL_PROXY_COEXIST="1"
GO_API="${INTEROP_GO_API_BASE:-}"
GO_TOKEN="${INTEROP_GO_API_TOKEN:-}"
API_SECRET="${L18_API_SECRET:-}"

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
    --gui-mode)
      GUI_MODE="$2"
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
if [[ "$GUI_MODE" != "core" && "$GUI_MODE" != "host-gui" ]]; then
  echo "--gui-mode must be core or host-gui" >&2
  exit 2
fi
if [[ "$GUI_MODE" == "host-gui" ]]; then
  if [[ -z "$GUI_APP" ]]; then
    echo "--gui-app is required when --gui-mode host-gui" >&2
    exit 2
  fi
  if [[ ! -e "$GUI_APP" ]]; then
    echo "gui app not found: $GUI_APP" >&2
    exit 1
  fi
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
  if [[ "$GUI_MODE" == "host-gui" ]]; then
    RUN_NAME="capstone_${PROFILE}_hostgui_fixedcfg"
  else
    RUN_NAME="capstone_${PROFILE}_core_fixedcfg"
  fi
fi

if [[ -z "$API_SECRET" ]]; then
  API_SECRET="l18-${PROFILE}-secret"
fi
if [[ -z "$API_SECRET" ]]; then
  echo "L18_API_SECRET must not be empty" >&2
  exit 2
fi
if [[ "$PROFILE" == "certify" ]]; then
  if [[ "$ALLOW_EXISTING_SYSTEM_PROXY" != "0" || "$ALLOW_REAL_PROXY_COEXIST" != "0" ]]; then
    echo "certify profile requires --allow-existing-system-proxy 0 and --allow-real-proxy-coexist 0" >&2
    exit 2
  fi
fi

RUN_ROOT="${BATCH_ROOT}/${RUN_NAME}"
RUN_DIR="${RUN_ROOT}/r1"
CANARY_RUNTIME="${RUN_ROOT}/canary_runtime"
RUNTIME_CONFIG_DIR="${RUN_ROOT}/runtime_configs"

mkdir -p "${RUN_DIR}" "${CANARY_RUNTIME}" "${RUNTIME_CONFIG_DIR}"
printf '%s\n' "${BATCH_ROOT}" > "${BATCH_ROOT}/BATCH_ROOT.txt"

CANARY_PID_FILE="${CANARY_RUNTIME}/canary.pid"
CANARY_LOG="${CANARY_RUNTIME}/canary.log"

CONFIG_FREEZE_JSON="${RUN_ROOT}/config.freeze.json"
PRECHECK_TXT="${RUN_ROOT}/precheck.txt"
STATUS_FILE="${RUN_DIR}/l18_capstone_status.json"
STDOUT_LOG="${RUN_DIR}/capstone.stdout.log"
STDERR_LOG="${RUN_DIR}/capstone.stderr.log"
SUMMARY_TSV="${RUN_ROOT}/summary.tsv"
PORT_MAP_JSON="${RUN_ROOT}/port_map.json"
MANIFEST_JSON="${RUN_ROOT}/evidence_manifest.json"
LEAK_ASSERT_JSON="${RUN_ROOT}/post_run_leak_assert.json"

GO_RUNTIME_CFG="${RUNTIME_CONFIG_DIR}/l18_gui_go.json"
RUST_RUNTIME_CFG="${RUNTIME_CONFIG_DIR}/l18_gui_rust.json"
CANARY_CFG="${CANARY_RUNTIME}/canary_runtime.json"

GUI_DIR="${RUN_DIR}/gui"

RUST_BIN="${ROOT_DIR}/target/release/run"
RUST_APP_BIN="${ROOT_DIR}/target/release/app"
FROZEN_BIN_DIR="${RUN_ROOT}/runtime_bin"
FROZEN_RUST_BIN="${FROZEN_BIN_DIR}/run"
FROZEN_RUST_APP_BIN="${FROZEN_BIN_DIR}/app"
FROZEN_GO_BIN="${FROZEN_BIN_DIR}/sing-box"

allocate_ports() {
  python3 - <<'PY'
import socket

names = [
    "GO_CONTROLLER_PORT",
    "RUST_CONTROLLER_PORT",
    "GO_PROXY_PORT",
    "RUST_PROXY_PORT",
    "CANARY_CONTROLLER_PORT",
    "CANARY_PROXY_PORT",
]

allocated = {}
holders = []
try:
    for name in names:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind(("127.0.0.1", 0))
        holders.append(sock)
        allocated[name] = sock.getsockname()[1]
    for name in names:
        print(f"{name}={allocated[name]}")
finally:
    for sock in holders:
        sock.close()
PY
}

check_port_free() {
  local port="$1"
  if lsof -nP -iTCP:"${port}" -sTCP:LISTEN >/dev/null 2>&1; then
    echo "port_busy:${port}" >&2
    lsof -nP -iTCP:"${port}" -sTCP:LISTEN >&2 || true
    return 1
  fi
  return 0
}

spawn_in_own_session() {
  local log_file="$1"
  shift

  if command -v setsid >/dev/null 2>&1; then
    setsid "$@" >"${log_file}" 2>&1 &
    echo "$!"
    return 0
  fi

  python3 - "${log_file}" "$@" <<'PY'
import os
import sys

log_file = sys.argv[1]
cmd = sys.argv[2:]

pid = os.fork()
if pid:
    print(pid)
    sys.exit(0)

os.setsid()
fd = os.open(log_file, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o644)
os.dup2(fd, 1)
os.dup2(fd, 2)
if fd > 2:
    os.close(fd)
os.execvp(cmd[0], cmd)
PY
}

stop_canary() {
  if [[ -f "${CANARY_PID_FILE}" ]]; then
    local cpid
    cpid="$(cat "${CANARY_PID_FILE}" 2>/dev/null || true)"
    if [[ -n "${cpid:-}" ]] && kill -0 "$cpid" 2>/dev/null; then
      kill "-$cpid" 2>/dev/null || kill "$cpid" 2>/dev/null || true
      sleep 0.5
      kill -0 "$cpid" 2>/dev/null && kill -9 "-$cpid" 2>/dev/null || kill -9 "$cpid" 2>/dev/null || true
    fi
  fi
}

eval "$(allocate_ports)"

CANARY_API_URL="http://127.0.0.1:${CANARY_CONTROLLER_PORT}"
GO_API_GENERATED="http://127.0.0.1:${GO_CONTROLLER_PORT}"
RUST_API_GENERATED="http://127.0.0.1:${RUST_CONTROLLER_PORT}"
GO_API_EFFECTIVE="${GO_API:-${GO_API_GENERATED}}"
GO_TOKEN_EFFECTIVE="${GO_TOKEN:-${API_SECRET}}"
RUST_API_EFFECTIVE="${RUST_API_GENERATED}"
RUNTIME_PORTS_CSV="${GO_CONTROLLER_PORT},${RUST_CONTROLLER_PORT},${GO_PROXY_PORT},${RUST_PROXY_PORT}"
ALL_PORTS_CSV="${RUNTIME_PORTS_CSV},${CANARY_CONTROLLER_PORT},${CANARY_PROXY_PORT}"

export GO_CONTROLLER_PORT RUST_CONTROLLER_PORT GO_PROXY_PORT RUST_PROXY_PORT CANARY_CONTROLLER_PORT CANARY_PROXY_PORT
export GO_RUNTIME_CFG RUST_RUNTIME_CFG CANARY_CFG API_SECRET PORT_MAP_JSON
export ROOT_DIR

python3 - <<'PY'
import json
import os
from pathlib import Path

root = Path(os.environ["ROOT_DIR"])

def load_json(rel_path: str):
    return json.loads((root / rel_path).read_text(encoding="utf-8"))

go_cfg = load_json("labs/interop-lab/configs/l18_gui_go.json")
go_cfg["experimental"]["clash_api"]["external_controller"] = f"127.0.0.1:{os.environ['GO_CONTROLLER_PORT']}"
go_cfg["experimental"]["clash_api"]["secret"] = os.environ["API_SECRET"]
go_cfg["inbounds"][0]["listen_port"] = int(os.environ["GO_PROXY_PORT"])

rust_cfg = load_json("labs/interop-lab/configs/l18_gui_rust.json")
rust_cfg["experimental"]["clash_api"]["external_controller"] = f"127.0.0.1:{os.environ['RUST_CONTROLLER_PORT']}"
rust_cfg["experimental"]["clash_api"]["secret"] = os.environ["API_SECRET"]
rust_cfg["inbounds"][0]["port"] = int(os.environ["RUST_PROXY_PORT"])

canary_cfg = {
    "log": {"level": "warn"},
    "experimental": {
        "clash_api": {
            "external_controller": f"127.0.0.1:{os.environ['CANARY_CONTROLLER_PORT']}",
            "secret": os.environ["API_SECRET"],
        }
    },
    "inbounds": [
        {
            "type": "socks",
            "name": "socks-in",
            "listen": "127.0.0.1",
            "port": int(os.environ["CANARY_PROXY_PORT"]),
        }
    ],
    "outbounds": [
        {
            "type": "selector",
            "name": "my-group",
            "outbounds": ["direct", "alt-direct"],
            "default": "direct",
        },
        {"type": "direct", "name": "direct"},
        {"type": "direct", "name": "alt-direct"},
    ],
    "route": {"rules": [], "final": "my-group"},
}

port_map = {
    "go_controller": int(os.environ["GO_CONTROLLER_PORT"]),
    "rust_controller": int(os.environ["RUST_CONTROLLER_PORT"]),
    "go_proxy": int(os.environ["GO_PROXY_PORT"]),
    "rust_proxy": int(os.environ["RUST_PROXY_PORT"]),
    "canary_controller": int(os.environ["CANARY_CONTROLLER_PORT"]),
    "canary_proxy": int(os.environ["CANARY_PROXY_PORT"]),
}

Path(os.environ["GO_RUNTIME_CFG"]).write_text(json.dumps(go_cfg, ensure_ascii=True, indent=2) + "\n", encoding="utf-8")
Path(os.environ["RUST_RUNTIME_CFG"]).write_text(json.dumps(rust_cfg, ensure_ascii=True, indent=2) + "\n", encoding="utf-8")
Path(os.environ["CANARY_CFG"]).write_text(json.dumps(canary_cfg, ensure_ascii=True, indent=2) + "\n", encoding="utf-8")
Path(os.environ["PORT_MAP_JSON"]).write_text(json.dumps(port_map, ensure_ascii=True, indent=2) + "\n", encoding="utf-8")
PY

{
  echo "generated_at=$(date -u +'%Y-%m-%dT%H:%M:%SZ')"
  echo "profile=${PROFILE}"
  echo "gui_mode=${GUI_MODE}"
  echo "gui_app=${GUI_APP}"
  echo "rust_bin=${RUST_BIN}"
  echo "rust_app_bin=${RUST_APP_BIN}"
  echo "frozen_rust_bin=${FROZEN_RUST_BIN}"
  echo "frozen_rust_app_bin=${FROZEN_RUST_APP_BIN}"
  echo "frozen_go_bin=${FROZEN_GO_BIN}"
  echo "go_oracle_script=${ROOT_DIR}/scripts/l18/build_go_oracle.sh"
  echo "require_docker=${REQUIRE_DOCKER}"
  echo "workspace_test_threads=${WORKSPACE_TEST_THREADS}"
  echo "allow_existing_system_proxy=${ALLOW_EXISTING_SYSTEM_PROXY}"
  echo "allow_real_proxy_coexist=${ALLOW_REAL_PROXY_COEXIST}"
  echo "api_secret_set=1"
  echo "go_api_effective=${GO_API_EFFECTIVE}"
  echo "rust_api_effective=${RUST_API_EFFECTIVE}"
  echo "fixed_env.L18_GUI_TIMEOUT_SEC=120"
  echo "fixed_env.L18_RUST_BUILD_ENABLED=0"
  echo "fixed_env.L18_GUI_GO_BUILD_ENABLED=0"
  echo "fixed_env.L18_GUI_RUST_BUILD_ENABLED=0"
  echo "fixed_env.L18_RUST_BIN=${FROZEN_RUST_BIN}"
  echo "fixed_env.L18_DUAL_RUST_BIN=${FROZEN_RUST_BIN}"
  echo "fixed_env.L18_DUAL_RUST_APP_BIN=${FROZEN_RUST_APP_BIN}"
  echo "check.port.go_controller=$(check_port_free "${GO_CONTROLLER_PORT}" && echo free || echo busy)"
  echo "check.port.rust_controller=$(check_port_free "${RUST_CONTROLLER_PORT}" && echo free || echo busy)"
  echo "check.port.go_proxy=$(check_port_free "${GO_PROXY_PORT}" && echo free || echo busy)"
  echo "check.port.rust_proxy=$(check_port_free "${RUST_PROXY_PORT}" && echo free || echo busy)"
  echo "check.port.canary_controller=$(check_port_free "${CANARY_CONTROLLER_PORT}" && echo free || echo busy)"
  echo "check.port.canary_proxy=$(check_port_free "${CANARY_PROXY_PORT}" && echo free || echo busy)"
} > "${PRECHECK_TXT}"

# Hard fail if any critical port is busy.
for p in "${GO_CONTROLLER_PORT}" "${RUST_CONTROLLER_PORT}" "${GO_PROXY_PORT}" "${RUST_PROXY_PORT}" "${CANARY_CONTROLLER_PORT}" "${CANARY_PROXY_PORT}"; do
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

echo "[L18 fixed-profile] building frozen go oracle..."
GO_ORACLE_BUILD_OUTPUT="$("${ROOT_DIR}/scripts/l18/build_go_oracle.sh" --output-root "${RUN_ROOT}/go_oracle" 2>&1)"
printf '%s\n' "${GO_ORACLE_BUILD_OUTPUT}" > "${RUN_ROOT}/go_oracle_build.log"
FROZEN_GO_BIN_SRC="$(printf '%s\n' "${GO_ORACLE_BUILD_OUTPUT}" | awk -F= '/^binary=/{print $2}' | tail -n1)"
if [[ -z "${FROZEN_GO_BIN_SRC}" ]]; then
  echo "failed to parse go oracle binary path from build output" >&2
  cat "${RUN_ROOT}/go_oracle_build.log" >&2
  exit 1
fi
if [[ ! -x "${FROZEN_GO_BIN_SRC}" ]]; then
  echo "go oracle binary not executable after build: ${FROZEN_GO_BIN_SRC}" >&2
  exit 1
fi
cp "${FROZEN_GO_BIN_SRC}" "${FROZEN_GO_BIN}"
chmod +x "${FROZEN_GO_BIN}"

trap stop_canary EXIT

CANARY_PID="$(spawn_in_own_session "${CANARY_LOG}" "${RUST_BIN}" --config "${CANARY_CFG}")"
echo "$CANARY_PID" > "${CANARY_PID_FILE}"

ready=0
for _ in $(seq 1 120); do
  code="$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer ${API_SECRET}" "${CANARY_API_URL}/services/health" || true)"
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

export ROOT_DIR GUI_APP GUI_MODE RUN_ROOT RUN_DIR STATUS_FILE
export PRECHECK_TXT CONFIG_FREEZE_JSON RUST_BIN REQUIRE_DOCKER WORKSPACE_TEST_THREADS
export ALLOW_EXISTING_SYSTEM_PROXY ALLOW_REAL_PROXY_COEXIST CANARY_API_URL CANARY_PID_FILE
export FROZEN_RUST_BIN FROZEN_RUST_APP_BIN
export GO_API_EFFECTIVE GO_TOKEN_EFFECTIVE RUST_API_EFFECTIVE PORT_MAP_JSON
export GO_RUNTIME_CFG RUST_RUNTIME_CFG API_SECRET RUNTIME_PORTS_CSV ALL_PORTS_CSV FROZEN_GO_BIN
export FIXED_PROFILE="${PROFILE}"
python3 - <<'PY'
import json
import os
from datetime import datetime, timezone

payload = {
    "generated_at": datetime.now(timezone.utc).isoformat(),
    "profile": os.environ["FIXED_PROFILE"],
    "gui_mode": os.environ["GUI_MODE"],
    "run_root": os.environ["RUN_ROOT"],
    "run_dir": os.environ["RUN_DIR"],
    "status_file": os.environ["STATUS_FILE"],
    "gui_app": os.environ["GUI_APP"],
    "canary": {
        "api_url": os.environ["CANARY_API_URL"],
        "pid_file": os.environ["CANARY_PID_FILE"],
    },
    "port_map_file": os.environ["PORT_MAP_JSON"],
    "runtime_configs": {
        "go": os.environ["GO_RUNTIME_CFG"],
        "rust": os.environ["RUST_RUNTIME_CFG"],
    },
    "fixed_env": {
        "L18_GUI_TIMEOUT_SEC": "120",
        "L18_RUST_BUILD_ENABLED": "0",
        "L18_GUI_GO_BUILD_ENABLED": "0",
        "L18_GUI_RUST_BUILD_ENABLED": "0",
        "L18_RUST_BIN": os.environ["FROZEN_RUST_BIN"],
        "L18_GO_BIN": os.environ["FROZEN_GO_BIN"],
        "L18_GO_CONFIG": os.environ["GO_RUNTIME_CFG"],
        "L18_RUST_CONFIG": os.environ["RUST_RUNTIME_CFG"],
        "L18_DUAL_GO_BIN": os.environ["FROZEN_GO_BIN"],
        "L18_DUAL_RUST_BIN": os.environ["FROZEN_RUST_BIN"],
        "L18_DUAL_RUST_APP_BIN": os.environ["FROZEN_RUST_APP_BIN"],
        "L18_GO_API_URL": os.environ["GO_API_EFFECTIVE"],
        "L18_GO_API_TOKEN": os.environ["GO_TOKEN_EFFECTIVE"],
        "L18_GO_API_SECRET": os.environ["GO_TOKEN_EFFECTIVE"],
        "L18_RUST_API_URL": os.environ["RUST_API_EFFECTIVE"],
        "L18_RUST_API_TOKEN": os.environ["API_SECRET"],
        "L18_RUST_API_SECRET": os.environ["API_SECRET"],
        "L18_CANARY_API_SECRET": os.environ["API_SECRET"],
        "L18_DUAL_GO_CONFIG": os.environ["GO_RUNTIME_CFG"],
        "L18_DUAL_RUST_CONFIG": os.environ["RUST_RUNTIME_CFG"],
        "L18_REQUIRED_PORTS": os.environ["RUNTIME_PORTS_CSV"],
        "L18_EXPECTED_RUNTIME_PORTS": os.environ["RUNTIME_PORTS_CSV"],
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
  --gui-mode "${GUI_MODE}"
  --api-url "${CANARY_API_URL}"
  --pid-file "${CANARY_PID_FILE}"
  --status-file "${STATUS_FILE}"
  --allow-existing-system-proxy "${ALLOW_EXISTING_SYSTEM_PROXY}"
  --allow-real-proxy-coexist "${ALLOW_REAL_PROXY_COEXIST}"
  --workspace-test-threads "${WORKSPACE_TEST_THREADS}"
  --canary-output-root "${RUN_DIR}/canary"
  --require-docker "${REQUIRE_DOCKER}"
)
if [[ "$GUI_MODE" == "host-gui" ]]; then
  CAPSTONE_CMD+=(--gui-app "${GUI_APP}" --gui-sandbox-root "${GUI_DIR}/sandbox")
fi
if [[ -n "${GO_API}" ]]; then
  CAPSTONE_CMD+=(--go-api "${GO_API}")
fi
if [[ -n "${GO_TOKEN}" ]]; then
  CAPSTONE_CMD+=(--go-token "${GO_TOKEN}")
fi

set +e
env -u PROFILE \
  -u INTEROP_RUST_API_BASE -u INTEROP_RUST_API_SECRET -u INTEROP_RUST_API_SECRET_WRONG \
  -u INTEROP_GO_API_BASE -u INTEROP_GO_API_SECRET -u INTEROP_GO_API_SECRET_WRONG \
  -u INTEROP_GO_API_TOKEN -u INTEROP_RUST_BIN \
  INTEROP_GO_API_BASE="${GO_API_EFFECTIVE}" \
  INTEROP_GO_API_TOKEN="${GO_TOKEN_EFFECTIVE}" \
  INTEROP_GO_API_SECRET="${GO_TOKEN_EFFECTIVE}" \
  INTEROP_RUST_API_BASE="${RUST_API_EFFECTIVE}" \
  INTEROP_RUST_API_SECRET="${API_SECRET}" \
  L18_BASELINE_LOCK="${RUN_DIR}/preflight/baseline.lock.json" \
  L18_GO_ORACLE_OUTPUT_ROOT="${RUN_DIR}/oracle/go" \
  L18_DUAL_REPORT_ROOT="${RUN_DIR}/dual_kernel" \
  L18_DUAL_ARTIFACTS_DIR="${RUN_DIR}/dual_kernel_artifacts" \
  L18_PERF_GATE_LOCK="${RUN_DIR}/perf/perf_gate.lock.json" \
  L18_PERF_GATE_REPORT="${RUN_DIR}/perf/perf_gate.json" \
  L18_PERF_WORK_DIR="${RUN_DIR}/perf/work" \
  L18_REQUIRED_PORTS="${RUNTIME_PORTS_CSV}" \
  L18_EXPECTED_RUNTIME_PORTS="${RUNTIME_PORTS_CSV}" \
  L18_GO_BIN="${FROZEN_GO_BIN}" \
  L18_GO_CONFIG="${GO_RUNTIME_CFG}" \
  L18_GO_API_URL="${GO_API_EFFECTIVE}" \
  L18_GO_API_TOKEN="${GO_TOKEN_EFFECTIVE}" \
  L18_GO_API_SECRET="${GO_TOKEN_EFFECTIVE}" \
  L18_RUST_API_URL="${RUST_API_EFFECTIVE}" \
  L18_RUST_API_TOKEN="${API_SECRET}" \
  L18_RUST_API_SECRET="${API_SECRET}" \
  L18_CANARY_API_SECRET="${API_SECRET}" \
  L18_GO_PROXY_PORT="${GO_PROXY_PORT}" \
  L18_RUST_PROXY_PORT="${RUST_PROXY_PORT}" \
  L18_DUAL_GO_BIN="${FROZEN_GO_BIN}" \
  L18_DUAL_GO_CONFIG="${GO_RUNTIME_CFG}" \
  L18_DUAL_RUST_CONFIG="${RUST_RUNTIME_CFG}" \
  L18_RUST_CONFIG="${RUST_RUNTIME_CFG}" \
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

stop_canary

export ALL_PORTS_CSV LEAK_ASSERT_JSON
python3 - <<'PY'
import json
import os
import subprocess
import time
from pathlib import Path

ports = [p.strip() for p in os.environ["ALL_PORTS_CSV"].split(",") if p.strip()]

def collect_busy():
    busy_ports = []
    for port in ports:
        proc = subprocess.run(
            ["lsof", "-nP", f"-iTCP:{port}", "-sTCP:LISTEN"],
            capture_output=True,
            text=True,
            check=False,
        )
        if proc.returncode == 0 and proc.stdout.strip():
            busy_ports.append({"port": int(port), "lsof": proc.stdout.strip().splitlines()[1:]})
    return busy_ports

busy = []
for _ in range(40):
    busy = collect_busy()
    if not busy:
        break
    time.sleep(0.25)

payload = {
    "ports_checked": [int(p) for p in ports],
    "released": not busy,
    "busy": busy,
}
Path(os.environ["LEAK_ASSERT_JSON"]).write_text(
    json.dumps(payload, ensure_ascii=True, indent=2) + "\n",
    encoding="utf-8",
)
PY

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
echo "port_map=${PORT_MAP_JSON}"
echo "precheck=${PRECHECK_TXT}"
echo "stdout_log=${STDOUT_LOG}"
echo "stderr_log=${STDERR_LOG}"
echo "status_file=${STATUS_FILE}"
echo "leak_assert=${LEAK_ASSERT_JSON}"

export BATCH_ROOT MANIFEST_JSON SUMMARY_TSV LEAK_ASSERT_JSON STDOUT_LOG STDERR_LOG CONFIG_FREEZE_JSON STATUS_FILE PORT_MAP_JSON
export GO_API_EFFECTIVE RUST_API_EFFECTIVE PRECHECK_TXT
printf -v CAPSTONE_CMD_STR '%q ' "${CAPSTONE_CMD[@]}"
export CAPSTONE_CMD_STR
python3 - <<'PY'
import hashlib
import json
import os
import subprocess
from pathlib import Path

def sha256_file(path_str: str):
    path = Path(path_str)
    if not path.is_file():
        return None
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()

status_path = Path(os.environ["STATUS_FILE"])
gate_summary = {}
if status_path.is_file():
    try:
        gate_summary = json.loads(status_path.read_text(encoding="utf-8")).get("gates", {})
    except Exception:
        gate_summary = {}

artifact_paths = {
    "status_file": os.environ["STATUS_FILE"],
    "summary_tsv": os.environ["SUMMARY_TSV"],
    "config_freeze": os.environ["CONFIG_FREEZE_JSON"],
    "precheck": os.environ["PRECHECK_TXT"],
    "port_map": os.environ["PORT_MAP_JSON"],
    "stdout_log": os.environ["STDOUT_LOG"],
    "stderr_log": os.environ["STDERR_LOG"],
    "leak_assert": os.environ["LEAK_ASSERT_JSON"],
}

manifest = {
    "batch_id": Path(os.environ["BATCH_ROOT"]).name,
    "profile": os.environ["FIXED_PROFILE"],
    "gui_mode": os.environ["GUI_MODE"],
    "commit": subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip(),
    "command": os.environ["CAPSTONE_CMD_STR"].strip(),
    "artifact_hashes": {name: sha256_file(path) for name, path in artifact_paths.items()},
    "gate_summary": gate_summary,
    "port_map": json.loads(Path(os.environ["PORT_MAP_JSON"]).read_text(encoding="utf-8")),
    "api_urls": {
        "go": os.environ["GO_API_EFFECTIVE"],
        "rust": os.environ["RUST_API_EFFECTIVE"],
        "canary": os.environ["CANARY_API_URL"],
    },
}

Path(os.environ["MANIFEST_JSON"]).write_text(
    json.dumps(manifest, ensure_ascii=True, indent=2) + "\n",
    encoding="utf-8",
)
PY
exit "${rc}"
