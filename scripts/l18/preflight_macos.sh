#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage:
  scripts/l18/preflight_macos.sh [--baseline-lock PATH] [--go-source-dir PATH] [--gui-path PATH] [--required-ports CSV] [--require-docker 0|1]

Checks (hard-fail):
  - macOS host
  - go/cargo/rustc/jq/python3/lsof/curl/nc
  - Docker Desktop daemon availability (only when require-docker=1)
  - Go source path + GUI path
  - required ports are free
  - loopback/network basic readiness

Output:
  reports/l18/baseline.lock.json (default)
USAGE
}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"

BASELINE_LOCK="${L18_BASELINE_LOCK:-${ROOT_DIR}/reports/l18/baseline.lock.json}"
GO_SOURCE_DIR="${L18_GO_SOURCE_DIR:-${ROOT_DIR}/go_fork_source/sing-box-1.12.14}"
GUI_PATH="${L18_GUI_PATH:-${ROOT_DIR}/GUI_fork_source/GUI.for.SingBox-1.19.0}"
REQUIRED_PORTS_CSV="${L18_REQUIRED_PORTS:-9090,19090,11810,11811}"
REQUIRE_DOCKER="${L18_REQUIRE_DOCKER:-0}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --baseline-lock)
      BASELINE_LOCK="$2"
      shift 2
      ;;
    --go-source-dir)
      GO_SOURCE_DIR="$2"
      shift 2
      ;;
    --gui-path)
      GUI_PATH="$2"
      shift 2
      ;;
    --required-ports)
      REQUIRED_PORTS_CSV="$2"
      shift 2
      ;;
    --require-docker)
      REQUIRE_DOCKER="$2"
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

if [[ "$REQUIRE_DOCKER" != "0" && "$REQUIRE_DOCKER" != "1" ]]; then
  echo "--require-docker must be 0 or 1" >&2
  exit 2
fi

fail_count=0
FAIL_REASONS_FILE="$(mktemp)"
PORT_STATUS_FILE="$(mktemp)"
WARN_REASONS_FILE="$(mktemp)"
cleanup() {
  rm -f "$FAIL_REASONS_FILE" "$PORT_STATUS_FILE" "$WARN_REASONS_FILE"
}
trap cleanup EXIT

mark_fail() {
  local reason="$1"
  echo "$reason" >> "$FAIL_REASONS_FILE"
  fail_count=$((fail_count + 1))
}

mark_warn() {
  local reason="$1"
  echo "$reason" >> "$WARN_REASONS_FILE"
}

if [[ "$(uname -s)" != "Darwin" ]]; then
  mark_fail "non_macos_host"
fi

check_cmd_required() {
  local cmd="$1"
  if ! command -v "$cmd" >/dev/null 2>&1; then
    mark_fail "missing_command_${cmd}"
  fi
}

check_cmd_required go
check_cmd_required cargo
check_cmd_required rustc
check_cmd_required jq
check_cmd_required python3
check_cmd_required lsof
check_cmd_required curl
check_cmd_required nc

if [[ ! -d "$GO_SOURCE_DIR" ]]; then
  mark_fail "go_source_missing:${GO_SOURCE_DIR}"
fi
if [[ ! -e "$GUI_PATH" ]]; then
  mark_fail "gui_path_missing:${GUI_PATH}"
fi

if [[ "$REQUIRE_DOCKER" == "1" ]]; then
  if ! command -v docker >/dev/null 2>&1; then
    mark_fail "missing_command_docker"
  elif ! docker info >/dev/null 2>&1; then
    mark_fail "docker_desktop_unavailable"
  fi
else
  if ! command -v docker >/dev/null 2>&1; then
    mark_warn "docker_command_missing_non_blocking"
  elif ! docker info >/dev/null 2>&1; then
    mark_warn "docker_desktop_unavailable_non_blocking"
  fi
fi

if ! ifconfig lo0 >/dev/null 2>&1; then
  mark_fail "loopback_interface_lo0_missing"
fi

if ! route -n get 127.0.0.1 >/dev/null 2>&1; then
  mark_fail "loopback_route_unavailable"
fi

if ! dscacheutil -q host -a name localhost >/dev/null 2>&1; then
  mark_fail "localhost_dns_resolution_failed"
fi

if ! python3 - <<'PY' >/dev/null 2>&1
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind(("127.0.0.1", 0))
s.close()
PY
then
  mark_fail "loopback_bind_failed"
fi

IFS=',' read -r -a required_ports <<< "$REQUIRED_PORTS_CSV"
for raw_port in "${required_ports[@]}"; do
  port="$(echo "$raw_port" | tr -d '[:space:]')"
  [[ -z "$port" ]] && continue
  if [[ ! "$port" =~ ^[0-9]+$ ]]; then
    mark_fail "invalid_required_port:${port}"
    continue
  fi

  if lsof -nP -iTCP:"${port}" -sTCP:LISTEN >/dev/null 2>&1; then
    printf '%s\t%s\n' "$port" "busy" >> "$PORT_STATUS_FILE"
    mark_fail "port_busy:${port}"
  else
    printf '%s\t%s\n' "$port" "free" >> "$PORT_STATUS_FILE"
  fi
done

if [[ "$fail_count" -ne 0 ]]; then
  echo "[L18 preflight] FAIL (${fail_count})" >&2
  sed 's/^/  - /' "$FAIL_REASONS_FILE" >&2
  exit 1
fi

warn_count="$(wc -l < "$WARN_REASONS_FILE" | awk '{print $1+0}')"
if [[ "$warn_count" -gt 0 ]]; then
  echo "[L18 preflight] WARN (${warn_count})"
  sed 's/^/  - /' "$WARN_REASONS_FILE"
fi

mkdir -p "$(dirname "$BASELINE_LOCK")"

ROOT_GIT_COMMIT="$(git -C "$ROOT_DIR" rev-parse HEAD 2>/dev/null || echo unknown)"
GO_SOURCE_COMMIT="$(git -C "$GO_SOURCE_DIR" rev-parse HEAD 2>/dev/null || echo unknown)"
GO_TOOL_VERSION="$(go version 2>/dev/null || echo unknown)"
CARGO_VERSION="$(cargo --version 2>/dev/null || echo unknown)"
RUSTC_VERSION="$(rustc --version 2>/dev/null || echo unknown)"
JQ_VERSION="$(jq --version 2>/dev/null || echo unknown)"
PYTHON_VERSION="$(python3 --version 2>/dev/null || echo unknown)"
DOCKER_VERSION="$(docker version --format '{{.Server.Version}}' 2>/dev/null || docker version --format '{{.Client.Version}}' 2>/dev/null || echo unknown)"

export BASELINE_LOCK ROOT_DIR GO_SOURCE_DIR GUI_PATH REQUIRED_PORTS_CSV
export ROOT_GIT_COMMIT GO_SOURCE_COMMIT GO_TOOL_VERSION CARGO_VERSION RUSTC_VERSION JQ_VERSION PYTHON_VERSION DOCKER_VERSION PORT_STATUS_FILE WARN_REASONS_FILE REQUIRE_DOCKER
python3 - <<'PY'
import json
import os
import platform
import socket
from datetime import datetime, timezone

baseline_lock = os.environ["BASELINE_LOCK"]
ports_file = os.environ["PORT_STATUS_FILE"]

ports = []
if os.path.exists(ports_file):
    with open(ports_file, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            port, status = line.split("\t", 1)
            ports.append({"port": int(port), "status": status})

warnings = []
warn_file = os.environ["WARN_REASONS_FILE"]
if os.path.exists(warn_file):
    with open(warn_file, "r", encoding="utf-8") as f:
        warnings = [line.strip() for line in f if line.strip()]

payload = {
    "generated_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
    "host": {
        "hostname": socket.gethostname(),
        "os": platform.platform(),
        "machine": platform.machine(),
    },
    "sources": {
        "rust_repo_root": os.environ["ROOT_DIR"],
        "rust_commit": os.environ["ROOT_GIT_COMMIT"],
        "go_oracle_source": os.environ["GO_SOURCE_DIR"],
        "go_oracle_commit": os.environ["GO_SOURCE_COMMIT"],
        "gui_path": os.environ["GUI_PATH"],
    },
    "tools": {
        "go": os.environ["GO_TOOL_VERSION"],
        "cargo": os.environ["CARGO_VERSION"],
        "rustc": os.environ["RUSTC_VERSION"],
        "jq": os.environ["JQ_VERSION"],
        "python3": os.environ["PYTHON_VERSION"],
        "docker": os.environ["DOCKER_VERSION"],
    },
    "checks": {
        "require_docker": os.environ["REQUIRE_DOCKER"] == "1",
        "required_ports": ports,
        "warnings": warnings,
        "network": {
            "loopback_bind": "pass",
            "localhost_dns": "pass",
            "loopback_route": "pass",
        },
    },
}

os.makedirs(os.path.dirname(baseline_lock), exist_ok=True)
with open(baseline_lock, "w", encoding="utf-8") as f:
    json.dump(payload, f, indent=2, ensure_ascii=False)

print(f"baseline lock written: {baseline_lock}")
PY

echo "[L18 preflight] PASS"
echo "baseline lock: $BASELINE_LOCK"
