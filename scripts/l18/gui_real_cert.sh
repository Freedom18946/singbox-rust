#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage:
  scripts/l18/gui_real_cert.sh \
    --gui-app <path> \
    [--gui-process-name NAME] \
    [--go-bin PATH] [--go-config PATH] [--go-api-url URL] [--go-api-token TOKEN] \
    [--go-build-enabled 0|1] [--go-build-tags TAGS] \
    [--rust-bin PATH] [--rust-config PATH] [--rust-api-url URL] [--rust-api-token TOKEN] \
    [--rust-build-enabled 0|1] [--rust-build-features FEATURES] \
    [--runtime-log-dir PATH] \
    [--automation-cmd PATH] [--timeout-sec N] [--report-json PATH] [--report-md PATH] \
    [--capabilities-gate-enabled 0|1] \
    [--go-capabilities-required 0|1] [--rust-capabilities-required 0|1] \
    [--sandbox-root PATH] [--allow-existing-system-proxy 0|1] [--allow-real-proxy-coexist 0|1]

Required steps per core:
  startup -> load_config -> switch_proxy -> connections_panel -> logs_panel
USAGE
}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"

GUI_APP="${L18_GUI_APP:-}"
GUI_PROCESS_NAME="${L18_GUI_PROCESS_NAME:-GUI.for.SingBox}"

DEFAULT_GO_BIN="${ROOT_DIR}/go_fork_source/sing-box-1.12.14/sing-box"
GO_BIN="${L18_GO_BIN:-${DEFAULT_GO_BIN}}"
GO_CONFIG="${L18_GO_CONFIG:-${ROOT_DIR}/labs/interop-lab/configs/l18_gui_go.json}"
GO_API_URL="${L18_GO_API_URL:-http://127.0.0.1:9090}"
GO_API_TOKEN="${L18_GO_API_TOKEN:-test-secret}"
GO_BUILD_ENABLED="${L18_GUI_GO_BUILD_ENABLED:-1}"
GO_BUILD_TAGS="${L18_GUI_GO_BUILD_TAGS:-with_clash_api}"

DEFAULT_RUST_BIN="${ROOT_DIR}/target/release/run"
RUST_BIN="${L18_RUST_BIN:-${DEFAULT_RUST_BIN}}"
RUST_CONFIG="${L18_RUST_CONFIG:-${ROOT_DIR}/labs/interop-lab/configs/l18_gui_rust.json}"
RUST_API_URL="${L18_RUST_API_URL:-http://127.0.0.1:19090}"
RUST_API_TOKEN="${L18_RUST_API_TOKEN:-test-secret}"
RUST_BUILD_ENABLED="${L18_GUI_RUST_BUILD_ENABLED:-1}"
RUST_BUILD_FEATURES="${L18_GUI_RUST_BUILD_FEATURES:-parity}"

AUTOMATION_CMD="${L18_GUI_AUTOMATION_CMD:-}"
TIMEOUT_SEC="${L18_GUI_TIMEOUT_SEC:-45}"
REPORT_JSON="${L18_GUI_REAL_REPORT_JSON:-${ROOT_DIR}/reports/l18/gui_real_cert.json}"
REPORT_MD="${L18_GUI_REAL_REPORT_MD:-${ROOT_DIR}/reports/l18/gui_real_cert.md}"
RUNTIME_LOG_DIR="${L18_GUI_REAL_RUNTIME_LOG_DIR:-${ROOT_DIR}/reports/l18/gui_real}"

SANDBOX_ROOT="${L18_GUI_SANDBOX_ROOT:-}"
ALLOW_EXISTING_SYSTEM_PROXY="${L18_ALLOW_EXISTING_SYSTEM_PROXY:-0}"
ALLOW_REAL_PROXY_COEXIST="${L18_ALLOW_REAL_PROXY_COEXIST:-0}"
REAL_PROXY_PROCESS_PATTERNS="${L18_REAL_PROXY_PROCESS_PATTERNS:-ClashX,Clash Verge,Surge,v2ray,xray,mihomo,clash-meta,NekoRay,Quantumult,Outline,AdGuard,sing-box}"
REAL_PROXY_PORTS="${L18_REAL_PROXY_PORTS:-7890,7891,1080,10808}"
EXPECTED_RUNTIME_PORTS="${L18_EXPECTED_RUNTIME_PORTS:-${L18_REQUIRED_PORTS:-9090,19090,11810,11811}}"
CAPABILITIES_GATE_ENABLED="${L20_CAPABILITIES_GATE_ENABLED:-1}"
CAPABILITIES_GATE_TIMEOUT_SEC="${L20_CAPABILITIES_GATE_TIMEOUT_SEC:-5}"
GO_CAPABILITIES_REQUIRED="${L20_CAPABILITIES_GO_REQUIRED:-0}"
RUST_CAPABILITIES_REQUIRED="${L20_CAPABILITIES_RUST_REQUIRED:-1}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --gui-app)
      GUI_APP="$2"
      shift 2
      ;;
    --gui-process-name)
      GUI_PROCESS_NAME="$2"
      shift 2
      ;;
    --go-bin)
      GO_BIN="$2"
      shift 2
      ;;
    --go-config)
      GO_CONFIG="$2"
      shift 2
      ;;
    --go-api-url)
      GO_API_URL="$2"
      shift 2
      ;;
    --go-api-token)
      GO_API_TOKEN="$2"
      shift 2
      ;;
    --go-build-enabled)
      GO_BUILD_ENABLED="$2"
      shift 2
      ;;
    --go-build-tags)
      GO_BUILD_TAGS="$2"
      shift 2
      ;;
    --rust-bin)
      RUST_BIN="$2"
      shift 2
      ;;
    --rust-config)
      RUST_CONFIG="$2"
      shift 2
      ;;
    --rust-api-url)
      RUST_API_URL="$2"
      shift 2
      ;;
    --rust-api-token)
      RUST_API_TOKEN="$2"
      shift 2
      ;;
    --rust-build-enabled)
      RUST_BUILD_ENABLED="$2"
      shift 2
      ;;
    --rust-build-features)
      RUST_BUILD_FEATURES="$2"
      shift 2
      ;;
    --runtime-log-dir)
      RUNTIME_LOG_DIR="$2"
      shift 2
      ;;
    --automation-cmd)
      AUTOMATION_CMD="$2"
      shift 2
      ;;
    --timeout-sec)
      TIMEOUT_SEC="$2"
      shift 2
      ;;
    --capabilities-gate-enabled)
      CAPABILITIES_GATE_ENABLED="$2"
      shift 2
      ;;
    --go-capabilities-required)
      GO_CAPABILITIES_REQUIRED="$2"
      shift 2
      ;;
    --rust-capabilities-required)
      RUST_CAPABILITIES_REQUIRED="$2"
      shift 2
      ;;
    --report-json)
      REPORT_JSON="$2"
      shift 2
      ;;
    --report-md)
      REPORT_MD="$2"
      shift 2
      ;;
    --sandbox-root)
      SANDBOX_ROOT="$2"
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

if [[ -z "$GUI_APP" ]]; then
  echo "--gui-app is required" >&2
  exit 2
fi

if [[ ! -e "$GUI_APP" ]]; then
  echo "gui app not found: $GUI_APP" >&2
  exit 1
fi

if [[ "$GO_BUILD_ENABLED" != "0" && "$GO_BUILD_ENABLED" != "1" ]]; then
  echo "--go-build-enabled must be 0 or 1" >&2
  exit 2
fi
if [[ "$RUST_BUILD_ENABLED" != "0" && "$RUST_BUILD_ENABLED" != "1" ]]; then
  echo "--rust-build-enabled must be 0 or 1" >&2
  exit 2
fi
if [[ ! -f "$GO_CONFIG" ]]; then
  echo "go config not found: $GO_CONFIG" >&2
  exit 1
fi
if [[ ! -f "$RUST_CONFIG" ]]; then
  echo "rust config not found: $RUST_CONFIG" >&2
  exit 1
fi
if [[ -z "$RUNTIME_LOG_DIR" ]]; then
  echo "--runtime-log-dir must not be empty" >&2
  exit 2
fi
if [[ -n "$AUTOMATION_CMD" && ! -x "$AUTOMATION_CMD" ]]; then
  echo "automation cmd not executable: $AUTOMATION_CMD" >&2
  exit 1
fi
if [[ "$ALLOW_EXISTING_SYSTEM_PROXY" != "0" && "$ALLOW_EXISTING_SYSTEM_PROXY" != "1" ]]; then
  echo "--allow-existing-system-proxy must be 0 or 1" >&2
  exit 2
fi
if [[ "$ALLOW_REAL_PROXY_COEXIST" != "0" && "$ALLOW_REAL_PROXY_COEXIST" != "1" ]]; then
  echo "--allow-real-proxy-coexist must be 0 or 1" >&2
  exit 2
fi
if [[ "$CAPABILITIES_GATE_ENABLED" != "0" && "$CAPABILITIES_GATE_ENABLED" != "1" ]]; then
  echo "--capabilities-gate-enabled must be 0 or 1" >&2
  exit 2
fi
if [[ "$GO_CAPABILITIES_REQUIRED" != "0" && "$GO_CAPABILITIES_REQUIRED" != "1" ]]; then
  echo "--go-capabilities-required must be 0 or 1" >&2
  exit 2
fi
if [[ "$RUST_CAPABILITIES_REQUIRED" != "0" && "$RUST_CAPABILITIES_REQUIRED" != "1" ]]; then
  echo "--rust-capabilities-required must be 0 or 1" >&2
  exit 2
fi
if ! [[ "$CAPABILITIES_GATE_TIMEOUT_SEC" =~ ^[0-9]+$ ]] || [[ "$CAPABILITIES_GATE_TIMEOUT_SEC" -lt 1 ]]; then
  echo "L20_CAPABILITIES_GATE_TIMEOUT_SEC must be a positive integer" >&2
  exit 2
fi

if [[ ! ( "$GO_BUILD_ENABLED" == "1" && "$GO_BIN" == "$DEFAULT_GO_BIN" ) && ! -x "$GO_BIN" ]]; then
  echo "go binary not executable: $GO_BIN" >&2
  exit 1
fi
if [[ ! ( "$RUST_BUILD_ENABLED" == "1" && "$RUST_BIN" == "$DEFAULT_RUST_BIN" ) && ! -x "$RUST_BIN" ]]; then
  echo "rust binary not executable: $RUST_BIN" >&2
  exit 1
fi

if [[ "$GO_BUILD_ENABLED" == "1" && "$GO_BIN" == "$DEFAULT_GO_BIN" ]]; then
  if [[ ! -x "${ROOT_DIR}/scripts/l18/build_go_oracle.sh" ]]; then
    echo "go oracle build script not executable: ${ROOT_DIR}/scripts/l18/build_go_oracle.sh" >&2
    exit 1
  fi
  echo "[L18 gui-real] building go oracle (tags=${GO_BUILD_TAGS})..."
  go_build_output="$("${ROOT_DIR}/scripts/l18/build_go_oracle.sh" --build-tags "$GO_BUILD_TAGS")"
  built_go_bin="$(printf '%s\n' "$go_build_output" | sed -n 's/^binary=//p' | tail -n1)"
  if [[ -z "$built_go_bin" || ! -x "$built_go_bin" ]]; then
    echo "go oracle build succeeded but binary path is invalid" >&2
    echo "$go_build_output" >&2
    exit 1
  fi
  GO_BIN="$built_go_bin"
fi

if [[ "$RUST_BUILD_ENABLED" == "1" && "$RUST_BIN" == "$DEFAULT_RUST_BIN" ]]; then
  echo "[L18 gui-real] building rust run (features=${RUST_BUILD_FEATURES})..."
  cargo build --release -p app --features "$RUST_BUILD_FEATURES" --bin run >/dev/null
fi

if [[ ! -x "$GO_BIN" ]]; then
  echo "go binary not executable after build: $GO_BIN" >&2
  exit 1
fi
if [[ ! -x "$RUST_BIN" ]]; then
  echo "rust binary not executable after build: $RUST_BIN" >&2
  exit 1
fi

if [[ -z "$SANDBOX_ROOT" ]]; then
  SANDBOX_ROOT="${ROOT_DIR}/reports/l18/sandbox/gui_real_$(date -u +'%Y%m%dT%H%M%SZ')_${RANDOM}"
fi

mkdir -p "$(dirname "$REPORT_JSON")" "$(dirname "$REPORT_MD")" "$RUNTIME_LOG_DIR" "$SANDBOX_ROOT"

SANDBOX_TMP="${SANDBOX_ROOT}/tmp"
mkdir -p "$SANDBOX_TMP"

RESULTS_FILE="$(mktemp)"
SANDBOX_NOTES_FILE="$(mktemp)"
PROC_HITS_FILE="$(mktemp)"
PORT_HITS_FILE="$(mktemp)"
SYSTEM_PROXY_BEFORE_FILE="${SANDBOX_ROOT}/system_proxy.before.txt"
SYSTEM_PROXY_AFTER_FILE="${SANDBOX_ROOT}/system_proxy.after.txt"

GUI_PID=""
ACTIVE_KERNEL_PID=""

SANDBOX_PRECHECK_PASS=1
SANDBOX_POSTCHECK_PASS=1
SYSTEM_PROXY_UNCHANGED=1
SYSTEM_PROXY_BEFORE_ENABLED=0
SYSTEM_PROXY_AFTER_ENABLED=0

cleanup_files() {
  stop_pid "$ACTIVE_KERNEL_PID"
  stop_pid "$GUI_PID"
  if [[ -f "$SYSTEM_PROXY_BEFORE_FILE" ]]; then
    snapshot_system_proxy "$SYSTEM_PROXY_AFTER_FILE" >/dev/null 2>&1 || true
    if [[ ! -f "$SYSTEM_PROXY_AFTER_FILE" ]] || ! cmp -s "$SYSTEM_PROXY_BEFORE_FILE" "$SYSTEM_PROXY_AFTER_FILE"; then
      restore_system_proxy_snapshot "$SYSTEM_PROXY_BEFORE_FILE" >/dev/null 2>&1 || true
    fi
  fi
  rm -f "$RESULTS_FILE" "$SANDBOX_NOTES_FILE" "$PROC_HITS_FILE" "$PORT_HITS_FILE"
}
trap cleanup_files EXIT

record_sandbox_note() {
  local note="$1"
  echo "$note" >> "$SANDBOX_NOTES_FILE"
}

sanitize_note() {
  echo "$1" | tr '\t\n\r' ' ' | sed 's/  */ /g'
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

assert_loopback_url() {
  local label="$1"
  local url="$2"
  python3 - "$label" "$url" <<'PY'
import sys
import urllib.parse

label, url = sys.argv[1], sys.argv[2]
parsed = urllib.parse.urlparse(url)
host = (parsed.hostname or "").lower()
if host not in ("127.0.0.1", "localhost", "::1"):
    print(f"{label}_not_loopback:{host}")
    sys.exit(1)
print(f"{label}_loopback_ok")
PY
}

check_config_no_system_capture() {
  local label="$1"
  local config_path="$2"

  if jq -e '.inbounds[]? | select((.type // "") | ascii_downcase | IN("tun", "tproxy", "redirect"))' "$config_path" >/dev/null 2>&1; then
    record_sandbox_note "${label}_config_has_system_capture_inbound"
    return 1
  fi
  return 0
}

snapshot_system_proxy() {
  local out_file="$1"
  scutil --proxy > "$out_file"
}

list_network_services() {
  networksetup -listallnetworkservices 2>/dev/null | sed '1d' | sed '/^\*/d' | sed '/^$/d'
}

service_supports_proxy_config() {
  local service="$1"
  networksetup -getwebproxy "$service" >/dev/null 2>&1 || \
    networksetup -getsecurewebproxy "$service" >/dev/null 2>&1 || \
    networksetup -getsocksfirewallproxy "$service" >/dev/null 2>&1
}

is_system_proxy_enabled_file() {
  local in_file="$1"
  if grep -Eq '^[[:space:]]*(HTTPEnable|HTTPSEnable|SOCKSEnable|ProxyAutoConfigEnable|ProxyAutoDiscoveryEnable)[[:space:]]*:[[:space:]]*1$' "$in_file"; then
    return 0
  fi
  return 1
}

restore_system_proxy_snapshot() {
  local snapshot_file="$1"
  local http_enable=""
  local http_proxy=""
  local http_port=""
  local https_enable=""
  local https_proxy=""
  local https_port=""
  local socks_enable=""
  local socks_proxy=""
  local socks_port=""
  local pac_enable=""
  local pac_url=""
  local autodiscovery_enable=""
  local bypass_domains=()
  local services=()
  local discovered_services=()
  local key=""
  local value=""
  local existing=""
  local candidate=""
  local duplicate=0

  while IFS= read -r candidate; do
    [[ -z "$candidate" ]] && continue
    discovered_services+=("$candidate")
  done < <(list_network_services)
  for candidate in "Wi-Fi" "Ethernet"; do
    [[ -z "$candidate" ]] && continue
    services+=("$candidate")
  done
  for candidate in "${discovered_services[@]}"; do
    [[ -z "$candidate" ]] && continue
    duplicate=0
    for existing in "${services[@]}"; do
      if [[ "$existing" == "$candidate" ]]; then
        duplicate=1
        break
      fi
    done
    if [[ "$duplicate" == "0" ]]; then
      services+=("$candidate")
    fi
  done

  while IFS=$'\t' read -r key value; do
    case "$key" in
      HTTPEnable) http_enable="$value" ;;
      HTTPProxy) http_proxy="$value" ;;
      HTTPPort) http_port="$value" ;;
      HTTPSEnable) https_enable="$value" ;;
      HTTPSProxy) https_proxy="$value" ;;
      HTTPSPort) https_port="$value" ;;
      SOCKSEnable) socks_enable="$value" ;;
      SOCKSProxy) socks_proxy="$value" ;;
      SOCKSPort) socks_port="$value" ;;
      ProxyAutoConfigEnable) pac_enable="$value" ;;
      ProxyAutoConfigURLString) pac_url="$value" ;;
      ProxyAutoDiscoveryEnable) autodiscovery_enable="$value" ;;
      ExceptionsListItem) bypass_domains+=("$value") ;;
    esac
  done < <(
    python3 - "$snapshot_file" <<'PY'
import re
import sys

snapshot_path = sys.argv[1]
array_key = None

with open(snapshot_path, "r", encoding="utf-8", errors="replace") as fh:
    for raw in fh:
        line = raw.rstrip("\n")
        if array_key:
            if line.strip() == "}":
                array_key = None
                continue
            match = re.match(r"\s+\d+\s+:\s+(.*)$", line)
            if match:
                print(f"{array_key}Item\t{match.group(1)}")
            continue

        array_match = re.match(r"\s+([A-Za-z0-9]+)\s+:\s+<array>\s+\{$", line)
        if array_match:
          array_key = array_match.group(1)
          continue

        match = re.match(r"\s+([A-Za-z0-9]+)\s+:\s+(.*)$", line)
        if match:
            print(f"{match.group(1)}\t{match.group(2)}")
PY
  )

  local attempted=0
  local service=""
  for service in "${services[@]}"; do
    if ! service_supports_proxy_config "$service"; then
      continue
    fi
    attempted=1

    if [[ "$http_enable" == "1" && -n "$http_proxy" && "$http_port" =~ ^[0-9]+$ ]]; then
      networksetup -setwebproxy "$service" "$http_proxy" "$http_port" >/dev/null 2>&1 || true
      networksetup -setwebproxystate "$service" on >/dev/null 2>&1 || true
    else
      networksetup -setwebproxystate "$service" off >/dev/null 2>&1 || true
    fi

    if [[ "$https_enable" == "1" && -n "$https_proxy" && "$https_port" =~ ^[0-9]+$ ]]; then
      networksetup -setsecurewebproxy "$service" "$https_proxy" "$https_port" >/dev/null 2>&1 || true
      networksetup -setsecurewebproxystate "$service" on >/dev/null 2>&1 || true
    else
      networksetup -setsecurewebproxystate "$service" off >/dev/null 2>&1 || true
    fi

    if [[ "$socks_enable" == "1" && -n "$socks_proxy" && "$socks_port" =~ ^[0-9]+$ ]]; then
      networksetup -setsocksfirewallproxy "$service" "$socks_proxy" "$socks_port" >/dev/null 2>&1 || true
      networksetup -setsocksfirewallproxystate "$service" on >/dev/null 2>&1 || true
    else
      networksetup -setsocksfirewallproxystate "$service" off >/dev/null 2>&1 || true
    fi

    if [[ "${#bypass_domains[@]}" -gt 0 ]]; then
      networksetup -setproxybypassdomains "$service" "${bypass_domains[@]}" >/dev/null 2>&1 || true
    else
      networksetup -setproxybypassdomains "$service" Empty >/dev/null 2>&1 || true
    fi

    if [[ "$pac_enable" == "1" && -n "$pac_url" ]]; then
      networksetup -setautoproxyurl "$service" "$pac_url" >/dev/null 2>&1 || true
      networksetup -setautoproxystate "$service" on >/dev/null 2>&1 || true
    else
      networksetup -setautoproxystate "$service" off >/dev/null 2>&1 || true
    fi

    if [[ "$autodiscovery_enable" == "1" ]]; then
      networksetup -setproxyautodiscovery "$service" on >/dev/null 2>&1 || true
    else
      networksetup -setproxyautodiscovery "$service" off >/dev/null 2>&1 || true
    fi
  done

  if [[ "$attempted" == "1" ]]; then
    return 0
  fi
  return 1
}

expected_runtime_ports_released() {
  IFS=',' read -r -a expected_ports <<< "$EXPECTED_RUNTIME_PORTS"
  for raw_port in "${expected_ports[@]}"; do
    port="$(echo "$raw_port" | tr -d '[:space:]')"
    [[ -z "$port" ]] && continue
    if lsof -nP -iTCP:"$port" -sTCP:LISTEN >/dev/null 2>&1; then
      return 1
    fi
  done
  return 0
}

detect_real_proxy_processes() {
  : > "$PROC_HITS_FILE"
  IFS=',' read -r -a patterns <<< "$REAL_PROXY_PROCESS_PATTERNS"
  for raw in "${patterns[@]}"; do
    pattern="$(echo "$raw" | sed 's/^ *//;s/ *$//')"
    [[ -z "$pattern" ]] && continue
    while IFS= read -r pid; do
      [[ -z "$pid" ]] && continue
      cmd="$(ps -p "$pid" -o command= 2>/dev/null | head -n1 | sed 's/^ *//')"
      [[ -z "$cmd" ]] && continue
      printf '%s\t%s\t%s\n' "$pattern" "$pid" "$cmd" >> "$PROC_HITS_FILE"
    done < <(pgrep -if "$pattern" || true)
  done
  if [[ -s "$PROC_HITS_FILE" ]]; then
    sort -u "$PROC_HITS_FILE" -o "$PROC_HITS_FILE"
  fi
}

detect_real_proxy_ports() {
  : > "$PORT_HITS_FILE"
  IFS=',' read -r -a ports <<< "$REAL_PROXY_PORTS"
  for raw in "${ports[@]}"; do
    port="$(echo "$raw" | tr -d '[:space:]')"
    [[ -z "$port" ]] && continue
    [[ "$port" =~ ^[0-9]+$ ]] || continue
    if lsof -nP -iTCP:"${port}" -sTCP:LISTEN >/dev/null 2>&1; then
      lsof -nP -iTCP:"${port}" -sTCP:LISTEN | sed '1d' | awk -v p="$port" '{print p"\t"$1"\t"$2"\t"$9}' >> "$PORT_HITS_FILE"
    fi
  done
  if [[ -s "$PORT_HITS_FILE" ]]; then
    sort -u "$PORT_HITS_FILE" -o "$PORT_HITS_FILE"
  fi
}

curl_code() {
  local api_url="$1"
  local path="$2"
  local token="$3"

  if [[ -n "$token" ]]; then
    curl -sS --max-time 5 -o /dev/null -w '%{http_code}' -H "Authorization: Bearer ${token}" "${api_url}${path}" || echo 000
  else
    curl -sS --max-time 5 -o /dev/null -w '%{http_code}' "${api_url}${path}" || echo 000
  fi
}

websocket_code() {
  local api_url="$1"
  local path="$2"
  local code=""
  local rc=0

  code="$(curl -sS --http1.1 --max-time 3 -o /dev/null -w '%{http_code}' \
    -H 'Connection: Upgrade' \
    -H 'Upgrade: websocket' \
    -H 'Sec-WebSocket-Version: 13' \
    -H 'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==' \
    "${api_url}${path}" 2>/dev/null)" || rc=$?

  if [[ "$code" == "101" || "$code" == "200" ]]; then
    echo "$code"
    return 0
  fi

  if [[ -n "$code" ]]; then
    echo "$code"
  else
    echo "000"
  fi
  return "$rc"
}

check_capabilities_negotiation() {
  local core="$1"
  local api_url="$2"
  local token="$3"
  local required="$4"
  local out_json="$5"

  python3 "${ROOT_DIR}/scripts/l18/capability_negotiation_eval.py" \
    --core "$core" \
    --api-url "$api_url" \
    --token "$token" \
    --required "$required" \
    --timeout-sec "$CAPABILITIES_GATE_TIMEOUT_SEC" \
    --out-json "$out_json"
}

wait_health_200() {
  local api_url="$1"
  local token="$2"
  local timeout_sec="$3"
  local i=0
  while [[ "$i" -lt "$timeout_sec" ]]; do
    code="$(curl_code "$api_url" "/services/health" "$token")"
    if [[ "$code" == "200" ]]; then
      return 0
    fi
    i=$((i + 1))
    sleep 1
  done
  return 1
}

wait_kernel_ready() {
  local api_url="$1"
  local token="$2"
  local timeout_sec="$3"
  local i=0
  while [[ "$i" -lt "$timeout_sec" ]]; do
    health_code="$(curl_code "$api_url" "/services/health" "$token")"
    if [[ "$health_code" == "200" ]]; then
      return 0
    fi

    proxies_code="$(curl_code "$api_url" "/proxies" "$token")"
    if [[ "$proxies_code" == "200" ]]; then
      return 0
    fi

    i=$((i + 1))
    sleep 1
  done
  return 1
}

wait_gui_pid() {
  local pid="$1"
  local timeout_sec="$2"
  local i=0
  while [[ "$i" -lt "$timeout_sec" ]]; do
    if [[ -n "$pid" ]] && kill -0 "$pid" >/dev/null 2>&1; then
      return 0
    fi
    if pgrep -if "$GUI_PROCESS_NAME" >/dev/null 2>&1; then
      return 0
    fi
    i=$((i + 1))
    sleep 1
  done
  return 1
}

gui_window_count() {
  local count
  count="$(osascript -e "tell application \"System Events\" to count windows of process \"${GUI_PROCESS_NAME}\"" 2>/dev/null || echo 0)"
  if [[ "$count" =~ ^[0-9]+$ ]]; then
    echo "$count"
  else
    echo "0"
  fi
}

wait_gui_window() {
  local timeout_sec="$1"
  local i=0
  while [[ "$i" -lt "$timeout_sec" ]]; do
    local count
    count="$(gui_window_count)"
    if [[ "$count" -gt 0 ]]; then
      echo "$count"
      return 0
    fi
    i=$((i + 1))
    sleep 1
  done
  echo "$(gui_window_count)"
  return 1
}

activate_gui_process() {
  osascript -e "tell application \"System Events\" to set frontmost of process \"${GUI_PROCESS_NAME}\" to true" >/dev/null 2>&1 || true
}

url_hostport() {
  local url="$1"
  local no_scheme="${url#*://}"
  echo "${no_scheme%%/*}"
}

stop_pid() {
  local pid="$1"
  if [[ -z "$pid" ]]; then
    return
  fi
  if kill -0 "$pid" >/dev/null 2>&1; then
    kill "-$pid" >/dev/null 2>&1 || kill "$pid" >/dev/null 2>&1 || true
    for _ in $(seq 1 20); do
      if ! kill -0 "$pid" >/dev/null 2>&1; then
        wait "$pid" >/dev/null 2>&1 || true
        return
      fi
      sleep 0.2
    done
    kill -KILL "-$pid" >/dev/null 2>&1 || kill -KILL "$pid" >/dev/null 2>&1 || true
    wait "$pid" >/dev/null 2>&1 || true
  fi
}

resolve_gui_executable() {
  local app_path="$1"
  if [[ "$app_path" == *.app ]]; then
    local info_plist="${app_path}/Contents/Info.plist"
    if [[ ! -f "$info_plist" ]]; then
      return 1
    fi
    local exe_name
    exe_name="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleExecutable' "$info_plist" 2>/dev/null || true)"
    if [[ -z "$exe_name" ]]; then
      return 1
    fi
    local exec_path="${app_path}/Contents/MacOS/${exe_name}"
    if [[ ! -x "$exec_path" ]]; then
      return 1
    fi
    echo "$exec_path"
    return 0
  fi

  if [[ -x "$app_path" ]]; then
    echo "$app_path"
    return 0
  fi

  return 1
}

start_gui() {
  local gui_exec="$1"
  local core_home="$2"
  local core_tmp="$3"
  local gui_log="$4"

  mkdir -p "$core_home" "$core_tmp"
  HOME="$core_home" \
  XDG_CONFIG_HOME="$core_home/.config" \
  XDG_CACHE_HOME="$core_home/.cache" \
  TMPDIR="$core_tmp" \
  GUI_PID="$(spawn_in_own_session "$gui_log" "$gui_exec")"
}

switch_proxy_step() {
  local api_url="$1"
  local token="$2"

  python3 - "$api_url" "$token" <<'PY'
import json
import sys
import urllib.error
import urllib.parse
import urllib.request

api = sys.argv[1].rstrip("/")
token = sys.argv[2]

headers = {"Accept": "application/json"}
if token:
    headers["Authorization"] = f"Bearer {token}"

req = urllib.request.Request(f"{api}/proxies", headers=headers, method="GET")
try:
    with urllib.request.urlopen(req, timeout=8) as resp:
        if resp.status != 200:
            raise RuntimeError(f"GET /proxies status={resp.status}")
        payload = json.loads(resp.read().decode("utf-8", errors="ignore"))
except Exception as exc:
    print(f"fetch_proxies_failed:{exc}")
    sys.exit(1)

proxies = payload.get("proxies") if isinstance(payload, dict) else None
if not isinstance(proxies, dict):
    print("invalid_proxies_payload")
    sys.exit(1)

selected = None
for name, obj in proxies.items():
    if name == "GLOBAL":
        continue
    if isinstance(obj, dict) and isinstance(obj.get("all"), list) and obj.get("all"):
        now = obj.get("now")
        if isinstance(now, str) and now:
            selected = (name, now)
            break
        first = obj["all"][0]
        if isinstance(first, str) and first:
            selected = (name, first)
            break

if not selected:
    print("switch_not_applicable:no_selector_group_found")
    sys.exit(0)

group, target = selected
body = json.dumps({"name": target}).encode("utf-8")
url_group = urllib.parse.quote(group, safe="")
put_req = urllib.request.Request(
    f"{api}/proxies/{url_group}",
    data=body,
    headers={**headers, "Content-Type": "application/json"},
    method="PUT",
)

try:
    with urllib.request.urlopen(put_req, timeout=8) as resp:
        if resp.status not in (200, 204):
            raise RuntimeError(f"PUT /proxies/{group} status={resp.status}")
except urllib.error.HTTPError as exc:
    if exc.code in (404, 405):
        print(f"switch_endpoint_not_supported:{exc.code}")
        sys.exit(0)
    print(f"proxy_switch_http_error:{exc.code}")
    sys.exit(1)
except Exception as exc:
    print(f"proxy_switch_failed:{exc}")
    sys.exit(1)

print(f"switched:{group}->{target}")
PY
}

append_all_step_failures() {
  local core="$1"
  local reason="$2"
  for step_id in startup load_config switch_proxy connections_panel logs_panel; do
    printf '%s\t%s\t%s\t%s\n' "$core" "$step_id" "FAILED" "$reason" >> "$RESULTS_FILE"
  done
}

run_step() {
  local core="$1"
  local step_id="$2"
  local api_url="$3"
  local token="$4"
  local kernel_log="$5"

  local status="PROVEN"
  local note=""

  if [[ -n "$AUTOMATION_CMD" ]]; then
    if ! note="$($AUTOMATION_CMD --core "$core" --step "$step_id" --api-url "$api_url" 2>&1)"; then
      status="FAILED"
      note="automation_failed:${note}"
    fi
  else
    case "$step_id" in
      startup)
        if wait_gui_pid "$GUI_PID" "$TIMEOUT_SEC" && wait_kernel_ready "$api_url" "$token" "$TIMEOUT_SEC"; then
          activate_gui_process
          if ! window_count="$(wait_gui_window 5)"; then
            status="PARTIAL"
            note="gui_process_and_kernel_ready windows=0"
          else
            note="gui_process_and_kernel_ready windows=${window_count}"
          fi
        else
          status="FAILED"
          note="gui_or_kernel_not_ready"
        fi
        ;;
      load_config)
        code="$(curl_code "$api_url" "/proxies" "$token")"
        if [[ "$code" == "200" ]]; then
          note="/proxies=200"
        else
          status="FAILED"
          note="/proxies=${code}"
        fi
        ;;
      switch_proxy)
        if note="$(switch_proxy_step "$api_url" "$token" 2>/dev/null)"; then
          case "$note" in
            switch_not_applicable:*|switch_endpoint_not_supported:*)
              status="PARTIAL"
              ;;
          esac
        else
          status="FAILED"
        fi
        ;;
      connections_panel)
        code="$(curl_code "$api_url" "/connections" "$token")"
        if [[ "$code" == "200" ]]; then
          note="/connections=200"
        else
          status="FAILED"
          note="/connections=${code}"
        fi
        ;;
      logs_panel)
        local ws_path="/logs?level=debug"
        if [[ -n "$token" ]]; then
          ws_path="${ws_path}&token=${token}"
        fi
        code="$(websocket_code "$api_url" "$ws_path")"
        if [[ "$code" == "101" || "$code" == "200" ]]; then
          note="/logs=${code}"
        elif [[ -s "$kernel_log" ]]; then
          note="kernel_log_non_empty"
        else
          code="$(curl_code "$api_url" "/connections" "$token")"
          if [[ "$code" == "200" ]]; then
            status="PARTIAL"
            note="kernel_log_empty_connections_probe=200"
          else
            status="FAILED"
            note="kernel_log_empty_connections_probe=${code}"
          fi
        fi
        ;;
      *)
        status="FAILED"
        note="unknown_step"
        ;;
    esac
  fi

  note="$(sanitize_note "$note")"
  printf '%s\t%s\t%s\t%s\n' "$core" "$step_id" "$status" "$note" >> "$RESULTS_FILE"

  if [[ "$status" == "FAILED" ]]; then
    return 1
  fi
  return 0
}

run_core() {
  local core="$1"
  local bin="$2"
  local config="$3"
  local api_url="$4"
  local token="$5"
  local gui_exec="$6"

  local kernel_log="${RUNTIME_LOG_DIR}/${core}.kernel.log"
  local gui_log="${RUNTIME_LOG_DIR}/${core}.gui.log"
  local core_home="${SANDBOX_ROOT}/home/${core}"
  local core_tmp="${SANDBOX_ROOT}/tmp/${core}"
  local capabilities_required="$RUST_CAPABILITIES_REQUIRED"
  local negotiation_file="${SANDBOX_ROOT}/capabilities.negotiation.${core}.json"
  local start_cmd=()

  mkdir -p "$core_home" "$core_tmp"

  stop_pid "$ACTIVE_KERNEL_PID"
  ACTIVE_KERNEL_PID=""
  stop_pid "$GUI_PID"
  GUI_PID=""

  if [[ "$core" == "go" ]]; then
    start_cmd=("$bin" run -c "$config")
  else
    # Support both rust CLI styles:
    # 1) `<bin> run --config ...` (subcommand style)
    # 2) `<bin> --config ...` (single-command binary, e.g. `run`)
    if "$bin" run --help >/dev/null 2>&1; then
      start_cmd=("$bin" run --config "$config")
    else
      start_cmd=("$bin" --config "$config")
    fi
  fi

  HOME="$core_home" \
  XDG_CONFIG_HOME="$core_home/.config" \
  XDG_CACHE_HOME="$core_home/.cache" \
  TMPDIR="$core_tmp" \
  ACTIVE_KERNEL_PID="$(spawn_in_own_session "$kernel_log" "${start_cmd[@]}")"

  sleep 1
  if ! kill -0 "$ACTIVE_KERNEL_PID" >/dev/null 2>&1; then
    append_all_step_failures "$core" "kernel_failed_to_start"
    return 1
  fi

  if [[ "$core" == "go" ]]; then
    capabilities_required="$GO_CAPABILITIES_REQUIRED"
  fi

  if [[ "$CAPABILITIES_GATE_ENABLED" == "1" ]]; then
    if ! check_capabilities_negotiation "$core" "$api_url" "$token" "$capabilities_required" "$negotiation_file"; then
      local failure_reason
      failure_reason="$(jq -r '.reason // "negotiation_failed"' "$negotiation_file" 2>/dev/null || echo "negotiation_failed")"
      record_sandbox_note "capabilities_negotiation_${core}_failed:${failure_reason}"
      append_all_step_failures "$core" "capabilities_negotiation_failed:${failure_reason}"
      stop_pid "$ACTIVE_KERNEL_PID"
      ACTIVE_KERNEL_PID=""
      return 1
    fi
    local negotiation_status
    negotiation_status="$(jq -r '.status // "unknown"' "$negotiation_file" 2>/dev/null || echo "unknown")"
    local negotiation_reason
    negotiation_reason="$(jq -r '.reason // ""' "$negotiation_file" 2>/dev/null || true)"
    if [[ -n "$negotiation_reason" ]]; then
      record_sandbox_note "capabilities_negotiation_${core}_${negotiation_status}:${negotiation_reason}"
    else
      record_sandbox_note "capabilities_negotiation_${core}_${negotiation_status}"
    fi
  fi

  start_gui "$gui_exec" "$core_home" "$core_tmp" "$gui_log"

  run_step "$core" "startup" "$api_url" "$token" "$kernel_log" || true
  run_step "$core" "load_config" "$api_url" "$token" "$kernel_log" || true
  run_step "$core" "switch_proxy" "$api_url" "$token" "$kernel_log" || true
  run_step "$core" "connections_panel" "$api_url" "$token" "$kernel_log" || true
  run_step "$core" "logs_panel" "$api_url" "$token" "$kernel_log" || true

  stop_pid "$GUI_PID"
  GUI_PID=""
  stop_pid "$ACTIVE_KERNEL_PID"
  ACTIVE_KERNEL_PID=""
}

sandbox_precheck() {
  local ok=0

  if ! assert_loopback_url "go_api" "$GO_API_URL" >/dev/null 2>&1; then
    record_sandbox_note "go_api_not_loopback:${GO_API_URL}"
    ok=1
  fi
  if ! assert_loopback_url "rust_api" "$RUST_API_URL" >/dev/null 2>&1; then
    record_sandbox_note "rust_api_not_loopback:${RUST_API_URL}"
    ok=1
  fi

  if ! check_config_no_system_capture "go" "$GO_CONFIG"; then
    ok=1
  fi
  if ! check_config_no_system_capture "rust" "$RUST_CONFIG"; then
    ok=1
  fi

  snapshot_system_proxy "$SYSTEM_PROXY_BEFORE_FILE"
  if is_system_proxy_enabled_file "$SYSTEM_PROXY_BEFORE_FILE"; then
    SYSTEM_PROXY_BEFORE_ENABLED=1
    if [[ "$ALLOW_EXISTING_SYSTEM_PROXY" != "1" ]]; then
      record_sandbox_note "existing_system_proxy_enabled"
      ok=1
    fi
  fi

  if [[ "$ALLOW_REAL_PROXY_COEXIST" != "1" ]]; then
    detect_real_proxy_processes
    if [[ -s "$PROC_HITS_FILE" ]]; then
      while IFS= read -r line; do
        record_sandbox_note "real_proxy_process_detected:${line}"
      done < "$PROC_HITS_FILE"
      ok=1
    fi

    detect_real_proxy_ports
    if [[ -s "$PORT_HITS_FILE" ]]; then
      while IFS= read -r line; do
        record_sandbox_note "real_proxy_port_busy:${line}"
      done < "$PORT_HITS_FILE"
      ok=1
    fi
  fi

  return "$ok"
}

run_postcheck() {
  local settled=0
  local after_enabled=0
  for _ in $(seq 1 40); do
    snapshot_system_proxy "$SYSTEM_PROXY_AFTER_FILE"
    after_enabled=0
    if is_system_proxy_enabled_file "$SYSTEM_PROXY_AFTER_FILE"; then
      after_enabled=1
    fi
    if cmp -s "$SYSTEM_PROXY_BEFORE_FILE" "$SYSTEM_PROXY_AFTER_FILE" && expected_runtime_ports_released; then
      SYSTEM_PROXY_AFTER_ENABLED="$after_enabled"
      SYSTEM_PROXY_UNCHANGED=1
      SANDBOX_POSTCHECK_PASS=1
      settled=1
      break
    fi
    sleep 0.25
  done

  if [[ "$settled" == "1" ]]; then
    return 0
  fi

  snapshot_system_proxy "$SYSTEM_PROXY_AFTER_FILE"
  if is_system_proxy_enabled_file "$SYSTEM_PROXY_AFTER_FILE"; then
    SYSTEM_PROXY_AFTER_ENABLED=1
  fi

  if ! cmp -s "$SYSTEM_PROXY_BEFORE_FILE" "$SYSTEM_PROXY_AFTER_FILE"; then
    if restore_system_proxy_snapshot "$SYSTEM_PROXY_BEFORE_FILE"; then
      for _ in $(seq 1 20); do
        snapshot_system_proxy "$SYSTEM_PROXY_AFTER_FILE"
        after_enabled=0
        if is_system_proxy_enabled_file "$SYSTEM_PROXY_AFTER_FILE"; then
          after_enabled=1
        fi
        if cmp -s "$SYSTEM_PROXY_BEFORE_FILE" "$SYSTEM_PROXY_AFTER_FILE" && expected_runtime_ports_released; then
          SYSTEM_PROXY_AFTER_ENABLED="$after_enabled"
          SYSTEM_PROXY_UNCHANGED=1
          SANDBOX_POSTCHECK_PASS=1
          record_sandbox_note "system_proxy_snapshot_restored"
          return 0
        fi
        sleep 0.25
      done
      snapshot_system_proxy "$SYSTEM_PROXY_AFTER_FILE"
      if is_system_proxy_enabled_file "$SYSTEM_PROXY_AFTER_FILE"; then
        SYSTEM_PROXY_AFTER_ENABLED=1
      else
        SYSTEM_PROXY_AFTER_ENABLED=0
      fi
      record_sandbox_note "system_proxy_restore_attempted"
    else
      record_sandbox_note "system_proxy_restore_failed"
    fi
  fi

  if ! cmp -s "$SYSTEM_PROXY_BEFORE_FILE" "$SYSTEM_PROXY_AFTER_FILE"; then
    SYSTEM_PROXY_UNCHANGED=0
    SANDBOX_POSTCHECK_PASS=0
    record_sandbox_note "system_proxy_snapshot_changed"
  fi

  IFS=',' read -r -a expected_ports <<< "$EXPECTED_RUNTIME_PORTS"
  for raw_port in "${expected_ports[@]}"; do
    port="$(echo "$raw_port" | tr -d '[:space:]')"
    [[ -z "$port" ]] && continue
    if lsof -nP -iTCP:"$port" -sTCP:LISTEN >/dev/null 2>&1; then
      SANDBOX_POSTCHECK_PASS=0
      record_sandbox_note "port_not_released:${port}"
    fi
  done
}

GUI_EXEC=""
if GUI_EXEC="$(resolve_gui_executable "$GUI_APP")"; then
  :
else
  record_sandbox_note "gui_executable_unresolved:${GUI_APP}"
  SANDBOX_PRECHECK_PASS=0
fi

if [[ "$SANDBOX_PRECHECK_PASS" -eq 1 ]]; then
  if ! sandbox_precheck; then
    SANDBOX_PRECHECK_PASS=0
  fi
fi

if [[ "$SANDBOX_PRECHECK_PASS" -eq 1 ]]; then
  run_core "go" "$GO_BIN" "$GO_CONFIG" "$GO_API_URL" "$GO_API_TOKEN" "$GUI_EXEC" || true
  run_core "rust" "$RUST_BIN" "$RUST_CONFIG" "$RUST_API_URL" "$RUST_API_TOKEN" "$GUI_EXEC" || true
else
  append_all_step_failures "go" "sandbox_precheck_failed"
  append_all_step_failures "rust" "sandbox_precheck_failed"
  SANDBOX_POSTCHECK_PASS=0
fi

run_postcheck

export RESULTS_FILE REPORT_JSON REPORT_MD GUI_APP GUI_PROCESS_NAME GO_API_URL RUST_API_URL SANDBOX_ROOT SANDBOX_NOTES_FILE
export SANDBOX_PRECHECK_PASS SANDBOX_POSTCHECK_PASS SYSTEM_PROXY_UNCHANGED SYSTEM_PROXY_BEFORE_ENABLED SYSTEM_PROXY_AFTER_ENABLED
export CAPABILITIES_GATE_ENABLED
export NEGOTIATION_GO_FILE="${SANDBOX_ROOT}/capabilities.negotiation.go.json"
export NEGOTIATION_RUST_FILE="${SANDBOX_ROOT}/capabilities.negotiation.rust.json"
python3 - <<'PY'
import json
import os
from datetime import datetime, timezone

required_steps = ["startup", "load_config", "switch_proxy", "connections_panel", "logs_panel"]
cores = {
    "go": {"steps": {}, "ordered_steps": []},
    "rust": {"steps": {}, "ordered_steps": []},
}

with open(os.environ["RESULTS_FILE"], "r", encoding="utf-8") as f:
    for line in f:
        line = line.rstrip("\n")
        if not line:
            continue
        core, step_id, status, note = line.split("\t", 3)
        if core not in cores:
            continue
        record = {"id": step_id, "status": status, "note": note}
        cores[core]["steps"][step_id] = record

for core in ("go", "rust"):
    ordered = []
    missing = []
    overall_status = "PROVEN"
    for step_id in required_steps:
        item = cores[core]["steps"].get(step_id)
        if not item:
            item = {"id": step_id, "status": "FAILED", "note": "missing_step_record"}
            missing.append(step_id)
            overall_status = "FAILED"
        elif item["status"] == "FAILED":
            overall_status = "FAILED"
        elif item["status"] in ("PARTIAL", "ADVISORY", "UNTESTED") and overall_status != "FAILED":
            overall_status = "PARTIAL"
        ordered.append(item)
    cores[core]["ordered_steps"] = ordered
    cores[core]["overall_status"] = overall_status
    cores[core]["pass"] = overall_status != "FAILED"
    cores[core]["missing_steps"] = missing

sandbox_notes = []
if os.path.isfile(os.environ["SANDBOX_NOTES_FILE"]):
    with open(os.environ["SANDBOX_NOTES_FILE"], "r", encoding="utf-8") as f:
        sandbox_notes = [line.strip() for line in f if line.strip()]

sandbox_precheck = os.environ.get("SANDBOX_PRECHECK_PASS", "0") == "1"
sandbox_postcheck = os.environ.get("SANDBOX_POSTCHECK_PASS", "0") == "1"
proxy_unchanged = os.environ.get("SYSTEM_PROXY_UNCHANGED", "0") == "1"

sandbox_pass = sandbox_precheck and sandbox_postcheck and proxy_unchanged
sandbox_status = "PROVEN" if sandbox_pass else "FAILED"

def load_negotiation(path: str):
    if not os.path.isfile(path):
        return {
            "checked": False,
            "pass": False,
            "status": "not-run",
            "reason": "missing_negotiation_artifact",
        }
    try:
        with open(path, "r", encoding="utf-8") as fh:
            payload = json.load(fh)
    except Exception as exc:
        return {
            "checked": False,
            "pass": False,
            "status": "invalid-artifact",
            "reason": f"parse_failed:{exc}",
        }
    if not isinstance(payload, dict):
        return {
            "checked": False,
            "pass": False,
            "status": "invalid-artifact",
            "reason": "artifact_not_object",
        }
    return payload

negotiation_enabled = os.environ.get("CAPABILITIES_GATE_ENABLED", "0") == "1"
negotiation = {
    "enabled": negotiation_enabled,
    "go": load_negotiation(os.environ["NEGOTIATION_GO_FILE"]),
    "rust": load_negotiation(os.environ["NEGOTIATION_RUST_FILE"]),
}

for core in ("go", "rust"):
    item = negotiation[core]
    required = item.get("required") is True
    if required and item.get("status") in ("PARTIAL", "ADVISORY", "UNTESTED") and cores[core]["overall_status"] == "PROVEN":
        cores[core]["overall_status"] = "PARTIAL"
        cores[core]["pass"] = True
    if item.get("status") == "FAILED":
        cores[core]["overall_status"] = "FAILED"
        cores[core]["pass"] = False

overall_status = "PROVEN"
if sandbox_status == "FAILED" or any(cores[core]["overall_status"] == "FAILED" for core in ("go", "rust")):
    overall_status = "FAILED"
elif any(cores[core]["overall_status"] in ("PARTIAL", "ADVISORY", "UNTESTED") for core in ("go", "rust")):
    overall_status = "PARTIAL"

overall_pass = overall_status != "FAILED"

payload = {
    "generated_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
    "gui": {
        "app": os.path.abspath(os.environ["GUI_APP"]),
        "process_name": os.environ["GUI_PROCESS_NAME"],
    },
    "api_urls": {
        "go": os.environ["GO_API_URL"],
        "rust": os.environ["RUST_API_URL"],
    },
    "sandbox": {
        "root": os.path.abspath(os.environ["SANDBOX_ROOT"]),
        "status": sandbox_status,
        "precheck_pass": sandbox_precheck,
        "postcheck_pass": sandbox_postcheck,
        "system_proxy_snapshot_unchanged": proxy_unchanged,
        "system_proxy_before_enabled": os.environ.get("SYSTEM_PROXY_BEFORE_ENABLED", "0") == "1",
        "system_proxy_after_enabled": os.environ.get("SYSTEM_PROXY_AFTER_ENABLED", "0") == "1",
        "notes": sandbox_notes,
    },
    "required_steps": required_steps,
    "capability_negotiation": negotiation,
    "cores": {
        "go": {
            "overall_status": cores["go"]["overall_status"],
            "pass": cores["go"]["pass"],
            "missing_steps": cores["go"]["missing_steps"],
            "steps": cores["go"]["ordered_steps"],
        },
        "rust": {
            "overall_status": cores["rust"]["overall_status"],
            "pass": cores["rust"]["pass"],
            "missing_steps": cores["rust"]["missing_steps"],
            "steps": cores["rust"]["ordered_steps"],
        },
    },
    "overall_status": overall_status,
    "pass": overall_pass,
}

with open(os.environ["REPORT_JSON"], "w", encoding="utf-8") as f:
    json.dump(payload, f, indent=2, ensure_ascii=False)

lines = []
lines.append("# L18 GUI Real Certification")
lines.append("")
lines.append(f"- Generated: {payload['generated_at']}")
lines.append(f"- GUI App: `{payload['gui']['app']}`")
lines.append(f"- GUI Process: `{payload['gui']['process_name']}`")
lines.append(f"- Sandbox Root: `{payload['sandbox']['root']}`")
lines.append(f"- Sandbox: **{sandbox_status}**")
lines.append(f"- Overall: **{overall_status}**")
lines.append("")

lines.append("## Capability Negotiation")
lines.append("")
lines.append(f"- Enabled: `{str(negotiation_enabled).lower()}`")
lines.append("")
lines.append("| Core | Required | Status | Pass | Contract | Min Required | Reason |")
lines.append("|---|---|---|---|---|---|---|")
for core in ("go", "rust"):
    item = negotiation[core]
    required = item.get("required")
    required_cell = str(required).lower() if isinstance(required, bool) else "-"
    status = item.get("status", "-")
    passed = item.get("pass")
    pass_cell = str(passed).lower() if isinstance(passed, bool) else "-"
    contract = item.get("contract_version") or "-"
    minimum = item.get("required_min_contract_version") or "-"
    reason = item.get("reason") or "-"
    lines.append(f"| `{core}` | `{required_cell}` | `{status}` | `{pass_cell}` | `{contract}` | `{minimum}` | `{reason}` |")
lines.append("")

if sandbox_notes:
    lines.append("## Sandbox Notes")
    lines.append("")
    for note in sandbox_notes:
        lines.append(f"- {note}")
    lines.append("")

lines.append("| Step | Go | Rust |")
lines.append("|---|---|---|")
for step_id in required_steps:
    go_step = cores["go"]["steps"].get(step_id, {"status": "FAILED", "note": "missing"})
    rust_step = cores["rust"]["steps"].get(step_id, {"status": "FAILED", "note": "missing"})
    go_cell = f"{go_step['status']} ({go_step['note']})"
    rust_cell = f"{rust_step['status']} ({rust_step['note']})"
    lines.append(f"| `{step_id}` | {go_cell} | {rust_cell} |")

with open(os.environ["REPORT_MD"], "w", encoding="utf-8") as f:
    f.write("\n".join(lines) + "\n")

print(f"report json written: {os.environ['REPORT_JSON']}")
print(f"report md written: {os.environ['REPORT_MD']}")
print(f"overall_pass={int(overall_pass)}")
PY

overall_status="$(jq -r '.overall_status // (if .pass then "PROVEN" else "FAILED" end)' "$REPORT_JSON")"
if [[ "$overall_status" == "FAILED" ]]; then
  echo "[L18 gui-real] FAILED" >&2
  exit 1
fi

echo "[L18 gui-real] ${overall_status}"
