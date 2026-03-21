#!/usr/bin/env bash
# Shared Go oracle helper functions.
# Sourced by: run_case_trend_gate.sh, run_dual_kernel_diff_replay.sh, aggregate_trend_report.sh
#
# Expected variables (set by the sourcing script before sourcing):
#   GO_ORACLE_BIN, GO_ORACLE_CONFIG, GO_ORACLE_API_URL, GO_ORACLE_API_SECRET,
#   GO_ORACLE_BUILD_IF_MISSING, GO_ORACLE_LOG, GO_ORACLE_PID

GO_ORACLE_PID="${GO_ORACLE_PID:-}"

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

case_needs_external_go_oracle() {
  local case_id="$1"
  local case_file="labs/interop-lab/cases/${case_id}.yaml"
  if [[ ! -f "${case_file}" ]]; then
    return 1
  fi
  python3 - "${case_file}" <<'PY'
import sys
import yaml

with open(sys.argv[1], "r", encoding="utf-8") as f:
    case = yaml.safe_load(f)

go_spec = ((case or {}).get("bootstrap") or {}).get("go") or {}
command = go_spec.get("command")
raise SystemExit(0 if not command else 1)
PY
}
