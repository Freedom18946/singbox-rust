#!/usr/bin/env bash
set -euo pipefail

ROOT_ARTIFACTS_DIR="${ARTIFACTS_DIR:-labs/interop-lab/artifacts}"
STRICT_ARTIFACTS_DIR="${STRICT_ARTIFACTS_DIR:-${ROOT_ARTIFACTS_DIR}/strict_dual_kernel}"
ENV_ARTIFACTS_DIR="${ENV_ARTIFACTS_DIR:-${ROOT_ARTIFACTS_DIR}/env_limited_dual_kernel}"
INTEROP_SKIP_APP_BUILD="${INTEROP_SKIP_APP_BUILD:-0}"
MANAGE_GO_ORACLE="${MANAGE_GO_ORACLE:-0}"
GO_ORACLE_BIN="${GO_ORACLE_BIN:-go_fork_source/sing-box-1.12.14/sing-box}"
GO_ORACLE_CONFIG="${GO_ORACLE_CONFIG:-labs/interop-lab/configs/l18_gui_go.json}"
GO_ORACLE_API_URL="${GO_ORACLE_API_URL:-http://127.0.0.1:9090}"
GO_ORACLE_API_SECRET="${GO_ORACLE_API_SECRET:-test-secret}"
GO_ORACLE_BUILD_IF_MISSING="${GO_ORACLE_BUILD_IF_MISSING:-1}"
GO_ORACLE_LOG="${GO_ORACLE_LOG:-/tmp/interop-go-oracle-diff-replay.log}"
GO_ORACLE_PID=""

EXIT_DIFF_FAIL=1
EXIT_USAGE=2
EXIT_NO_CASES=3
EXIT_ARTIFACT_INCOMPLETE=4

if [[ "${INTEROP_SKIP_APP_BUILD}" != "1" ]]; then
  echo "prebuild: cargo build -p app --features acceptance,clash_api --bin app"
  cargo build -p app --features acceptance,clash_api --bin app >/dev/null
fi

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

echo "dual-kernel replay: strict_artifacts=${STRICT_ARTIFACTS_DIR} env_artifacts=${ENV_ARTIFACTS_DIR}"

case_list_output="$(cargo run -p interop-lab -- case list)"
if [[ -z "${case_list_output}" ]]; then
  echo "error: empty case list output"
  exit "${EXIT_NO_CASES}"
fi

strict_cases=()
env_cases=()
while IFS=$'\t' read -r case_id _priority kernel_mode env_class _tags; do
  [[ -z "${case_id}" ]] && continue
  if [[ "${kernel_mode}" != "Both" ]]; then
    continue
  fi

  env_lc="$(printf '%s' "${env_class}" | tr '[:upper:]' '[:lower:]')"
  if [[ "${env_lc}" == "envlimited" ]]; then
    env_lc="env_limited"
  fi

  if [[ "${env_lc}" == "strict" ]]; then
    strict_cases+=("${case_id}")
  elif [[ "${env_lc}" == "env_limited" ]]; then
    env_cases+=("${case_id}")
  fi
done <<< "${case_list_output}"

echo "detected both-kernel cases: strict=${#strict_cases[@]} env_limited=${#env_cases[@]}"

if [[ ${#strict_cases[@]} -eq 0 && ${#env_cases[@]} -eq 0 ]]; then
  echo "error: no kernel_mode=both cases found in case list"
  exit "${EXIT_NO_CASES}"
fi

mkdir -p "${STRICT_ARTIFACTS_DIR}" "${ENV_ARTIFACTS_DIR}"

run_fail_count=0
artifacts_fail_count=0

if [[ ${#strict_cases[@]} -gt 0 ]]; then
  echo "running strict dual-kernel cases..."
  for case_id in "${strict_cases[@]}"; do
    echo "  run case=${case_id} artifacts=${STRICT_ARTIFACTS_DIR}"
    stop_managed_go_oracle
    if [[ "${MANAGE_GO_ORACLE}" == "1" ]] && case_needs_external_go_oracle "${case_id}"; then
      start_managed_go_oracle
    fi
    run_output="$(cargo run -p interop-lab -- --artifacts-dir "${STRICT_ARTIFACTS_DIR}" case run "${case_id}" --kernel both --env-class strict)"
    echo "${run_output}"

    run_dir="$(printf '%s\n' "${run_output}" | sed -n 's/^run_dir=//p' | tail -n1)"
    if [[ -z "${run_dir}" || ! -d "${run_dir}" ]]; then
      echo "error: strict case=${case_id} missing run_dir in output"
      run_fail_count=$((run_fail_count + 1))
      continue
    fi

    if [[ ! -f "${run_dir}/rust.snapshot.json" || ! -f "${run_dir}/go.snapshot.json" ]]; then
      echo "error: strict case=${case_id} incomplete artifacts under ${run_dir}"
      artifacts_fail_count=$((artifacts_fail_count + 1))
    fi
  done
else
  echo "skip strict run: no both-kernel strict cases"
fi

if [[ ${#env_cases[@]} -gt 0 ]]; then
  echo "running env-limited dual-kernel cases..."
  for case_id in "${env_cases[@]}"; do
    echo "  run case=${case_id} artifacts=${ENV_ARTIFACTS_DIR}"
    stop_managed_go_oracle
    if [[ "${MANAGE_GO_ORACLE}" == "1" ]] && case_needs_external_go_oracle "${case_id}"; then
      start_managed_go_oracle
    fi
    run_output="$(cargo run -p interop-lab -- --artifacts-dir "${ENV_ARTIFACTS_DIR}" case run "${case_id}" --kernel both --env-class env-limited)"
    echo "${run_output}"

    run_dir="$(printf '%s\n' "${run_output}" | sed -n 's/^run_dir=//p' | tail -n1)"
    if [[ -z "${run_dir}" || ! -d "${run_dir}" ]]; then
      echo "error: env-limited case=${case_id} missing run_dir in output"
      run_fail_count=$((run_fail_count + 1))
      continue
    fi

    if [[ ! -f "${run_dir}/rust.snapshot.json" || ! -f "${run_dir}/go.snapshot.json" ]]; then
      echo "error: env-limited case=${case_id} incomplete artifacts under ${run_dir}"
      artifacts_fail_count=$((artifacts_fail_count + 1))
    fi
  done
else
  echo "skip env-limited run: no both-kernel env-limited cases"
fi

if [[ ${run_fail_count} -gt 0 ]]; then
  echo "error: run replay failed for ${run_fail_count} case(s)"
  echo "summary_pass=0"
  echo "summary_fail=0"
  echo "summary_run_fail=${run_fail_count}"
  echo "summary_artifact_fail=${artifacts_fail_count}"
  exit "${EXIT_USAGE}"
fi

if [[ ${artifacts_fail_count} -gt 0 ]]; then
  echo "error: artifact integrity check failed for ${artifacts_fail_count} case(s)"
  echo "summary_pass=0"
  echo "summary_fail=0"
  echo "summary_run_fail=${run_fail_count}"
  echo "summary_artifact_fail=${artifacts_fail_count}"
  exit "${EXIT_ARTIFACT_INCOMPLETE}"
fi

pass_count=0
fail_count=0

echo "diff replay for strict cases..."
for case_id in "${strict_cases[@]}"; do
  echo "  diff case=${case_id} artifacts=${STRICT_ARTIFACTS_DIR}"
  if cargo run -p interop-lab -- --artifacts-dir "${STRICT_ARTIFACTS_DIR}" case diff "${case_id}"; then
    pass_count=$((pass_count + 1))
  else
    fail_count=$((fail_count + 1))
  fi
done

echo "diff replay for env-limited cases..."
for case_id in "${env_cases[@]}"; do
  echo "  diff case=${case_id} artifacts=${ENV_ARTIFACTS_DIR}"
  if cargo run -p interop-lab -- --artifacts-dir "${ENV_ARTIFACTS_DIR}" case diff "${case_id}"; then
    pass_count=$((pass_count + 1))
  else
    fail_count=$((fail_count + 1))
  fi
done

echo "dual-kernel diff replay summary: pass=${pass_count} fail=${fail_count}"
echo "summary_pass=${pass_count}"
echo "summary_fail=${fail_count}"
echo "summary_run_fail=${run_fail_count}"
echo "summary_artifact_fail=${artifacts_fail_count}"

if [[ ${fail_count} -gt 0 ]]; then
  exit "${EXIT_DIFF_FAIL}"
fi
