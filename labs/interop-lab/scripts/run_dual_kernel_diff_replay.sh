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

# shellcheck source=lib_go_oracle.sh
source "$(dirname "$0")/lib_go_oracle.sh"

EXIT_DIFF_FAIL=1
EXIT_USAGE=2
EXIT_NO_CASES=3
EXIT_ARTIFACT_INCOMPLETE=4

if [[ "${INTEROP_SKIP_APP_BUILD}" != "1" ]]; then
  echo "prebuild: cargo build -p app --features acceptance,clash_api --bin app"
  cargo build -p app --features acceptance,clash_api --bin app >/dev/null
fi

cleanup() {
  stop_managed_go_oracle
}
trap cleanup EXIT

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
