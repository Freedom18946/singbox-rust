#!/usr/bin/env bash
set -euo pipefail

ROOT_ARTIFACTS_DIR="${ARTIFACTS_DIR:-labs/interop-lab/artifacts}"
STRICT_ARTIFACTS_DIR="${STRICT_ARTIFACTS_DIR:-${ROOT_ARTIFACTS_DIR}/strict_dual_kernel}"
ENV_ARTIFACTS_DIR="${ENV_ARTIFACTS_DIR:-${ROOT_ARTIFACTS_DIR}/env_limited_dual_kernel}"
INTEROP_SKIP_APP_BUILD="${INTEROP_SKIP_APP_BUILD:-0}"

if [[ "${INTEROP_SKIP_APP_BUILD}" != "1" ]]; then
  echo "prebuild: cargo build -p app --features acceptance --bin app"
  cargo build -p app --features acceptance --bin app >/dev/null
fi

echo "dual-kernel replay: strict_artifacts=${STRICT_ARTIFACTS_DIR} env_artifacts=${ENV_ARTIFACTS_DIR}"

case_list_output="$(cargo run -p interop-lab -- case list)"

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

if [[ ${#strict_cases[@]} -gt 0 ]]; then
  echo "running strict dual-kernel cases..."
  for case_id in "${strict_cases[@]}"; do
    echo "  run case=${case_id} artifacts=${STRICT_ARTIFACTS_DIR}"
    cargo run -p interop-lab -- --artifacts-dir "${STRICT_ARTIFACTS_DIR}" case run "${case_id}" --kernel both --env-class strict
  done
else
  echo "skip strict run: no both-kernel strict cases"
fi

if [[ ${#env_cases[@]} -gt 0 ]]; then
  echo "running env-limited dual-kernel cases..."
  for case_id in "${env_cases[@]}"; do
    echo "  run case=${case_id} artifacts=${ENV_ARTIFACTS_DIR}"
    cargo run -p interop-lab -- --artifacts-dir "${ENV_ARTIFACTS_DIR}" case run "${case_id}" --kernel both --env-class env-limited
  done
else
  echo "skip env-limited run: no both-kernel env-limited cases"
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
if [[ ${fail_count} -gt 0 ]]; then
  exit 1
fi
