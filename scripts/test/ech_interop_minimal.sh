#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUT_JSON="${ROOT_DIR}/reports/security/ech_interop_minimal.json"
OUT_LOG_DIR="${ROOT_DIR}/reports/security/ech_interop_minimal_logs"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/l20-ech-interop-XXXXXX")"

cleanup() {
  rm -rf "${TMP_DIR}"
}
trap cleanup EXIT

mkdir -p "${OUT_LOG_DIR}" "$(dirname "${OUT_JSON}")"

BIN="${ROOT_DIR}/target/debug/app"
BUILD_LOG="${OUT_LOG_DIR}/build.log"

echo "[ech-interop] building app(check) with schema-v2 ..."
cargo build -p app --features schema-v2 --bin app >"${BUILD_LOG}" 2>&1

if [[ ! -x "${BIN}" ]]; then
  echo "[ech-interop] build failed: missing ${BIN}" >&2
  exit 2
fi

RESULTS_JSONL="${TMP_DIR}/results.jsonl"
: >"${RESULTS_JSONL}"

run_case() {
  local case_id="$1"
  local mode="$2"
  local expected="$3"
  local cfg_path="$4"

  local stdout_path="${OUT_LOG_DIR}/${case_id}.stdout.json"
  local stderr_path="${OUT_LOG_DIR}/${case_id}.stderr.log"

  set +e
  "${BIN}" check -c "${cfg_path}" --schema-v2-validate --format json >"${stdout_path}" 2>"${stderr_path}"
  local rc=$?
  set -e

  local parse_ok="true"
  if ! jq -e . "${stdout_path}" >/dev/null 2>&1; then
    parse_ok="false"
  fi

  local error_count warning_count status matched
  if [[ "${parse_ok}" == "true" ]]; then
    error_count="$(jq -r '.summary.errors // 0' "${stdout_path}")"
    warning_count="$(jq -r '.summary.warnings // 0' "${stdout_path}")"
  else
    error_count="-1"
    warning_count="-1"
  fi

  status="fail"
  matched="false"
  if [[ "${parse_ok}" == "true" ]]; then
    case "${expected}" in
      pass_no_error)
        if [[ "${error_count}" == "0" ]]; then
          status="pass"
          matched="true"
        fi
        ;;
      fail_with_error)
        if [[ "${error_count}" -gt 0 ]]; then
          status="pass"
          matched="true"
        fi
        ;;
      *)
        status="fail"
        matched="false"
        ;;
    esac
  fi

  jq -c -n \
    --arg case_id "${case_id}" \
    --arg mode "${mode}" \
    --arg expected "${expected}" \
    --arg matched "${matched}" \
    --arg status "${status}" \
    --argjson parse_ok "${parse_ok}" \
    --argjson rc "${rc}" \
    --argjson error_count "${error_count}" \
    --argjson warning_count "${warning_count}" \
    --arg stdout_path "${stdout_path}" \
    --arg stderr_path "${stderr_path}" \
    '{
      case_id: $case_id,
      mode: $mode,
      expected: $expected,
      expectation_met: ($matched == "true"),
      status: $status,
      parse_ok: $parse_ok,
      rc: $rc,
      error_count: $error_count,
      warning_count: $warning_count,
      stdout_path: $stdout_path,
      stderr_path: $stderr_path
    }' >>"${RESULTS_JSONL}"
}

cat >"${TMP_DIR}/tcp_ech_pass.json" <<'JSON'
{
  "schema_version": 2,
  "outbounds": [
    {
      "type": "trojan",
      "name": "ech-tcp-pass",
      "server": "example.com",
      "port": 443,
      "password": "secret",
      "tls": {
        "enabled": true,
        "ech": { "enabled": true }
      }
    }
  ]
}
JSON

cat >"${TMP_DIR}/quic_ech_reject_fail.json" <<'JSON'
{
  "schema_version": 2,
  "outbounds": [
    {
      "type": "tuic",
      "name": "quic-ech-reject",
      "server": "example.com",
      "port": 443,
      "uuid": "00000000-0000-0000-0000-000000000000",
      "password": "secret",
      "tls": {
        "ech": { "enabled": true }
      }
    }
  ]
}
JSON

cat >"${TMP_DIR}/quic_ech_experimental_pass.json" <<'JSON'
{
  "schema_version": 2,
  "experimental": {
    "quic_ech_mode": "experimental"
  },
  "outbounds": [
    {
      "type": "tuic",
      "name": "quic-ech-experimental",
      "server": "example.com",
      "port": 443,
      "uuid": "00000000-0000-0000-0000-000000000000",
      "password": "secret",
      "tls": {
        "ech": { "enabled": true }
      }
    }
  ]
}
JSON

run_case "tcp_ech_pass" "tcp_ech" "pass_no_error" "${TMP_DIR}/tcp_ech_pass.json"
run_case "quic_ech_reject_fail" "quic_ech_reject" "fail_with_error" "${TMP_DIR}/quic_ech_reject_fail.json"
run_case "quic_ech_experimental_pass" "quic_ech_experimental" "pass_no_error" "${TMP_DIR}/quic_ech_experimental_pass.json"

python3 - "${RESULTS_JSONL}" "${OUT_JSON}" <<'PY'
import json
import sys
from datetime import datetime, timezone

results_path, out_path = sys.argv[1], sys.argv[2]
cases = []
with open(results_path, "r", encoding="utf-8") as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        cases.append(json.loads(line))

overall_pass = all(c.get("expectation_met") for c in cases)
payload = {
    "schema_version": "1.0.0",
    "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    "suite": "l20.ech_interop_minimal",
    "overall": "PASS" if overall_pass else "FAIL",
    "case_count": len(cases),
    "cases": cases,
}

with open(out_path, "w", encoding="utf-8") as f:
    json.dump(payload, f, ensure_ascii=False, indent=2)
    f.write("\n")
PY

echo "[ech-interop] wrote ${OUT_JSON}"
echo "[ech-interop] logs at ${OUT_LOG_DIR}"
