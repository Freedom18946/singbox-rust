#!/bin/bash
# Static fixture suite for gui_real_cert capability negotiation gate.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
EVAL_SCRIPT="${ROOT_DIR}/scripts/l18/capability_negotiation_eval.py"
FIXTURE_DIR="${ROOT_DIR}/scripts/l18/fixtures/capability_negotiation"
OUT_DIR="${1:-${ROOT_DIR}/reports/l21/artifacts/gui_capability_negotiation}"
mkdir -p "$OUT_DIR"

run_case() {
  local name="$1"
  local fixture="$2"
  local required="$3"
  local expect_exit="$4"
  local expect_status="$5"
  local expect_reason_prefix="$6"

  local out_json="${OUT_DIR}/${name}.result.json"
  local full_fixture="${FIXTURE_DIR}/${fixture}"

  set +e
  python3 "$EVAL_SCRIPT" \
    --core "rust" \
    --api-url "http://127.0.0.1:19090" \
    --token "" \
    --required "$required" \
    --timeout-sec 3 \
    --payload-file "$full_fixture" \
    --out-json "$out_json"
  local code=$?
  set -e

  if [[ "$code" -ne "$expect_exit" ]]; then
    echo "[fixture-check] FAIL ${name}: exit=${code}, expect=${expect_exit}" >&2
    return 1
  fi

  local status reason
  status="$(jq -r '.status // ""' "$out_json")"
  reason="$(jq -r '.reason // ""' "$out_json")"
  if [[ "$status" != "$expect_status" ]]; then
    echo "[fixture-check] FAIL ${name}: status='${status}', expect='${expect_status}'" >&2
    return 1
  fi
  if [[ -n "$expect_reason_prefix" && "$reason" != "$expect_reason_prefix"* ]]; then
    echo "[fixture-check] FAIL ${name}: reason='${reason}', expect-prefix='${expect_reason_prefix}'" >&2
    return 1
  fi

  echo "[fixture-check] PASS ${name} (exit=${code}, status=${status}, reason=${reason})"
}

run_case "required_status_blocked" "case_required_status_blocked.json" "1" "1" "blocked" "required_status_not_ok:"
run_case "breaking_changes_non_empty" "case_breaking_changes_non_empty.json" "1" "1" "blocked" "breaking_changes_non_empty:"
run_case "baseline_ok" "case_ok.json" "1" "0" "ok" ""

echo "[fixture-check] all cases passed; artifacts at ${OUT_DIR}"
