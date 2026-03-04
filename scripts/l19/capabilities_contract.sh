#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage:
  scripts/l19/capabilities_contract.sh [--out-json PATH] [--out-log PATH]

Runs the L19 GUI contract suite:
  cargo test -p sb-api capabilities_contract_suite -- --nocapture
USAGE
}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"

OUT_JSON="${ROOT_DIR}/reports/l19/contracts/capabilities_contract.json"
OUT_LOG="${ROOT_DIR}/reports/l19/contracts/capabilities_contract.log"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --out-json)
      OUT_JSON="$2"
      shift 2
      ;;
    --out-log)
      OUT_LOG="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

mkdir -p "$(dirname "$OUT_JSON")" "$(dirname "$OUT_LOG")"

cmd=(cargo test -p sb-api capabilities_contract_suite -- --nocapture)
set +e
"${cmd[@]}" >"$OUT_LOG" 2>&1
rc=$?
set -e

status="PASS"
if [[ "$rc" -ne 0 ]]; then
  status="FAIL"
fi

python3 - "$OUT_JSON" "$OUT_LOG" "$status" "$rc" <<'PY'
import json
import sys
from datetime import datetime, timezone

out_json, out_log, status, rc = sys.argv[1:]
payload = {
    "schema_version": "1.0.0",
    "generated_at": datetime.now(timezone.utc).isoformat(),
    "suite": "sb-api.capabilities_contract_suite",
    "status": status,
    "exit_code": int(rc),
    "command": "cargo test -p sb-api capabilities_contract_suite -- --nocapture",
    "log_file": out_log,
}
with open(out_json, "w", encoding="utf-8") as f:
    json.dump(payload, f, indent=2, ensure_ascii=False)
    f.write("\n")
PY

echo "[l19-contract] status=${status} report=${OUT_JSON} log=${OUT_LOG}"
exit "$rc"
