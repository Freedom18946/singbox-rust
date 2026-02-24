#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage:
  scripts/l18/run_dual_kernel_cert.sh [--profile daily|nightly] [--run-id ID] [--report-root DIR] [--artifacts-dir DIR] [--cases-dir DIR] [--go-api URL] [--go-token TOKEN]

Profiles:
  daily: both-kernel + priority P0/P1
  nightly: all both-kernel cases

Outputs:
  reports/l18/dual_kernel/<run_id>/summary.json
  reports/l18/dual_kernel/<run_id>/diff_gate.json
USAGE
}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"

PROFILE="${L18_PROFILE:-daily}"
RUN_ID="${L18_RUN_ID:-}"
REPORT_ROOT="${L18_DUAL_REPORT_ROOT:-${ROOT_DIR}/reports/l18/dual_kernel}"
ARTIFACTS_DIR="${L18_DUAL_ARTIFACTS_DIR:-${ROOT_DIR}/labs/interop-lab/artifacts/l18_dual_kernel}"
CASES_DIR="${L18_CASES_DIR:-${ROOT_DIR}/labs/interop-lab/cases}"
GO_API="${INTEROP_GO_API_BASE:-}"
GO_TOKEN="${INTEROP_GO_API_TOKEN:-}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --profile)
      PROFILE="$2"
      shift 2
      ;;
    --run-id)
      RUN_ID="$2"
      shift 2
      ;;
    --report-root)
      REPORT_ROOT="$2"
      shift 2
      ;;
    --artifacts-dir)
      ARTIFACTS_DIR="$2"
      shift 2
      ;;
    --cases-dir)
      CASES_DIR="$2"
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
  daily|nightly)
    ;;
  *)
    echo "--profile must be daily or nightly" >&2
    exit 2
    ;;
esac

if [[ -z "$RUN_ID" ]]; then
  RAND_SUFFIX="$(od -An -N4 -tx1 /dev/urandom | tr -d ' \n')"
  RUN_ID="$(date -u +'%Y%m%dT%H%M%SZ')-${PROFILE}-${RAND_SUFFIX}"
fi

if [[ ! -d "$CASES_DIR" ]]; then
  echo "cases dir not found: $CASES_DIR" >&2
  exit 1
fi

REPORT_DIR="${REPORT_ROOT}/${RUN_ID}"
SUMMARY_JSON="${REPORT_DIR}/summary.json"
DIFF_GATE_JSON="${REPORT_DIR}/diff_gate.json"

mkdir -p "$REPORT_DIR" "$ARTIFACTS_DIR"

SELECTED_FILE="$(mktemp)"
RESULTS_FILE="$(mktemp)"
cleanup() {
  rm -f "$SELECTED_FILE" "$RESULTS_FILE"
}
trap cleanup EXIT

case_list_output="$(cargo run -p interop-lab -- --cases-dir "$CASES_DIR" case list)"
if [[ -z "$case_list_output" ]]; then
  echo "empty case list output" >&2
  exit 1
fi

while IFS=$'\t' read -r case_id priority kernel_mode env_class _tags; do
  [[ -z "$case_id" ]] && continue
  if [[ "$kernel_mode" != "Both" ]]; then
    continue
  fi

  if [[ "$PROFILE" == "daily" ]]; then
    if [[ "$priority" != "P0" && "$priority" != "P1" ]]; then
      continue
    fi
  fi

  printf '%s\t%s\t%s\n' "$case_id" "$priority" "$env_class" >> "$SELECTED_FILE"
done <<< "$case_list_output"

selected_count="$(wc -l < "$SELECTED_FILE" | awk '{print $1+0}')"
if [[ "$selected_count" -eq 0 ]]; then
  echo "no both-kernel cases selected for profile=$PROFILE" >&2
  exit 1
fi

echo "[L18 dual-cert] profile=${PROFILE} run_id=${RUN_ID} selected_cases=${selected_count}"

extract_kv() {
  local key="$1"
  local blob="$2"
  printf '%s\n' "$blob" | sed -n "s/^${key}=//p" | tail -n1
}

run_fail_count=0
diff_fail_count=0

while IFS=$'\t' read -r case_id priority env_class; do
  [[ -z "$case_id" ]] && continue

  echo "[L18 dual-cert] run case=${case_id} priority=${priority} env=${env_class}"

  run_cmd=(
    cargo run -p interop-lab --
    --cases-dir "$CASES_DIR"
    --artifacts-dir "$ARTIFACTS_DIR"
    case run "$case_id"
    --kernel both
  )
  if [[ -n "$GO_API" ]]; then
    run_cmd+=(--go-api "$GO_API")
  fi
  if [[ -n "$GO_TOKEN" ]]; then
    run_cmd+=(--go-token "$GO_TOKEN")
  fi

  run_status="PASS"
  diff_status="SKIP"
  run_dir=""
  clean="false"
  http_mm="0"
  ws_mm="0"
  sub_mm="0"
  traffic_mm="0"
  ignored_http="0"
  ignored_ws="0"
  ignored_counter="0"
  gate_score="0"

  if run_output="$("${run_cmd[@]}" 2>&1)"; then
    run_dir="$(extract_kv run_dir "$run_output")"
    if [[ -z "$run_dir" ]]; then
      run_status="FAIL"
      run_fail_count=$((run_fail_count + 1))
    fi
  else
    run_status="FAIL"
    run_fail_count=$((run_fail_count + 1))
  fi

  if [[ "$run_status" == "PASS" ]]; then
    diff_cmd=(
      cargo run -p interop-lab --
      --cases-dir "$CASES_DIR"
      --artifacts-dir "$ARTIFACTS_DIR"
      case diff "$case_id"
    )

    if diff_output="$("${diff_cmd[@]}" 2>&1)"; then
      diff_status="PASS"
    else
      diff_status="FAIL"
      diff_fail_count=$((diff_fail_count + 1))
    fi

    clean="$(extract_kv clean "${diff_output:-}")"
    http_mm="$(extract_kv http_mismatches "${diff_output:-}")"
    ws_mm="$(extract_kv ws_mismatches "${diff_output:-}")"
    sub_mm="$(extract_kv subscription_mismatches "${diff_output:-}")"
    traffic_mm="$(extract_kv traffic_mismatches "${diff_output:-}")"
    ignored_http="$(extract_kv ignored_http "${diff_output:-}")"
    ignored_ws="$(extract_kv ignored_ws "${diff_output:-}")"
    ignored_counter="$(extract_kv ignored_counter_jitter "${diff_output:-}")"
    gate_score="$(extract_kv gate_score "${diff_output:-}")"

    clean="${clean:-false}"
    http_mm="${http_mm:-0}"
    ws_mm="${ws_mm:-0}"
    sub_mm="${sub_mm:-0}"
    traffic_mm="${traffic_mm:-0}"
    ignored_http="${ignored_http:-0}"
    ignored_ws="${ignored_ws:-0}"
    ignored_counter="${ignored_counter:-0}"
    gate_score="${gate_score:-0}"
  fi

  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$case_id" "$priority" "$env_class" "$run_status" "$diff_status" "$clean" \
    "$http_mm" "$ws_mm" "$sub_mm" "$traffic_mm" "$ignored_http" "$ignored_ws" \
    "$ignored_counter" "$gate_score" "$run_dir" >> "$RESULTS_FILE"
done < "$SELECTED_FILE"

export PROFILE RUN_ID ARTIFACTS_DIR GO_API REPORT_DIR SUMMARY_JSON DIFF_GATE_JSON SELECTED_FILE RESULTS_FILE
python3 - <<'PY'
import json
import os
from datetime import datetime, timezone

selected_file = os.environ["SELECTED_FILE"]
results_file = os.environ["RESULTS_FILE"]

selected = []
with open(selected_file, "r", encoding="utf-8") as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        case_id, priority, env_class = line.split("\t", 2)
        selected.append({
            "case_id": case_id,
            "priority": priority,
            "env_class": env_class,
        })

results = []
with open(results_file, "r", encoding="utf-8") as f:
    for line in f:
        line = line.rstrip("\n")
        if not line:
            continue
        (
            case_id,
            priority,
            env_class,
            run_status,
            diff_status,
            clean,
            http_mm,
            ws_mm,
            sub_mm,
            traffic_mm,
            ignored_http,
            ignored_ws,
            ignored_counter,
            gate_score,
            run_dir,
        ) = line.split("\t", 14)

        results.append({
            "case_id": case_id,
            "priority": priority,
            "env_class": env_class,
            "run_status": run_status,
            "diff_status": diff_status,
            "clean": clean.lower() == "true",
            "mismatches": {
                "http": int(http_mm),
                "ws": int(ws_mm),
                "subscription": int(sub_mm),
                "traffic": int(traffic_mm),
            },
            "ignored": {
                "http": int(ignored_http),
                "ws": int(ignored_ws),
                "counter_jitter": int(ignored_counter),
            },
            "gate_score": float(gate_score),
            "run_dir": run_dir,
        })

run_fail = sum(1 for r in results if r["run_status"] != "PASS")
diff_fail = sum(1 for r in results if r["run_status"] == "PASS" and r["diff_status"] != "PASS")
pass_flag = len(results) > 0 and run_fail == 0 and diff_fail == 0

summary = {
    "generated_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
    "profile": os.environ["PROFILE"],
    "run_id": os.environ["RUN_ID"],
    "artifacts_dir": os.path.abspath(os.environ["ARTIFACTS_DIR"]),
    "go_api": os.environ.get("GO_API", ""),
    "selected_case_count": len(selected),
    "results_count": len(results),
    "run_fail_count": run_fail,
    "diff_fail_count": diff_fail,
    "pass": pass_flag,
    "selected": selected,
    "results": results,
}

diff_gate = {
    "generated_at": summary["generated_at"],
    "profile": summary["profile"],
    "run_id": summary["run_id"],
    "selected_case_count": summary["selected_case_count"],
    "run_fail_count": run_fail,
    "diff_fail_count": diff_fail,
    "criteria": {
        "required": {
            "run_fail_count": 0,
            "diff_fail_count": 0,
        }
    },
    "pass": pass_flag,
}

os.makedirs(os.environ["REPORT_DIR"], exist_ok=True)
with open(os.environ["SUMMARY_JSON"], "w", encoding="utf-8") as f:
    json.dump(summary, f, indent=2, ensure_ascii=False)
with open(os.environ["DIFF_GATE_JSON"], "w", encoding="utf-8") as f:
    json.dump(diff_gate, f, indent=2, ensure_ascii=False)

print(f"summary written: {os.environ['SUMMARY_JSON']}")
print(f"diff gate written: {os.environ['DIFF_GATE_JSON']}")
PY

echo "[L18 dual-cert] summary=${SUMMARY_JSON}"
echo "[L18 dual-cert] diff_gate=${DIFF_GATE_JSON}"

if [[ "$run_fail_count" -ne 0 || "$diff_fail_count" -ne 0 ]]; then
  echo "[L18 dual-cert] FAIL run_fail=${run_fail_count} diff_fail=${diff_fail_count}" >&2
  exit 1
fi

echo "[L18 dual-cert] PASS"
