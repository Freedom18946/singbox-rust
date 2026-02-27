#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage:
  scripts/l18/run_stress_short_48x.sh \
    --gui-app <abs_path_to_gui_app> \
    [--duration-min 30] \
    [--batch-root DIR] \
    [--run-name NAME] \
    [--require-docker 0|1] \
    [--allow-existing-system-proxy 0|1] \
    [--allow-real-proxy-coexist 0|1]

Goal:
  - Short high-pressure rehearsal in ~30 minutes
  - Broad protocol/data-flow coverage via interop-lab full rust case set
  - Compound stress target = 48x (4 ws streams * 4 P2 rounds * 3x perf sampling)

Notes:
  - This is a stress rehearsal and does not replace L18 nightly 24h / certify 7d evidence.
USAGE
}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
cd "${ROOT_DIR}"

DURATION_MIN=30
GUI_APP=""
BATCH_ROOT=""
RUN_NAME="stress_short_48x"
REQUIRE_DOCKER=0
ALLOW_EXISTING_SYSTEM_PROXY=1
ALLOW_REAL_PROXY_COEXIST=1

while [[ $# -gt 0 ]]; do
  case "$1" in
    --duration-min)
      DURATION_MIN="$2"
      shift 2
      ;;
    --gui-app)
      GUI_APP="$2"
      shift 2
      ;;
    --batch-root)
      BATCH_ROOT="$2"
      shift 2
      ;;
    --run-name)
      RUN_NAME="$2"
      shift 2
      ;;
    --require-docker)
      REQUIRE_DOCKER="$2"
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
if ! [[ "$DURATION_MIN" =~ ^[1-9][0-9]*$ ]]; then
  echo "--duration-min must be positive integer" >&2
  exit 2
fi
if [[ "$REQUIRE_DOCKER" != "0" && "$REQUIRE_DOCKER" != "1" ]]; then
  echo "--require-docker must be 0 or 1" >&2
  exit 2
fi
if [[ "$ALLOW_EXISTING_SYSTEM_PROXY" != "0" && "$ALLOW_EXISTING_SYSTEM_PROXY" != "1" ]]; then
  echo "--allow-existing-system-proxy must be 0 or 1" >&2
  exit 2
fi
if [[ "$ALLOW_REAL_PROXY_COEXIST" != "0" && "$ALLOW_REAL_PROXY_COEXIST" != "1" ]]; then
  echo "--allow-real-proxy-coexist must be 0 or 1" >&2
  exit 2
fi

if [[ -z "$BATCH_ROOT" ]]; then
  BATCH_ROOT="${ROOT_DIR}/reports/l18/batches/$(date -u +'%Y%m%dT%H%M%SZ')-l18-stress-48x"
fi
if [[ "$BATCH_ROOT" != /* ]]; then
  BATCH_ROOT="${ROOT_DIR}/${BATCH_ROOT}"
fi

RUN_ROOT="${BATCH_ROOT}/${RUN_NAME}"
RUN_DIR="${RUN_ROOT}/r1"
mkdir -p "$RUN_DIR"
printf '%s\n' "$BATCH_ROOT" > "${BATCH_ROOT}/BATCH_ROOT.txt"

CANARY_RUNTIME_DIR="${RUN_ROOT}/canary_runtime"
CANARY_CFG="${CANARY_RUNTIME_DIR}/canary_rust_29090_nosecret.json"
CANARY_PID_FILE="${CANARY_RUNTIME_DIR}/canary.pid"
CANARY_LOG="${CANARY_RUNTIME_DIR}/canary.log"
CANARY_JSONL="${RUN_DIR}/canary/canary_stress_30m.jsonl"
CANARY_SUMMARY="${RUN_DIR}/canary/canary_stress_30m.md"
CANARY_API_URL="http://127.0.0.1:29090"
CANARY_API_SECRET="l18-stress-secret"
CANARY_AUTH_HEADER="Authorization: Bearer ${CANARY_API_SECRET}"
CANARY_INTERVAL_SEC=15

GUI_DIR="${RUN_DIR}/gui"
INTEROP_ARTIFACTS="${RUN_DIR}/interop_artifacts"
CASES_SHORT_DIR="${RUN_DIR}/cases_short"
DUAL_REPORT_ROOT="${RUN_DIR}/dual_kernel"
DUAL_ARTIFACTS_DIR="${RUN_DIR}/dual_kernel_artifacts"
PERF_DIR="${RUN_DIR}/perf"
PERF_REPORT="${PERF_DIR}/perf_gate.json"
PERF_LOCK="${PERF_DIR}/perf_gate.lock.json"
GUI_REPORT_JSON_SRC="${ROOT_DIR}/reports/l18/gui_real_cert.json"
GUI_REPORT_MD_SRC="${ROOT_DIR}/reports/l18/gui_real_cert.md"
GUI_REPORT_JSON_DST="${GUI_DIR}/gui_real_cert.json"
GUI_REPORT_MD_DST="${GUI_DIR}/gui_real_cert.md"

STATUS_FILE="${RUN_DIR}/stress_status.json"
SUMMARY_TSV="${RUN_ROOT}/summary.tsv"
CONFIG_FREEZE_JSON="${RUN_ROOT}/config.freeze.json"
PRECHECK_TXT="${RUN_ROOT}/precheck.txt"
MAIN_LOG="${RUN_DIR}/stress.main.log"

mkdir -p "${CANARY_RUNTIME_DIR}" "${RUN_DIR}/canary" "${GUI_DIR}" "${INTEROP_ARTIFACTS}" "${DUAL_REPORT_ROOT}" "${DUAL_ARTIFACTS_DIR}" "${PERF_DIR}" "${CASES_SHORT_DIR}"

RUST_BIN="${ROOT_DIR}/target/release/run"
RUST_APP_BIN="${ROOT_DIR}/target/release/app"
GO_BIN="${ROOT_DIR}/go_fork_source/sing-box-1.12.14/sing-box"
P2_ROUNDS_TOTAL=4
WS_PARALLEL_FACTOR=4
PERF_SAMPLE_FACTOR=3
COMPOSITE_PRESSURE=$((P2_ROUNDS_TOTAL * WS_PARALLEL_FACTOR * PERF_SAMPLE_FACTOR))

START_EPOCH="$(date +%s)"
DEADLINE_EPOCH=$((START_EPOCH + DURATION_MIN * 60))

declare -A STAGE_STATUS
declare -A STAGE_RC
STAGE_ORDER=()
HAS_FAIL=0

log() {
  printf '[%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*" | tee -a "$MAIN_LOG"
}

remaining_sec() {
  local now
  now="$(date +%s)"
  local left=$((DEADLINE_EPOCH - now))
  if (( left < 0 )); then
    left=0
  fi
  printf '%s\n' "$left"
}

check_port_free() {
  local port="$1"
  if lsof -nP -iTCP:"${port}" -sTCP:LISTEN >/dev/null 2>&1; then
    return 1
  fi
  return 0
}

run_stage() {
  local key="$1"
  shift
  local out_log="${RUN_DIR}/stages/${key}.stdout.log"
  local err_log="${RUN_DIR}/stages/${key}.stderr.log"
  mkdir -p "${RUN_DIR}/stages"
  STAGE_ORDER+=("$key")

  local left
  left="$(remaining_sec)"
  if (( left < 30 )); then
    log "stage=${key} skipped: budget exhausted (remaining=${left}s)"
    STAGE_STATUS["$key"]="TIMEOUT"
    STAGE_RC["$key"]="124"
    HAS_FAIL=1
    return 124
  fi

  log "stage=${key} start remaining=${left}s cmd=$*"
  if python3 - "$left" "$@" >"$out_log" 2>"$err_log" <<'PY'
import subprocess
import sys

timeout_sec = int(sys.argv[1])
cmd = sys.argv[2:]
try:
    res = subprocess.run(cmd, timeout=timeout_sec)
except subprocess.TimeoutExpired:
    sys.exit(124)
sys.exit(res.returncode)
PY
  then
    STAGE_STATUS["$key"]="PASS"
    STAGE_RC["$key"]="0"
    log "stage=${key} PASS"
    return 0
  else
    local rc=$?
    STAGE_STATUS["$key"]="FAIL"
    STAGE_RC["$key"]="$rc"
    HAS_FAIL=1
    log "stage=${key} FAIL rc=${rc}"
    return "$rc"
  fi
}

CANARY_SAMPLER_PID=""
stop_canary_runtime() {
  if [[ -f "${CANARY_PID_FILE}" ]]; then
    local cpid
    cpid="$(cat "${CANARY_PID_FILE}" 2>/dev/null || true)"
    if [[ -n "${cpid:-}" ]] && kill -0 "$cpid" 2>/dev/null; then
      kill "$cpid" 2>/dev/null || true
      sleep 0.5
      kill -0 "$cpid" 2>/dev/null && kill -9 "$cpid" 2>/dev/null || true
    fi
  fi
}

stop_canary_sampler() {
  if [[ -n "${CANARY_SAMPLER_PID}" ]] && kill -0 "${CANARY_SAMPLER_PID}" 2>/dev/null; then
    kill "${CANARY_SAMPLER_PID}" 2>/dev/null || true
    wait "${CANARY_SAMPLER_PID}" >/dev/null 2>&1 || true
  fi
}

finalize_canary_summary() {
  python3 - "$CANARY_JSONL" "$CANARY_SUMMARY" <<'PY'
import json
import sys
from pathlib import Path
from datetime import datetime, timezone

jsonl = Path(sys.argv[1])
summary = Path(sys.argv[2])
rows = []
if jsonl.exists():
    for line in jsonl.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        rows.append(json.loads(line))

sample_count = len(rows)
health_ok = sum(1 for r in rows if int(r.get("health_code", 0)) == 200)
rss_values = [int(r["rss_kb"]) for r in rows if r.get("rss_kb") not in (None, "null")]
fd_values = [int(r["fd_count"]) for r in rows if r.get("fd_count") not in (None, "null")]

first_ts = rows[0]["ts"] if rows else "null"
last_ts = rows[-1]["ts"] if rows else "null"
max_rss = max(rss_values) if rss_values else "null"
max_fd = max(fd_values) if fd_values else "null"

ok = sample_count > 0 and health_ok == sample_count and len(rss_values) == sample_count

summary.parent.mkdir(parents=True, exist_ok=True)
summary.write_text(
    "\n".join(
        [
            "# Canary Stress Summary",
            "",
            f"- generated_at: {datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}",
            f"- sample_count: {sample_count}",
            f"- health_200_count: {health_ok}",
            f"- first_ts: {first_ts}",
            f"- last_ts: {last_ts}",
            f"- max_rss_kb: {max_rss}",
            f"- max_fd_count: {max_fd}",
            f"- pass: {str(ok).lower()}",
            "",
            f"- jsonl: `{jsonl}`",
        ]
    )
    + "\n",
    encoding="utf-8",
)

print(f"sample_count={sample_count}")
print(f"health_200_count={health_ok}")
print(f"pass={str(ok).lower()}")
PY
}

cleanup() {
  stop_canary_sampler
  stop_canary_runtime
}
trap cleanup EXIT

for p in 9090 19090 11810 11811 29090 12810; do
  if ! check_port_free "$p"; then
    echo "port busy: $p" >&2
    lsof -nP -iTCP:"$p" -sTCP:LISTEN >&2 || true
    exit 1
  fi
done

{
  echo "generated_at=$(date -u +'%Y-%m-%dT%H:%M:%SZ')"
  echo "duration_min=${DURATION_MIN}"
  echo "gui_app=${GUI_APP}"
  echo "require_docker=${REQUIRE_DOCKER}"
  echo "allow_existing_system_proxy=${ALLOW_EXISTING_SYSTEM_PROXY}"
  echo "allow_real_proxy_coexist=${ALLOW_REAL_PROXY_COEXIST}"
  echo "pressure.ws_parallel_factor=${WS_PARALLEL_FACTOR}"
  echo "pressure.p2_rounds_total=${P2_ROUNDS_TOTAL}"
  echo "pressure.perf_sample_factor=${PERF_SAMPLE_FACTOR}"
  echo "pressure.composite=${COMPOSITE_PRESSURE}"
  echo "canary.interval_sec=${CANARY_INTERVAL_SEC}"
  echo "check.port.9090=$(check_port_free 9090 && echo free || echo busy)"
  echo "check.port.19090=$(check_port_free 19090 && echo free || echo busy)"
  echo "check.port.11810=$(check_port_free 11810 && echo free || echo busy)"
  echo "check.port.11811=$(check_port_free 11811 && echo free || echo busy)"
  echo "check.port.29090=$(check_port_free 29090 && echo free || echo busy)"
  echo "check.port.12810=$(check_port_free 12810 && echo free || echo busy)"
} > "${PRECHECK_TXT}"

cat > "${CANARY_CFG}" <<JSON
{
  "log": {"level": "warn"},
  "experimental": {
    "clash_api": {
      "external_controller": "127.0.0.1:29090",
      "secret": "${CANARY_API_SECRET}"
    }
  },
  "inbounds": [
    {
      "type": "socks",
      "name": "socks-in",
      "listen": "127.0.0.1",
      "port": 12810
    }
  ],
  "outbounds": [
    {
      "type": "selector",
      "name": "my-group",
      "outbounds": ["direct", "alt-direct"],
      "default": "direct"
    },
    {"type": "direct", "name": "direct"},
    {"type": "direct", "name": "alt-direct"}
  ],
  "route": {"rules": [], "final": "my-group"}
}
JSON

log "building rust parity runtime"
cargo build --release -p app --features parity --bin run --bin app >/dev/null
if [[ ! -x "${RUST_BIN}" ]]; then
  echo "rust binary not executable: ${RUST_BIN}" >&2
  exit 1
fi
if [[ ! -x "${RUST_APP_BIN}" ]]; then
  echo "rust app binary not executable: ${RUST_APP_BIN}" >&2
  exit 1
fi

log "starting dedicated canary runtime on 127.0.0.1:29090"
"${RUST_BIN}" --config "${CANARY_CFG}" > "${CANARY_LOG}" 2>&1 &
CANARY_PID="$!"
echo "${CANARY_PID}" > "${CANARY_PID_FILE}"

ready=0
for _ in $(seq 1 120); do
  code="$(curl -s -o /dev/null -w '%{http_code}' -H "${CANARY_AUTH_HEADER}" "${CANARY_API_URL}/services/health" || true)"
  if [[ "$code" == "200" ]]; then
    ready=1
    break
  fi
  sleep 0.25
done
if [[ "$ready" != "1" ]]; then
  echo "canary runtime health check failed: ${CANARY_API_URL}" >&2
  exit 1
fi

export INTEROP_RUST_API_BASE="${CANARY_API_URL}"
export INTEROP_RUST_API_SECRET="${CANARY_API_SECRET}"
export INTEROP_RUST_API_SECRET_WRONG="l18-stress-secret-wrong"
export INTEROP_RUST_BIN="${RUST_APP_BIN}"

log "preparing short-soak case set"
rm -rf "${CASES_SHORT_DIR}"
mkdir -p "${CASES_SHORT_DIR}"
while IFS= read -r -d '' case_file; do
  ln -s "${case_file}" "${CASES_SHORT_DIR}/$(basename "${case_file}")"
done < <(find "${ROOT_DIR}/labs/interop-lab/cases" -maxdepth 1 -name '*.yaml' -print0)

for soak_file in p2_connections_ws_soak_suite.yaml p2_connections_ws_soak_dual_core.yaml; do
  rm -f "${CASES_SHORT_DIR}/${soak_file}"
  cp "${ROOT_DIR}/labs/interop-lab/cases/${soak_file}" "${CASES_SHORT_DIR}/${soak_file}"
done

python3 - "${CASES_SHORT_DIR}" <<'PY'
from pathlib import Path
import re
import sys

cases_dir = Path(sys.argv[1])
targets = [
    cases_dir / "p2_connections_ws_soak_suite.yaml",
    cases_dir / "p2_connections_ws_soak_dual_core.yaml",
]
for path in targets:
    text = path.read_text(encoding="utf-8")
    text = re.sub(r'(SB_WS_SOAK_WAVES:\s*")20(")', r'\g<1>6\2', text)
    text = re.sub(r'(SB_WS_SOAK_WAVE_DELAY_MS:\s*")120(")', r'\g<1>80\2', text)
    text = re.sub(r"(timeout_ms:\s*)900000", r"\g<1>180000", text)
    path.write_text(text, encoding="utf-8")
PY

log "starting canary sampler (interval=${CANARY_INTERVAL_SEC}s)"
(
  sample=0
  : > "${CANARY_JSONL}"
  while :; do
    now_iso="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"
    pid="$(cat "${CANARY_PID_FILE}" 2>/dev/null || true)"
    health_code="$(curl -s -o /dev/null -w '%{http_code}' -H "${CANARY_AUTH_HEADER}" "${CANARY_API_URL}/services/health" || echo 000)"
    conn_payload="$(curl -s -H "${CANARY_AUTH_HEADER}" "${CANARY_API_URL}/connections" 2>/dev/null || true)"
    if [[ -n "$conn_payload" ]]; then
      conn_count="$(printf '%s' "$conn_payload" | jq -r 'if .connections then (.connections|length) elif .total then .total else "null" end' 2>/dev/null || echo null)"
    else
      conn_count="null"
    fi
    if [[ -n "${pid:-}" ]] && kill -0 "$pid" 2>/dev/null; then
      rss_kb="$(ps -o rss= -p "$pid" 2>/dev/null | awk '{print $1+0}' || echo null)"
      fd_count="$(lsof -p "$pid" 2>/dev/null | wc -l | awk '{print $1+0}' || echo null)"
    else
      rss_kb="null"
      fd_count="null"
    fi
    printf '{"ts":"%s","sample":%d,"pid":%s,"health_code":%s,"rss_kb":%s,"fd_count":%s,"connections":%s}\n' \
      "$now_iso" "$sample" "${pid:-null}" "$health_code" "$rss_kb" "$fd_count" "$conn_count" >> "${CANARY_JSONL}"
    sample=$((sample + 1))
    sleep "${CANARY_INTERVAL_SEC}"
  done
) &
CANARY_SAMPLER_PID="$!"

run_stage PREFLIGHT "${ROOT_DIR}/scripts/l18/preflight_macos.sh" --require-docker "${REQUIRE_DOCKER}" || true
run_stage GUI "${ROOT_DIR}/scripts/l18/gui_real_cert.sh" \
  --gui-app "${GUI_APP}" \
  --allow-existing-system-proxy "${ALLOW_EXISTING_SYSTEM_PROXY}" \
  --allow-real-proxy-coexist "${ALLOW_REAL_PROXY_COEXIST}" \
  --sandbox-root "${GUI_DIR}/sandbox" || true
if [[ -f "${GUI_REPORT_JSON_SRC}" ]]; then
  cp "${GUI_REPORT_JSON_SRC}" "${GUI_REPORT_JSON_DST}"
fi
if [[ -f "${GUI_REPORT_MD_SRC}" ]]; then
  cp "${GUI_REPORT_MD_SRC}" "${GUI_REPORT_MD_DST}"
fi
run_stage ALL_CASES_RUST cargo run -p interop-lab -- \
  --cases-dir "${CASES_SHORT_DIR}" \
  --artifacts-dir "${INTEROP_ARTIFACTS}" \
  case run \
  --kernel rust \
  --exclude-tag soak || true
run_stage SOAK_SHORT_WS cargo run -p interop-lab -- \
  --cases-dir "${CASES_SHORT_DIR}" \
  --artifacts-dir "${INTEROP_ARTIFACTS}" \
  case run p2_connections_ws_soak_suite \
  --kernel rust || true
run_stage SOAK_SHORT_WS_DUAL_CORE cargo run -p interop-lab -- \
  --cases-dir "${CASES_SHORT_DIR}" \
  --artifacts-dir "${INTEROP_ARTIFACTS}" \
  case run p2_connections_ws_soak_dual_core \
  --kernel rust || true
run_stage P2_ROUND_2 cargo run -p interop-lab -- \
  --cases-dir "${CASES_SHORT_DIR}" \
  --artifacts-dir "${INTEROP_ARTIFACTS}" \
  case run \
  --kernel rust \
  --priority p2 \
  --exclude-tag soak || true
run_stage P2_ROUND_3 cargo run -p interop-lab -- \
  --cases-dir "${CASES_SHORT_DIR}" \
  --artifacts-dir "${INTEROP_ARTIFACTS}" \
  case run \
  --kernel rust \
  --priority p2 \
  --exclude-tag soak || true
run_stage P2_ROUND_4 cargo run -p interop-lab -- \
  --cases-dir "${CASES_SHORT_DIR}" \
  --artifacts-dir "${INTEROP_ARTIFACTS}" \
  case run \
  --kernel rust \
  --priority p2 \
  --exclude-tag soak || true
run_stage DUAL_NIGHTLY "${ROOT_DIR}/scripts/l18/run_dual_kernel_cert.sh" \
  --profile nightly \
  --report-root "${DUAL_REPORT_ROOT}" \
  --artifacts-dir "${DUAL_ARTIFACTS_DIR}" || true
run_stage PERF_3X env \
  L18_PERF_ROUNDS=3 \
  L18_STARTUP_WARMUP_RUNS=1 \
  L18_STARTUP_SAMPLE_RUNS=14 \
  L18_PERF_WARMUP_REQUESTS=60 \
  L18_PERF_SAMPLE_REQUESTS=360 \
  L18_RUST_BUILD_ENABLED=0 \
  L18_RUST_BIN="${RUST_BIN}" \
  L18_PERF_GATE_LOCK="${PERF_LOCK}" \
  L18_PERF_GATE_REPORT="${PERF_REPORT}" \
  L18_PERF_WORK_DIR="${PERF_DIR}/work" \
  "${ROOT_DIR}/scripts/l18/perf_gate.sh" || true

stop_canary_sampler

CANARY_PASS_RAW="$(finalize_canary_summary | tee "${RUN_DIR}/canary/canary.summary.log" | awk -F= '/^pass=/{print $2}' | tail -n1)"
CANARY_PASS="FAIL"
if [[ "${CANARY_PASS_RAW}" == "true" ]]; then
  CANARY_PASS="PASS"
else
  HAS_FAIL=1
fi

END_EPOCH="$(date +%s)"
elapsed_sec=$((END_EPOCH - START_EPOCH))
budget_sec=$((DURATION_MIN * 60))
if (( elapsed_sec > budget_sec )); then
  HAS_FAIL=1
fi

overall="PASS"
if (( HAS_FAIL != 0 )); then
  overall="FAIL"
fi

export STATUS_FILE CONFIG_FREEZE_JSON
export START_EPOCH END_EPOCH DURATION_MIN elapsed_sec budget_sec overall
export PRECHECK_TXT MAIN_LOG
GUI_REPORT_JSON_PATH="${GUI_REPORT_JSON_DST}"
if [[ ! -f "${GUI_REPORT_JSON_PATH}" && -f "${GUI_REPORT_JSON_SRC}" ]]; then
  GUI_REPORT_JSON_PATH="${GUI_REPORT_JSON_SRC}"
fi
export GUI_DIR INTEROP_ARTIFACTS DUAL_REPORT_ROOT DUAL_ARTIFACTS_DIR PERF_REPORT PERF_LOCK CANARY_JSONL CANARY_SUMMARY CASES_SHORT_DIR GUI_REPORT_JSON_PATH
export P2_ROUNDS_TOTAL WS_PARALLEL_FACTOR PERF_SAMPLE_FACTOR COMPOSITE_PRESSURE CANARY_PASS
for key in "${STAGE_ORDER[@]}"; do
  export "STAGE_STATUS_${key}=${STAGE_STATUS[$key]}"
  export "STAGE_RC_${key}=${STAGE_RC[$key]}"
done
python3 - <<'PY'
import json
import os
from datetime import datetime, timezone

stages = {}
for k, v in os.environ.items():
    if k.startswith("STAGE_STATUS_"):
        stage_key = k[len("STAGE_STATUS_"):]
        stages[stage_key] = {
            "status": v,
            "rc": int(os.environ.get(f"STAGE_RC_{stage_key}", "0")),
        }

payload = {
    "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "mode": "short_stress",
    "duration_min_target": int(os.environ["DURATION_MIN"]),
    "elapsed_sec": int(os.environ["elapsed_sec"]),
    "budget_sec": int(os.environ["budget_sec"]),
    "overall": os.environ["overall"],
    "pressure_model": {
        "ws_parallel_factor": int(os.environ["WS_PARALLEL_FACTOR"]),
        "p2_rounds_total": int(os.environ["P2_ROUNDS_TOTAL"]),
        "perf_sample_factor": int(os.environ["PERF_SAMPLE_FACTOR"]),
        "composite_multiplier": int(os.environ["COMPOSITE_PRESSURE"]),
    },
    "artifacts": {
        "precheck": os.environ["PRECHECK_TXT"],
        "main_log": os.environ["MAIN_LOG"],
        "gui_report": os.environ["GUI_REPORT_JSON_PATH"],
        "canary_jsonl": os.environ["CANARY_JSONL"],
        "canary_summary": os.environ["CANARY_SUMMARY"],
        "dual_report_root": os.environ["DUAL_REPORT_ROOT"],
        "dual_artifacts_dir": os.environ["DUAL_ARTIFACTS_DIR"],
        "perf_report": os.environ["PERF_REPORT"],
        "perf_lock": os.environ["PERF_LOCK"],
        "interop_artifacts": os.environ["INTEROP_ARTIFACTS"],
        "cases_short_dir": os.environ["CASES_SHORT_DIR"],
    },
    "canary": {
        "status": os.environ["CANARY_PASS"],
    },
    "stages": stages,
}

with open(os.environ["STATUS_FILE"], "w", encoding="utf-8") as f:
    json.dump(payload, f, ensure_ascii=True, indent=2)

freeze = {
    "generated_at": datetime.now(timezone.utc).isoformat(),
    "mode": "short_stress_48x",
    "duration_min": int(os.environ["DURATION_MIN"]),
    "pressure_model": payload["pressure_model"],
}
with open(os.environ["CONFIG_FREEZE_JSON"], "w", encoding="utf-8") as f:
    json.dump(freeze, f, ensure_ascii=True, indent=2)
PY

echo -e "run\toverall\tcanary\tstatus_file" > "${SUMMARY_TSV}"
printf '%s\t%s\t%s\t%s\n' "r1" "${overall}" "${CANARY_PASS}" "${STATUS_FILE}" >> "${SUMMARY_TSV}"

log "summary:"
cat "${SUMMARY_TSV}" | tee -a "${MAIN_LOG}"
log "batch_root=${BATCH_ROOT}"
log "run_root=${RUN_ROOT}"
log "status_file=${STATUS_FILE}"
log "config_freeze=${CONFIG_FREEZE_JSON}"

if [[ "${overall}" != "PASS" ]]; then
  exit 1
fi
