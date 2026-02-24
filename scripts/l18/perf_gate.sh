#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage:
  scripts/l18/perf_gate.sh [options]

Options:
  --go-bin PATH
  --go-config PATH
  --go-proxy-port PORT
  --rust-bin PATH
  --rust-config PATH
  --rust-proxy-port PORT
  --sample-requests N
  --local-http-port PORT
  --report PATH
  --p95-threshold-pct N
  --rss-threshold-pct N
  --startup-threshold-pct N

Gate criteria (relative to Go):
  p95 latency <= +5%
  RSS peak <= +10%
  startup time <= +10%
USAGE
}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"

GO_BIN="${L18_GO_BIN:-${ROOT_DIR}/go_fork_source/sing-box-1.12.14/sing-box}"
GO_CONFIG="${L18_GO_CONFIG:-${ROOT_DIR}/labs/interop-lab/configs/bench_go.json}"
GO_PROXY_PORT="${L18_GO_PROXY_PORT:-11811}"

RUST_BIN="${L18_RUST_BIN:-${ROOT_DIR}/target/debug/run}"
RUST_CONFIG="${L18_RUST_CONFIG:-${ROOT_DIR}/labs/interop-lab/configs/bench_rust.json}"
RUST_PROXY_PORT="${L18_RUST_PROXY_PORT:-11810}"

SAMPLE_REQUESTS="${L18_PERF_SAMPLE_REQUESTS:-40}"
LOCAL_HTTP_PORT="${L18_LOCAL_HTTP_PORT:-18080}"

P95_THRESHOLD_PCT="${L18_P95_THRESHOLD_PCT:-5}"
RSS_THRESHOLD_PCT="${L18_RSS_THRESHOLD_PCT:-10}"
STARTUP_THRESHOLD_PCT="${L18_STARTUP_THRESHOLD_PCT:-10}"

REPORT_PATH="${L18_PERF_GATE_REPORT:-${ROOT_DIR}/reports/l18/perf_gate.json}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --go-bin)
      GO_BIN="$2"
      shift 2
      ;;
    --go-config)
      GO_CONFIG="$2"
      shift 2
      ;;
    --go-proxy-port)
      GO_PROXY_PORT="$2"
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
    --rust-proxy-port)
      RUST_PROXY_PORT="$2"
      shift 2
      ;;
    --sample-requests)
      SAMPLE_REQUESTS="$2"
      shift 2
      ;;
    --local-http-port)
      LOCAL_HTTP_PORT="$2"
      shift 2
      ;;
    --report)
      REPORT_PATH="$2"
      shift 2
      ;;
    --p95-threshold-pct)
      P95_THRESHOLD_PCT="$2"
      shift 2
      ;;
    --rss-threshold-pct)
      RSS_THRESHOLD_PCT="$2"
      shift 2
      ;;
    --startup-threshold-pct)
      STARTUP_THRESHOLD_PCT="$2"
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

if [[ ! -x "$GO_BIN" ]]; then
  echo "go binary not executable: $GO_BIN" >&2
  exit 1
fi
if [[ ! -f "$GO_CONFIG" ]]; then
  echo "go config not found: $GO_CONFIG" >&2
  exit 1
fi
if [[ ! -x "$RUST_BIN" ]]; then
  echo "rust binary not executable: $RUST_BIN" >&2
  exit 1
fi
if [[ ! -f "$RUST_CONFIG" ]]; then
  echo "rust config not found: $RUST_CONFIG" >&2
  exit 1
fi

mkdir -p "$(dirname "$REPORT_PATH")" "${ROOT_DIR}/reports/l18/perf"

LOCAL_URL="http://127.0.0.1:${LOCAL_HTTP_PORT}/"
LAT_RUST_FILE="${ROOT_DIR}/reports/l18/perf/rust_latency_samples.txt"
LAT_GO_FILE="${ROOT_DIR}/reports/l18/perf/go_latency_samples.txt"

RUST_STARTUP_MS=0
GO_STARTUP_MS=0
RUST_P95_MS=0
GO_P95_MS=0

SERVER_PID=""
cleanup() {
  if [[ -n "$SERVER_PID" ]]; then
    kill "$SERVER_PID" >/dev/null 2>&1 || true
    wait "$SERVER_PID" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

now_ms() {
  python3 - <<'PY'
import time
print(int(time.time() * 1000))
PY
}

wait_port_open() {
  local port="$1"
  local timeout_sec="$2"
  local i=0
  while [[ "$i" -lt "$timeout_sec" ]]; do
    if nc -z 127.0.0.1 "$port" >/dev/null 2>&1; then
      return 0
    fi
    i=$((i + 1))
    sleep 0.1
  done
  return 1
}

stop_pid() {
  local pid="$1"
  if [[ -z "$pid" ]]; then
    return
  fi
  if kill -0 "$pid" >/dev/null 2>&1; then
    kill "$pid" >/dev/null 2>&1 || true
    for _ in $(seq 1 30); do
      if ! kill -0 "$pid" >/dev/null 2>&1; then
        wait "$pid" >/dev/null 2>&1 || true
        return
      fi
      sleep 0.2
    done
    kill -KILL "$pid" >/dev/null 2>&1 || true
    wait "$pid" >/dev/null 2>&1 || true
  fi
}

calc_p95_from_file() {
  local file="$1"
  python3 - "$file" <<'PY'
import math
import sys

vals = []
with open(sys.argv[1], "r", encoding="utf-8") as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        vals.append(float(line))

if not vals:
    print("0")
    sys.exit(0)

vals.sort()
idx = max(0, math.ceil(len(vals) * 0.95) - 1)
print(f"{vals[idx] * 1000.0:.6f}")
PY
}

measure_latency_and_startup() {
  local core="$1"
  local mode="$2"
  local bin="$3"
  local config="$4"
  local proxy_port="$5"
  local out_samples="$6"

  : > "$out_samples"

  local cmd=()
  if [[ "$mode" == "go" ]]; then
    cmd=("$bin" run -c "$config")
  else
    cmd=("$bin" --config "$config")
  fi

  local start_ms end_ms
  start_ms="$(now_ms)"
  "${cmd[@]}" >"${ROOT_DIR}/reports/l18/perf/${core}.kernel.log" 2>&1 &
  local kernel_pid=$!

  if ! wait_port_open "$proxy_port" 30; then
    stop_pid "$kernel_pid"
    echo "${core} proxy port not ready: ${proxy_port}" >&2
    return 1
  fi

  end_ms="$(now_ms)"
  local startup_ms=$((end_ms - start_ms))

  for _ in $(seq 1 "$SAMPLE_REQUESTS"); do
    curl -sS --socks5-hostname "127.0.0.1:${proxy_port}" \
      --connect-timeout 3 \
      --max-time 8 \
      -o /dev/null \
      -w '%{time_total}\n' \
      "$LOCAL_URL" >> "$out_samples"
  done

  local p95_ms
  p95_ms="$(calc_p95_from_file "$out_samples")"

  stop_pid "$kernel_pid"

  if [[ "$core" == "rust" ]]; then
    RUST_STARTUP_MS="$startup_ms"
    RUST_P95_MS="$p95_ms"
  else
    GO_STARTUP_MS="$startup_ms"
    GO_P95_MS="$p95_ms"
  fi
}

if nc -z 127.0.0.1 "$LOCAL_HTTP_PORT" >/dev/null 2>&1; then
  echo "local http port busy: $LOCAL_HTTP_PORT" >&2
  exit 1
fi

python3 -m http.server "$LOCAL_HTTP_PORT" --bind 127.0.0.1 >"${ROOT_DIR}/reports/l18/perf/local_http_server.log" 2>&1 &
SERVER_PID=$!

if ! wait_port_open "$LOCAL_HTTP_PORT" 10; then
  echo "failed to start local http server on port ${LOCAL_HTTP_PORT}" >&2
  exit 1
fi

measure_latency_and_startup "rust" "rust" "$RUST_BIN" "$RUST_CONFIG" "$RUST_PROXY_PORT" "$LAT_RUST_FILE"
measure_latency_and_startup "go" "go" "$GO_BIN" "$GO_CONFIG" "$GO_PROXY_PORT" "$LAT_GO_FILE"

BENCH_TARGET_URL="$LOCAL_URL" \
RUST_BINARY="$RUST_BIN" \
RUST_CONFIG="$RUST_CONFIG" \
GO_BINARY="$GO_BIN" \
GO_CONFIG="$GO_CONFIG" \
"${ROOT_DIR}/scripts/bench_memory.sh"

"${ROOT_DIR}/scripts/bench_vs_go.sh" --quick >/dev/null

MEMORY_REPORT="${ROOT_DIR}/reports/benchmarks/memory_comparison.json"
if [[ ! -f "$MEMORY_REPORT" ]]; then
  echo "memory report missing: $MEMORY_REPORT" >&2
  exit 1
fi

export REPORT_PATH MEMORY_REPORT
export GO_STARTUP_MS RUST_STARTUP_MS GO_P95_MS RUST_P95_MS
export P95_THRESHOLD_PCT RSS_THRESHOLD_PCT STARTUP_THRESHOLD_PCT
python3 - <<'PY'
import json
import os
from datetime import datetime, timezone

memory_report = os.environ["MEMORY_REPORT"]
with open(memory_report, "r", encoding="utf-8") as f:
    mem = json.load(f)

def peak(entry):
    m = entry.get("measurements", {})
    vals = [
        int(m.get("idle", {}).get("rss_kb", 0) or 0),
        int(m.get("connections_100", {}).get("rss_kb", 0) or 0),
        int(m.get("connections_1000", {}).get("rss_kb", 0) or 0),
    ]
    return max(vals)

rust = mem.get("rust", {})
go = mem.get("go", {})

rust_peak = peak(rust)
go_peak = peak(go)

rust_p95 = float(os.environ.get("RUST_P95_MS", "0"))
go_p95 = float(os.environ.get("GO_P95_MS", "0"))
rust_startup = float(os.environ.get("RUST_STARTUP_MS", "0"))
go_startup = float(os.environ.get("GO_STARTUP_MS", "0"))

p95_limit = float(os.environ.get("P95_THRESHOLD_PCT", "5"))
rss_limit = float(os.environ.get("RSS_THRESHOLD_PCT", "10"))
startup_limit = float(os.environ.get("STARTUP_THRESHOLD_PCT", "10"))

errors = []
if go_p95 <= 0:
    errors.append("go_p95_unavailable")
if go_peak <= 0:
    errors.append("go_rss_peak_unavailable")
if go_startup <= 0:
    errors.append("go_startup_unavailable")

if errors:
    payload = {
        "generated_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "pass": False,
        "reason": "metrics_unavailable",
        "errors": errors,
        "metrics": {
            "latency_p95_ms": {"rust": rust_p95, "go": go_p95},
            "rss_peak_kb": {"rust": rust_peak, "go": go_peak},
            "startup_ms": {"rust": rust_startup, "go": go_startup},
        },
    }
    with open(os.environ["REPORT_PATH"], "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)
    print("metrics unavailable")
    raise SystemExit(1)

p95_reg = ((rust_p95 - go_p95) / go_p95) * 100.0
rss_reg = ((rust_peak - go_peak) / go_peak) * 100.0
startup_reg = ((rust_startup - go_startup) / go_startup) * 100.0

checks = {
    "latency_p95": {
        "value_pct": p95_reg,
        "limit_pct": p95_limit,
        "pass": p95_reg <= p95_limit,
    },
    "rss_peak": {
        "value_pct": rss_reg,
        "limit_pct": rss_limit,
        "pass": rss_reg <= rss_limit,
    },
    "startup": {
        "value_pct": startup_reg,
        "limit_pct": startup_limit,
        "pass": startup_reg <= startup_limit,
    },
}

pass_flag = all(v["pass"] for v in checks.values())

payload = {
    "generated_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
    "pass": pass_flag,
    "thresholds_pct": {
        "latency_p95": p95_limit,
        "rss_peak": rss_limit,
        "startup": startup_limit,
    },
    "metrics": {
        "latency_p95_ms": {"rust": rust_p95, "go": go_p95},
        "rss_peak_kb": {"rust": rust_peak, "go": go_peak},
        "startup_ms": {"rust": rust_startup, "go": go_startup},
    },
    "regressions_pct": {
        "latency_p95": p95_reg,
        "rss_peak": rss_reg,
        "startup": startup_reg,
    },
    "checks": checks,
    "inputs": {
        "memory_report": os.path.abspath(memory_report),
        "local_target": f"http://127.0.0.1:{os.environ.get('L18_LOCAL_HTTP_PORT', '')}/",
    },
}

with open(os.environ["REPORT_PATH"], "w", encoding="utf-8") as f:
    json.dump(payload, f, indent=2, ensure_ascii=False)

print(f"perf gate report written: {os.environ['REPORT_PATH']}")
print(f"pass={int(pass_flag)}")

if not pass_flag:
    raise SystemExit(1)
PY

echo "[L18 perf-gate] PASS"
