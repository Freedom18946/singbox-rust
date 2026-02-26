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
  --startup-warmup-runs N
  --startup-sample-runs N
  --warmup-requests N
  --sample-requests N
  --request-connect-timeout-sec N
  --request-max-time-sec N
  --local-http-port PORT
  --perf-rounds N
  --round-trim-each-side N
  --lock-file PATH
  --report PATH
  --p95-threshold-pct N
  --rss-threshold-pct N
  --startup-threshold-pct N

Gate criteria (relative to Go):
  p95 latency (trimmed-round median) <= +5%
  RSS peak <= +10%
  startup time (trimmed-round median) <= +10%
USAGE
}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"

GO_BIN="${L18_GO_BIN:-${ROOT_DIR}/go_fork_source/sing-box-1.12.14/sing-box}"
GO_CONFIG="${L18_GO_CONFIG:-${ROOT_DIR}/labs/interop-lab/configs/l18_perf_go.json}"
GO_PROXY_PORT="${L18_GO_PROXY_PORT:-11811}"

RUST_BIN="${L18_RUST_BIN:-${ROOT_DIR}/target/release/run}"
RUST_CONFIG="${L18_RUST_CONFIG:-${ROOT_DIR}/labs/interop-lab/configs/l18_perf_rust.json}"
RUST_PROXY_PORT="${L18_RUST_PROXY_PORT:-11810}"
RUST_BUILD_FEATURES="${L18_RUST_BUILD_FEATURES:-acceptance}"
RUST_BUILD_ENABLED="${L18_RUST_BUILD_ENABLED:-1}"

STARTUP_WARMUP_RUNS="${L18_STARTUP_WARMUP_RUNS:-1}"
STARTUP_SAMPLE_RUNS="${L18_STARTUP_SAMPLE_RUNS:-7}"
WARMUP_REQUESTS="${L18_PERF_WARMUP_REQUESTS:-20}"
SAMPLE_REQUESTS="${L18_PERF_SAMPLE_REQUESTS:-120}"
REQUEST_CONNECT_TIMEOUT_SEC="${L18_PERF_CONNECT_TIMEOUT_SEC:-3}"
REQUEST_MAX_TIME_SEC="${L18_PERF_MAX_TIME_SEC:-8}"
LOCAL_HTTP_PORT="${L18_LOCAL_HTTP_PORT:-18080}"
PERF_ROUNDS="${L18_PERF_ROUNDS:-3}"
ROUND_TRIM_EACH_SIDE="${L18_PERF_ROUND_TRIM_EACH_SIDE:-1}"

P95_THRESHOLD_PCT="${L18_P95_THRESHOLD_PCT:-5}"
RSS_THRESHOLD_PCT="${L18_RSS_THRESHOLD_PCT:-10}"
STARTUP_THRESHOLD_PCT="${L18_STARTUP_THRESHOLD_PCT:-10}"

LOCK_PATH="${L18_PERF_GATE_LOCK:-${ROOT_DIR}/reports/l18/perf/perf_gate.lock.json}"
REPORT_PATH="${L18_PERF_GATE_REPORT:-${ROOT_DIR}/reports/l18/perf_gate.json}"
PERF_WORK_DIR="${L18_PERF_WORK_DIR:-${ROOT_DIR}/reports/l18/perf}"

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
    --startup-warmup-runs)
      STARTUP_WARMUP_RUNS="$2"
      shift 2
      ;;
    --startup-sample-runs)
      STARTUP_SAMPLE_RUNS="$2"
      shift 2
      ;;
    --warmup-requests)
      WARMUP_REQUESTS="$2"
      shift 2
      ;;
    --sample-requests)
      SAMPLE_REQUESTS="$2"
      shift 2
      ;;
    --request-connect-timeout-sec)
      REQUEST_CONNECT_TIMEOUT_SEC="$2"
      shift 2
      ;;
    --request-max-time-sec)
      REQUEST_MAX_TIME_SEC="$2"
      shift 2
      ;;
    --local-http-port)
      LOCAL_HTTP_PORT="$2"
      shift 2
      ;;
    --perf-rounds)
      PERF_ROUNDS="$2"
      shift 2
      ;;
    --round-trim-each-side)
      ROUND_TRIM_EACH_SIDE="$2"
      shift 2
      ;;
    --lock-file)
      LOCK_PATH="$2"
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

ensure_positive_int() {
  local key="$1"
  local value="$2"
  if ! [[ "$value" =~ ^[0-9]+$ ]] || [[ "$value" -le 0 ]]; then
    echo "${key} must be positive integer, got: ${value}" >&2
    exit 2
  fi
}

ensure_nonnegative_int() {
  local key="$1"
  local value="$2"
  if ! [[ "$value" =~ ^[0-9]+$ ]]; then
    echo "${key} must be non-negative integer, got: ${value}" >&2
    exit 2
  fi
}

ensure_positive_int "go_proxy_port" "$GO_PROXY_PORT"
ensure_positive_int "rust_proxy_port" "$RUST_PROXY_PORT"
ensure_positive_int "startup_warmup_runs" "$STARTUP_WARMUP_RUNS"
ensure_positive_int "startup_sample_runs" "$STARTUP_SAMPLE_RUNS"
ensure_positive_int "warmup_requests" "$WARMUP_REQUESTS"
ensure_positive_int "sample_requests" "$SAMPLE_REQUESTS"
ensure_positive_int "request_connect_timeout_sec" "$REQUEST_CONNECT_TIMEOUT_SEC"
ensure_positive_int "request_max_time_sec" "$REQUEST_MAX_TIME_SEC"
ensure_positive_int "local_http_port" "$LOCAL_HTTP_PORT"
ensure_positive_int "perf_rounds" "$PERF_ROUNDS"
ensure_nonnegative_int "round_trim_each_side" "$ROUND_TRIM_EACH_SIDE"

max_trim_each_side=$(( (PERF_ROUNDS - 1) / 2 ))
if [[ "$ROUND_TRIM_EACH_SIDE" -gt "$max_trim_each_side" ]]; then
  echo "round_trim_each_side too large: ${ROUND_TRIM_EACH_SIDE} (max=${max_trim_each_side} for perf_rounds=${PERF_ROUNDS})" >&2
  exit 2
fi

if [[ "$RUST_BUILD_ENABLED" != "0" && "$RUST_BUILD_ENABLED" != "1" ]]; then
  echo "rust_build_enabled must be 0 or 1, got: ${RUST_BUILD_ENABLED}" >&2
  exit 2
fi

if [[ ! -x "$GO_BIN" ]]; then
  echo "go binary not executable: $GO_BIN" >&2
  exit 1
fi
if [[ ! -f "$GO_CONFIG" ]]; then
  echo "go config not found: $GO_CONFIG" >&2
  exit 1
fi

if [[ "$RUST_BUILD_ENABLED" == "1" && "$RUST_BIN" == "${ROOT_DIR}/target/release/run" ]]; then
  echo "[L18 perf-gate] building rust release run (features=${RUST_BUILD_FEATURES})..."
  cargo build --release -p app --features "$RUST_BUILD_FEATURES" --bin run >/dev/null
fi
if [[ ! -x "$RUST_BIN" ]]; then
  echo "rust binary not executable after build: $RUST_BIN" >&2
  exit 1
fi
if [[ ! -f "$RUST_CONFIG" ]]; then
  echo "rust config not found: $RUST_CONFIG" >&2
  exit 1
fi

mkdir -p "$(dirname "$REPORT_PATH")" "$(dirname "$LOCK_PATH")" "$PERF_WORK_DIR"

LOCAL_URL="http://127.0.0.1:${LOCAL_HTTP_PORT}/"

SERVER_PID=""
cleanup() {
  if [[ -n "$SERVER_PID" ]]; then
    kill "$SERVER_PID" >/dev/null 2>&1 || true
    wait "$SERVER_PID" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

now_ms() {
  if [[ -n "${EPOCHREALTIME:-}" ]]; then
    local sec="${EPOCHREALTIME%%.*}"
    local frac="${EPOCHREALTIME#*.}"
    local ms="${frac:0:3}"
    printf '%s\n' "$((10#${sec} * 1000 + 10#${ms}))"
    return
  fi
  python3 - <<'PY'
import time
print(int(time.time() * 1000))
PY
}

wait_port_open() {
  local port="$1"
  local timeout_sec="$2"
  local max_attempts=$((timeout_sec * 100))
  local i=0
  while [[ "$i" -lt "$max_attempts" ]]; do
    if (exec 3<>"/dev/tcp/127.0.0.1/${port}") >/dev/null 2>&1; then
      exec 3<&-
      exec 3>&-
      return 0
    fi
    i=$((i + 1))
    sleep 0.01
  done
  return 1
}

is_port_open() {
  local port="$1"
  if (exec 3<>"/dev/tcp/127.0.0.1/${port}") >/dev/null 2>&1; then
    exec 3<&-
    exec 3>&-
    return 0
  fi
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

calc_median_ms_from_file() {
  local file="$1"
  python3 - "$file" <<'PY'
import statistics
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
    raise SystemExit(0)

print(f"{statistics.median(vals):.6f}")
PY
}

record_lock() {
  local go_bin_sha256 rust_bin_sha256 go_cfg_sha256 rust_cfg_sha256
  go_bin_sha256="$(shasum -a 256 "$GO_BIN" | awk '{print $1}')"
  rust_bin_sha256="$(shasum -a 256 "$RUST_BIN" | awk '{print $1}')"
  go_cfg_sha256="$(shasum -a 256 "$GO_CONFIG" | awk '{print $1}')"
  rust_cfg_sha256="$(shasum -a 256 "$RUST_CONFIG" | awk '{print $1}')"

  export LOCK_PATH GO_BIN GO_CONFIG GO_PROXY_PORT RUST_BIN RUST_CONFIG RUST_PROXY_PORT
  export GO_BIN_SHA256="$go_bin_sha256"
  export RUST_BIN_SHA256="$rust_bin_sha256"
  export GO_CONFIG_SHA256="$go_cfg_sha256"
  export RUST_CONFIG_SHA256="$rust_cfg_sha256"
  export RUST_BUILD_FEATURES RUST_BUILD_ENABLED
  export STARTUP_WARMUP_RUNS STARTUP_SAMPLE_RUNS
  export WARMUP_REQUESTS SAMPLE_REQUESTS REQUEST_CONNECT_TIMEOUT_SEC REQUEST_MAX_TIME_SEC
  export LOCAL_HTTP_PORT P95_THRESHOLD_PCT RSS_THRESHOLD_PCT STARTUP_THRESHOLD_PCT
  export PERF_ROUNDS ROUND_TRIM_EACH_SIDE
  python3 - <<'PY'
import json
import os
from datetime import datetime, timezone

payload = {
    "generated_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
    "fixed_config": {
        "go_bin": os.path.abspath(os.environ["GO_BIN"]),
        "go_bin_sha256": os.environ["GO_BIN_SHA256"],
        "go_config": os.path.abspath(os.environ["GO_CONFIG"]),
        "go_config_sha256": os.environ["GO_CONFIG_SHA256"],
        "go_proxy_port": int(os.environ["GO_PROXY_PORT"]),
        "rust_bin": os.path.abspath(os.environ["RUST_BIN"]),
        "rust_bin_sha256": os.environ["RUST_BIN_SHA256"],
        "rust_config": os.path.abspath(os.environ["RUST_CONFIG"]),
        "rust_config_sha256": os.environ["RUST_CONFIG_SHA256"],
        "rust_proxy_port": int(os.environ["RUST_PROXY_PORT"]),
        "rust_build_features": os.environ.get("RUST_BUILD_FEATURES", ""),
        "rust_build_enabled": int(os.environ.get("RUST_BUILD_ENABLED", "0")),
        "startup_warmup_runs": int(os.environ.get("STARTUP_WARMUP_RUNS", "0")),
        "startup_sample_runs": int(os.environ.get("STARTUP_SAMPLE_RUNS", "0")),
        "warmup_requests": int(os.environ["WARMUP_REQUESTS"]),
        "sample_requests": int(os.environ["SAMPLE_REQUESTS"]),
        "request_connect_timeout_sec": int(os.environ["REQUEST_CONNECT_TIMEOUT_SEC"]),
        "request_max_time_sec": int(os.environ["REQUEST_MAX_TIME_SEC"]),
        "local_http_port": int(os.environ["LOCAL_HTTP_PORT"]),
        "perf_rounds": int(os.environ["PERF_ROUNDS"]),
        "round_trim_each_side": int(os.environ["ROUND_TRIM_EACH_SIDE"]),
        "rss_memory_levels": [100, 1000],
        "thresholds_pct": {
            "latency_p95": float(os.environ["P95_THRESHOLD_PCT"]),
            "rss_peak": float(os.environ["RSS_THRESHOLD_PCT"]),
            "startup": float(os.environ["STARTUP_THRESHOLD_PCT"]),
        },
    },
}

with open(os.environ["LOCK_PATH"], "w", encoding="utf-8") as f:
    json.dump(payload, f, indent=2, ensure_ascii=False)
PY
}

measure_startup_samples() {
  local core="$1"
  local mode="$2"
  local bin="$3"
  local config="$4"
  local proxy_port="$5"
  local out_startup_samples="$6"
  local kernel_log_file="$7"

  : > "$out_startup_samples"

  local cmd=()
  if [[ "$mode" == "go" ]]; then
    cmd=("$bin" run -c "$config")
  else
    cmd=("$bin" --config "$config")
  fi

  local total_runs=$((STARTUP_WARMUP_RUNS + STARTUP_SAMPLE_RUNS))
  local run_i=1
  while [[ "$run_i" -le "$total_runs" ]]; do
    local start_ms end_ms
    start_ms="$(now_ms)"
    "${cmd[@]}" >"${kernel_log_file}" 2>&1 &
    local kernel_pid=$!

    if ! wait_port_open "$proxy_port" 30; then
      stop_pid "$kernel_pid"
      echo "${core} proxy port not ready during startup sampling: ${proxy_port}" >&2
      return 1
    fi

    end_ms="$(now_ms)"
    local startup_ms=$((end_ms - start_ms))

    if [[ "$run_i" -gt "$STARTUP_WARMUP_RUNS" ]]; then
      printf '%s\n' "$startup_ms" >> "$out_startup_samples"
    fi

    stop_pid "$kernel_pid"
    run_i=$((run_i + 1))
  done

  local startup_sample_count
  startup_sample_count="$(wc -l < "$out_startup_samples" | tr -d ' ')"
  if [[ "$startup_sample_count" -ne "$STARTUP_SAMPLE_RUNS" ]]; then
    echo "${core} startup sample count mismatch: expected=${STARTUP_SAMPLE_RUNS} actual=${startup_sample_count}" >&2
    return 1
  fi

  local startup_median_ms
  startup_median_ms="$(calc_median_ms_from_file "$out_startup_samples")"
  printf '%s\n' "$startup_median_ms"
}

measure_latency() {
  local core="$1"
  local mode="$2"
  local bin="$3"
  local config="$4"
  local proxy_port="$5"
  local out_samples="$6"
  local kernel_log_file="$7"

  : > "$out_samples"

  local cmd=()
  if [[ "$mode" == "go" ]]; then
    cmd=("$bin" run -c "$config")
  else
    cmd=("$bin" --config "$config")
  fi

  "${cmd[@]}" >"${kernel_log_file}" 2>&1 &
  local kernel_pid=$!

  if ! wait_port_open "$proxy_port" 30; then
    stop_pid "$kernel_pid"
    echo "${core} proxy port not ready: ${proxy_port}" >&2
    return 1
  fi

  for _ in $(seq 1 "$WARMUP_REQUESTS"); do
    curl -sS --socks5-hostname "127.0.0.1:${proxy_port}" \
      --connect-timeout "$REQUEST_CONNECT_TIMEOUT_SEC" \
      --max-time "$REQUEST_MAX_TIME_SEC" \
      -o /dev/null \
      "$LOCAL_URL" >/dev/null
  done

  for _ in $(seq 1 "$SAMPLE_REQUESTS"); do
    curl -sS --socks5-hostname "127.0.0.1:${proxy_port}" \
      --connect-timeout "$REQUEST_CONNECT_TIMEOUT_SEC" \
      --max-time "$REQUEST_MAX_TIME_SEC" \
      -o /dev/null \
      -w '%{time_total}\n' \
      "$LOCAL_URL" >> "$out_samples"
  done

  local sample_count
  sample_count="$(wc -l < "$out_samples" | tr -d ' ')"
  if [[ "$sample_count" -ne "$SAMPLE_REQUESTS" ]]; then
    stop_pid "$kernel_pid"
    echo "${core} latency sample count mismatch: expected=${SAMPLE_REQUESTS} actual=${sample_count}" >&2
    return 1
  fi

  local p95_ms
  p95_ms="$(calc_p95_from_file "$out_samples")"

  stop_pid "$kernel_pid"
  printf '%s\n' "$p95_ms"
}

if is_port_open "$LOCAL_HTTP_PORT"; then
  echo "local http port busy: $LOCAL_HTTP_PORT" >&2
  exit 1
fi

python3 -m http.server "$LOCAL_HTTP_PORT" --bind 127.0.0.1 >"${PERF_WORK_DIR}/local_http_server.log" 2>&1 &
SERVER_PID=$!

if ! wait_port_open "$LOCAL_HTTP_PORT" 10; then
  echo "failed to start local http server on port ${LOCAL_HTTP_PORT}" >&2
  exit 1
fi

record_lock

declare -a RUST_P95_ROUNDS=()
declare -a GO_P95_ROUNDS=()
declare -a RUST_STARTUP_ROUNDS=()
declare -a GO_STARTUP_ROUNDS=()
declare -a RUST_SAMPLE_COUNT_ROUNDS=()
declare -a GO_SAMPLE_COUNT_ROUNDS=()
declare -a RUST_STARTUP_SAMPLE_COUNT_ROUNDS=()
declare -a GO_STARTUP_SAMPLE_COUNT_ROUNDS=()
declare -a ROUND_DIRS=()

for round_idx in $(seq 1 "$PERF_ROUNDS"); do
  round_tag="$(printf 'round_%02d' "$round_idx")"
  round_dir="${PERF_WORK_DIR}/${round_tag}"
  mkdir -p "$round_dir"
  ROUND_DIRS+=("$round_dir")

  startup_rust_file="${round_dir}/rust_startup_samples_ms.txt"
  startup_go_file="${round_dir}/go_startup_samples_ms.txt"
  latency_rust_file="${round_dir}/rust_latency_samples.txt"
  latency_go_file="${round_dir}/go_latency_samples.txt"

  rust_startup_ms="$(measure_startup_samples "rust" "rust" "$RUST_BIN" "$RUST_CONFIG" "$RUST_PROXY_PORT" "$startup_rust_file" "${round_dir}/rust_startup.kernel.log")"
  go_startup_ms="$(measure_startup_samples "go" "go" "$GO_BIN" "$GO_CONFIG" "$GO_PROXY_PORT" "$startup_go_file" "${round_dir}/go_startup.kernel.log")"
  rust_p95_ms="$(measure_latency "rust" "rust" "$RUST_BIN" "$RUST_CONFIG" "$RUST_PROXY_PORT" "$latency_rust_file" "${round_dir}/rust_latency.kernel.log")"
  go_p95_ms="$(measure_latency "go" "go" "$GO_BIN" "$GO_CONFIG" "$GO_PROXY_PORT" "$latency_go_file" "${round_dir}/go_latency.kernel.log")"

  RUST_STARTUP_ROUNDS+=("$rust_startup_ms")
  GO_STARTUP_ROUNDS+=("$go_startup_ms")
  RUST_P95_ROUNDS+=("$rust_p95_ms")
  GO_P95_ROUNDS+=("$go_p95_ms")

  RUST_SAMPLE_COUNT_ROUNDS+=("$(wc -l < "$latency_rust_file" | tr -d ' ')")
  GO_SAMPLE_COUNT_ROUNDS+=("$(wc -l < "$latency_go_file" | tr -d ' ')")
  RUST_STARTUP_SAMPLE_COUNT_ROUNDS+=("$(wc -l < "$startup_rust_file" | tr -d ' ')")
  GO_STARTUP_SAMPLE_COUNT_ROUNDS+=("$(wc -l < "$startup_go_file" | tr -d ' ')")

  echo "[L18 perf-gate] ${round_tag} startup_ms(rust/go)=${rust_startup_ms}/${go_startup_ms} p95_ms(rust/go)=${rust_p95_ms}/${go_p95_ms}"
done

MEMORY_REPORT="${PERF_WORK_DIR}/memory_comparison.json"
BENCH_TARGET_URL="$LOCAL_URL" \
BENCH_MEMORY_REPORT_FILE="$MEMORY_REPORT" \
BENCH_MEMORY_WORK_DIR="${PERF_WORK_DIR}/bench_memory" \
SINGBOX_BINARY="$RUST_BIN" \
SINGBOX_CONFIG="$RUST_CONFIG" \
RUST_PROXY_ADDR="127.0.0.1:${RUST_PROXY_PORT}" \
GO_BINARY="$GO_BIN" \
GO_CONFIG="$GO_CONFIG" \
GO_PROXY_ADDR="127.0.0.1:${GO_PROXY_PORT}" \
"${ROOT_DIR}/scripts/bench_memory.sh"

if [[ ! -f "$MEMORY_REPORT" ]]; then
  echo "memory report missing: $MEMORY_REPORT" >&2
  exit 1
fi

export REPORT_PATH LOCK_PATH MEMORY_REPORT
export P95_THRESHOLD_PCT RSS_THRESHOLD_PCT STARTUP_THRESHOLD_PCT
export GO_BIN GO_CONFIG GO_PROXY_PORT RUST_BIN RUST_CONFIG RUST_PROXY_PORT
export LOCAL_URL LOCAL_HTTP_PORT STARTUP_WARMUP_RUNS STARTUP_SAMPLE_RUNS WARMUP_REQUESTS SAMPLE_REQUESTS
export REQUEST_CONNECT_TIMEOUT_SEC REQUEST_MAX_TIME_SEC
export RUST_BUILD_FEATURES RUST_BUILD_ENABLED PERF_WORK_DIR PERF_ROUNDS ROUND_TRIM_EACH_SIDE
export RUST_P95_ROUNDS_CSV="$(IFS=,; echo "${RUST_P95_ROUNDS[*]}")"
export GO_P95_ROUNDS_CSV="$(IFS=,; echo "${GO_P95_ROUNDS[*]}")"
export RUST_STARTUP_ROUNDS_CSV="$(IFS=,; echo "${RUST_STARTUP_ROUNDS[*]}")"
export GO_STARTUP_ROUNDS_CSV="$(IFS=,; echo "${GO_STARTUP_ROUNDS[*]}")"
export RUST_SAMPLE_COUNT_ROUNDS_CSV="$(IFS=,; echo "${RUST_SAMPLE_COUNT_ROUNDS[*]}")"
export GO_SAMPLE_COUNT_ROUNDS_CSV="$(IFS=,; echo "${GO_SAMPLE_COUNT_ROUNDS[*]}")"
export RUST_STARTUP_SAMPLE_COUNT_ROUNDS_CSV="$(IFS=,; echo "${RUST_STARTUP_SAMPLE_COUNT_ROUNDS[*]}")"
export GO_STARTUP_SAMPLE_COUNT_ROUNDS_CSV="$(IFS=,; echo "${GO_STARTUP_SAMPLE_COUNT_ROUNDS[*]}")"
export ROUND_DIRS_CSV="$(IFS=,; echo "${ROUND_DIRS[*]}")"
python3 - <<'PY'
import json
import statistics
import os.path
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

p95_limit = float(os.environ.get("P95_THRESHOLD_PCT", "5"))
rss_limit = float(os.environ.get("RSS_THRESHOLD_PCT", "10"))
startup_limit = float(os.environ.get("STARTUP_THRESHOLD_PCT", "10"))
perf_rounds = int(os.environ.get("PERF_ROUNDS", "1"))
round_trim_each_side = int(os.environ.get("ROUND_TRIM_EACH_SIDE", "0"))

def parse_float_csv(key):
    raw = os.environ.get(key, "").strip()
    if not raw:
        return []
    vals = []
    for item in raw.split(","):
        item = item.strip()
        if not item:
            continue
        vals.append(float(item))
    return vals

def parse_int_csv(key):
    raw = os.environ.get(key, "").strip()
    if not raw:
        return []
    vals = []
    for item in raw.split(","):
        item = item.strip()
        if not item:
            continue
        vals.append(int(item))
    return vals

def parse_str_csv(key):
    raw = os.environ.get(key, "").strip()
    if not raw:
        return []
    vals = []
    for item in raw.split(","):
        item = item.strip()
        if item:
            vals.append(item)
    return vals

def robust_median(vals, trim_each_side):
    if not vals:
        return 0.0, [], [], 0
    sorted_vals = sorted(vals)
    max_trim = max((len(sorted_vals) - 1) // 2, 0)
    applied_trim = min(trim_each_side, max_trim)
    if applied_trim == 0:
        trimmed = sorted_vals[:]
    else:
        trimmed = sorted_vals[applied_trim:len(sorted_vals) - applied_trim]
    if not trimmed:
        trimmed = sorted_vals[:]
        applied_trim = 0
    return float(statistics.median(trimmed)), sorted_vals, trimmed, applied_trim

rust_p95_rounds = parse_float_csv("RUST_P95_ROUNDS_CSV")
go_p95_rounds = parse_float_csv("GO_P95_ROUNDS_CSV")
rust_startup_rounds = parse_float_csv("RUST_STARTUP_ROUNDS_CSV")
go_startup_rounds = parse_float_csv("GO_STARTUP_ROUNDS_CSV")
rust_sample_count_rounds = parse_int_csv("RUST_SAMPLE_COUNT_ROUNDS_CSV")
go_sample_count_rounds = parse_int_csv("GO_SAMPLE_COUNT_ROUNDS_CSV")
rust_startup_sample_count_rounds = parse_int_csv("RUST_STARTUP_SAMPLE_COUNT_ROUNDS_CSV")
go_startup_sample_count_rounds = parse_int_csv("GO_STARTUP_SAMPLE_COUNT_ROUNDS_CSV")
round_dirs = parse_str_csv("ROUND_DIRS_CSV")

rust_p95, rust_p95_sorted, rust_p95_trimmed, p95_trim_applied = robust_median(rust_p95_rounds, round_trim_each_side)
go_p95, go_p95_sorted, go_p95_trimmed, _ = robust_median(go_p95_rounds, round_trim_each_side)
rust_startup, rust_startup_sorted, rust_startup_trimmed, startup_trim_applied = robust_median(rust_startup_rounds, round_trim_each_side)
go_startup, go_startup_sorted, go_startup_trimmed, _ = robust_median(go_startup_rounds, round_trim_each_side)

warmup_requests = int(os.environ.get("WARMUP_REQUESTS", "0"))
sample_requests = int(os.environ.get("SAMPLE_REQUESTS", "0"))
startup_warmup_runs = int(os.environ.get("STARTUP_WARMUP_RUNS", "0"))
startup_sample_runs = int(os.environ.get("STARTUP_SAMPLE_RUNS", "0"))

errors = []
if len(rust_p95_rounds) != perf_rounds:
    errors.append("rust_p95_round_count_mismatch")
if len(go_p95_rounds) != perf_rounds:
    errors.append("go_p95_round_count_mismatch")
if len(rust_startup_rounds) != perf_rounds:
    errors.append("rust_startup_round_count_mismatch")
if len(go_startup_rounds) != perf_rounds:
    errors.append("go_startup_round_count_mismatch")
if len(rust_sample_count_rounds) != perf_rounds:
    errors.append("rust_sample_count_round_count_mismatch")
if len(go_sample_count_rounds) != perf_rounds:
    errors.append("go_sample_count_round_count_mismatch")
if len(rust_startup_sample_count_rounds) != perf_rounds:
    errors.append("rust_startup_sample_count_round_count_mismatch")
if len(go_startup_sample_count_rounds) != perf_rounds:
    errors.append("go_startup_sample_count_round_count_mismatch")
if len(round_dirs) != perf_rounds:
    errors.append("round_dir_count_mismatch")

if go_p95 <= 0:
    errors.append("go_p95_unavailable")
if go_peak <= 0:
    errors.append("go_rss_peak_unavailable")
if go_startup <= 0:
    errors.append("go_startup_unavailable")
if any(v != sample_requests for v in rust_sample_count_rounds):
    errors.append("rust_sample_count_mismatch")
if any(v != sample_requests for v in go_sample_count_rounds):
    errors.append("go_sample_count_mismatch")
if any(v != startup_sample_runs for v in rust_startup_sample_count_rounds):
    errors.append("rust_startup_sample_count_mismatch")
if any(v != startup_sample_runs for v in go_startup_sample_count_rounds):
    errors.append("go_startup_sample_count_mismatch")

rust_sample_count = rust_sample_count_rounds[0] if rust_sample_count_rounds else 0
go_sample_count = go_sample_count_rounds[0] if go_sample_count_rounds else 0
rust_startup_sample_count = rust_startup_sample_count_rounds[0] if rust_startup_sample_count_rounds else 0
go_startup_sample_count = go_startup_sample_count_rounds[0] if go_startup_sample_count_rounds else 0

if errors:
    payload = {
        "generated_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "pass": False,
        "reason": "metrics_unavailable",
        "errors": errors,
        "aggregation": {
            "method": "median_of_trimmed_rounds",
            "rounds": perf_rounds,
            "round_trim_each_side_requested": round_trim_each_side,
            "round_trim_each_side_applied": {
                "latency_p95": p95_trim_applied,
                "startup": startup_trim_applied,
            },
        },
        "metrics": {
            "latency_p95_ms": {"rust": rust_p95, "go": go_p95},
            "rss_peak_kb": {"rust": rust_peak, "go": go_peak},
            "startup_ms": {"rust": rust_startup, "go": go_startup},
        },
        "metrics_rounds": {
            "latency_p95_ms": {"rust": rust_p95_rounds, "go": go_p95_rounds},
            "startup_ms": {"rust": rust_startup_rounds, "go": go_startup_rounds},
        },
        "inputs": {
            "lock_file": os.path.abspath(os.environ["LOCK_PATH"]),
            "perf_work_dir": os.path.abspath(os.environ["PERF_WORK_DIR"]),
            "perf_rounds": perf_rounds,
            "round_trim_each_side": round_trim_each_side,
            "sample_requests": sample_requests,
            "warmup_requests": warmup_requests,
            "startup_sample_runs": startup_sample_runs,
            "startup_warmup_runs": startup_warmup_runs,
            "sample_count": {"rust": rust_sample_count, "go": go_sample_count},
            "sample_count_per_round": {
                "rust": rust_sample_count_rounds,
                "go": go_sample_count_rounds,
            },
            "startup_sample_count": {
                "rust": rust_startup_sample_count,
                "go": go_startup_sample_count,
            },
            "startup_sample_count_per_round": {
                "rust": rust_startup_sample_count_rounds,
                "go": go_startup_sample_count_rounds,
            },
            "round_dirs": [os.path.abspath(p) for p in round_dirs],
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
latency_round_reg = []
for rust_val, go_val in zip(rust_p95_rounds, go_p95_rounds):
    if go_val > 0:
        latency_round_reg.append(((rust_val - go_val) / go_val) * 100.0)
    else:
        latency_round_reg.append(None)

startup_round_reg = []
for rust_val, go_val in zip(rust_startup_rounds, go_startup_rounds):
    if go_val > 0:
        startup_round_reg.append(((rust_val - go_val) / go_val) * 100.0)
    else:
        startup_round_reg.append(None)

payload = {
    "generated_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
    "pass": pass_flag,
    "aggregation": {
        "method": "median_of_trimmed_rounds",
        "rounds": perf_rounds,
        "round_trim_each_side_requested": round_trim_each_side,
        "round_trim_each_side_applied": {
            "latency_p95": p95_trim_applied,
            "startup": startup_trim_applied,
        },
        "sorted_round_values_ms": {
            "latency_p95": {"rust": rust_p95_sorted, "go": go_p95_sorted},
            "startup": {"rust": rust_startup_sorted, "go": go_startup_sorted},
        },
        "trimmed_round_values_ms": {
            "latency_p95": {"rust": rust_p95_trimmed, "go": go_p95_trimmed},
            "startup": {"rust": rust_startup_trimmed, "go": go_startup_trimmed},
        },
    },
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
    "metrics_rounds": {
        "latency_p95_ms": {"rust": rust_p95_rounds, "go": go_p95_rounds},
        "startup_ms": {"rust": rust_startup_rounds, "go": go_startup_rounds},
    },
    "regressions_pct": {
        "latency_p95": p95_reg,
        "rss_peak": rss_reg,
        "startup": startup_reg,
    },
    "regressions_rounds_pct": {
        "latency_p95": latency_round_reg,
        "startup": startup_round_reg,
    },
    "checks": checks,
    "inputs": {
        "lock_file": os.path.abspath(os.environ["LOCK_PATH"]),
        "perf_work_dir": os.path.abspath(os.environ["PERF_WORK_DIR"]),
        "perf_rounds": perf_rounds,
        "round_trim_each_side": round_trim_each_side,
        "go_bin": os.path.abspath(os.environ["GO_BIN"]),
        "go_config": os.path.abspath(os.environ["GO_CONFIG"]),
        "go_proxy_port": int(os.environ["GO_PROXY_PORT"]),
        "rust_bin": os.path.abspath(os.environ["RUST_BIN"]),
        "rust_config": os.path.abspath(os.environ["RUST_CONFIG"]),
        "rust_proxy_port": int(os.environ["RUST_PROXY_PORT"]),
        "rust_build_features": os.environ.get("RUST_BUILD_FEATURES", ""),
        "rust_build_enabled": int(os.environ.get("RUST_BUILD_ENABLED", "0")),
        "startup_warmup_runs": startup_warmup_runs,
        "startup_sample_runs": startup_sample_runs,
        "warmup_requests": warmup_requests,
        "sample_requests": sample_requests,
        "sample_count": {"rust": rust_sample_count, "go": go_sample_count},
        "sample_count_per_round": {
            "rust": rust_sample_count_rounds,
            "go": go_sample_count_rounds,
        },
        "startup_sample_count": {
            "rust": rust_startup_sample_count,
            "go": go_startup_sample_count,
        },
        "startup_sample_count_per_round": {
            "rust": rust_startup_sample_count_rounds,
            "go": go_startup_sample_count_rounds,
        },
        "request_connect_timeout_sec": int(os.environ["REQUEST_CONNECT_TIMEOUT_SEC"]),
        "request_max_time_sec": int(os.environ["REQUEST_MAX_TIME_SEC"]),
        "memory_report": os.path.abspath(memory_report),
        "local_target": os.environ.get("LOCAL_URL", ""),
        "round_dirs": [os.path.abspath(p) for p in round_dirs],
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
