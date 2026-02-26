#!/usr/bin/env bash
# Memory usage benchmark for singbox-rust and Go sing-box
# Measures RSS/FD at idle, 100 connections, and 1000 connections.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
REPORT_DIR="$ROOT_DIR/reports/benchmarks"
REPORT_FILE="${BENCH_MEMORY_REPORT_FILE:-$REPORT_DIR/memory_comparison.json}"
WORK_DIR="${BENCH_MEMORY_WORK_DIR:-$REPORT_DIR/tmp}"

mkdir -p "$REPORT_DIR" "$WORK_DIR"

RUST_BINARY="${SINGBOX_BINARY:-$ROOT_DIR/target/debug/run}"
RUST_CONFIG="${SINGBOX_CONFIG:-$ROOT_DIR/labs/interop-lab/configs/bench_rust.json}"
GO_SRC_DIR="$ROOT_DIR/go_fork_source/sing-box-1.12.14"
GO_BINARY="${GO_BINARY:-$GO_SRC_DIR/sing-box}"
GO_CONFIG="${GO_CONFIG:-$ROOT_DIR/labs/interop-lab/configs/bench_go.json}"
RUST_PROXY_ADDR="${RUST_PROXY_ADDR:-127.0.0.1:11810}"
GO_PROXY_ADDR="${GO_PROXY_ADDR:-127.0.0.1:11811}"
TARGET_URL="${BENCH_TARGET_URL:-http://httpbin.org/delay/25}"

get_rss_kb() {
    local pid="$1"
    if [[ "$OSTYPE" == "darwin"* ]]; then
        ps -o rss= -p "$pid" 2>/dev/null | tr -d ' ' || echo "0"
    else
        awk '/VmRSS/{print $2}' "/proc/$pid/status" 2>/dev/null || echo "0"
    fi
}

get_fd_count() {
    local pid="$1"
    if [[ "$OSTYPE" == "darwin"* ]]; then
        lsof -p "$pid" 2>/dev/null | wc -l | tr -d ' ' || echo "0"
    else
        ls "/proc/$pid/fd" 2>/dev/null | wc -l | tr -d ' ' || echo "0"
    fi
}

check_proxy_available() {
    local proxy_addr="$1"
    local host="${proxy_addr%%:*}"
    local port="${proxy_addr##*:}"
    if command -v nc >/dev/null 2>&1; then
        nc -z -w 2 "$host" "$port" >/dev/null 2>&1
        return $?
    fi
    if command -v curl >/dev/null 2>&1; then
        curl -s --socks5-hostname "$proxy_addr" --connect-timeout 2 --max-time 3 \
            "http://httpbin.org/status/200" >/dev/null 2>&1
        return $?
    fi
    return 1
}

generate_connections() {
    local pid="$1"
    local count="$2"
    local proxy_addr="$3"
    local pids=()

    for i in $(seq 1 "$count"); do
        curl -s --socks5-hostname "$proxy_addr" \
            --connect-timeout 5 --max-time 30 \
            "$TARGET_URL" >/dev/null 2>&1 &
        pids+=("$!")
        if (( i % 100 == 0 )); then
            sleep 0.5
        fi
    done

    sleep 5
    local rss
    local fd
    rss="$(get_rss_kb "$pid")"
    fd="$(get_fd_count "$pid")"

    for p in "${pids[@]}"; do
        kill "$p" 2>/dev/null || true
    done
    for p in "${pids[@]}"; do
        wait "$p" 2>/dev/null || true
    done
    sleep 1

    echo "${rss}:${fd}"
}

stop_process() {
    local pid="$1"
    kill "$pid" 2>/dev/null || true
    for _ in $(seq 1 20); do
        if ! kill -0 "$pid" 2>/dev/null; then
            wait "$pid" 2>/dev/null || true
            return
        fi
        sleep 0.25
    done
    kill -KILL "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
}

set_unmeasured() {
    local prefix="$1"
    local status="$2"
    local reason="$3"
    eval "${prefix}_STATUS=\"$status\""
    eval "${prefix}_REASON=\"$reason\""
    eval "${prefix}_IDLE_RSS=0"
    eval "${prefix}_IDLE_FD=0"
    eval "${prefix}_C100_RSS=0"
    eval "${prefix}_C100_FD=0"
    eval "${prefix}_C100_DELTA=0"
    eval "${prefix}_C100_NOTE=\"unavailable\""
    eval "${prefix}_C1000_RSS=0"
    eval "${prefix}_C1000_FD=0"
    eval "${prefix}_C1000_DELTA=0"
    eval "${prefix}_C1000_NOTE=\"unavailable\""
}

measure_core() {
    local prefix="$1"
    local start_cmd="$2"
    local proxy_addr="$3"

    eval "$start_cmd" >"${WORK_DIR}/${prefix}_bench.log" 2>&1 &
    local pid=$!
    sleep 3

    if ! kill -0 "$pid" 2>/dev/null; then
        set_unmeasured "$prefix" "env_limited" "process_failed_to_start"
        return
    fi

    eval "${prefix}_STATUS=\"pass\""
    eval "${prefix}_REASON=\"\""

    local idle_rss idle_fd
    idle_rss="$(get_rss_kb "$pid")"
    idle_fd="$(get_fd_count "$pid")"

    eval "${prefix}_IDLE_RSS=$idle_rss"
    eval "${prefix}_IDLE_FD=$idle_fd"

    local c100_rss="$idle_rss" c100_fd="$idle_fd" c100_note="fallback_to_idle"
    local c1000_rss="$idle_rss" c1000_fd="$idle_fd" c1000_note="fallback_to_idle"

    if command -v curl >/dev/null 2>&1 && check_proxy_available "$proxy_addr"; then
        local m100 m1000
        m100="$(generate_connections "$pid" 100 "$proxy_addr")" || true
        m1000="$(generate_connections "$pid" 1000 "$proxy_addr")" || true
        if [ -n "$m100" ] && [ "$m100" != ":" ]; then
            c100_rss="${m100%%:*}"
            c100_fd="${m100##*:}"
            c100_note="measured"
        else
            c100_note="generator_failed"
        fi
        if [ -n "$m1000" ] && [ "$m1000" != ":" ]; then
            c1000_rss="${m1000%%:*}"
            c1000_fd="${m1000##*:}"
            c1000_note="measured"
        else
            c1000_note="generator_failed"
        fi
    else
        eval "${prefix}_STATUS=\"env_limited\""
        eval "${prefix}_REASON=\"proxy_unreachable_or_curl_missing\""
        c100_note="proxy_unreachable"
        c1000_note="proxy_unreachable"
    fi

    local c100_delta c1000_delta
    c100_delta=$(( c100_rss - idle_rss ))
    c1000_delta=$(( c1000_rss - idle_rss ))

    eval "${prefix}_C100_RSS=$c100_rss"
    eval "${prefix}_C100_FD=$c100_fd"
    eval "${prefix}_C100_DELTA=$c100_delta"
    eval "${prefix}_C100_NOTE=\"$c100_note\""
    eval "${prefix}_C1000_RSS=$c1000_rss"
    eval "${prefix}_C1000_FD=$c1000_fd"
    eval "${prefix}_C1000_DELTA=$c1000_delta"
    eval "${prefix}_C1000_NOTE=\"$c1000_note\""

    stop_process "$pid"
}

if [ ! -f "$RUST_BINARY" ]; then
    echo "[bench-memory] Rust binary missing, building..."
    cargo build -p app --features acceptance --bin run >/dev/null 2>&1 || true
fi

if [ ! -f "$RUST_BINARY" ]; then
    set_unmeasured "RUST" "env_limited" "rust_binary_missing"
else
    measure_core "RUST" "\"$RUST_BINARY\" --config \"$RUST_CONFIG\"" "$RUST_PROXY_ADDR"
fi

if [ ! -f "$GO_BINARY" ] && [ -d "$GO_SRC_DIR" ] && command -v go >/dev/null 2>&1; then
    echo "[bench-memory] Go binary missing, building..."
    (cd "$GO_SRC_DIR" && go build -o sing-box ./cmd/sing-box) >/dev/null 2>&1 || true
fi

if [ ! -f "$GO_BINARY" ]; then
    set_unmeasured "GO" "env_limited" "go_binary_missing"
else
    measure_core "GO" "\"$GO_BINARY\" run -c \"$GO_CONFIG\"" "$GO_PROXY_ADDR"
fi

export REPORT_FILE RUST_BINARY RUST_CONFIG GO_BINARY GO_CONFIG
export \
    RUST_STATUS RUST_REASON RUST_IDLE_RSS RUST_IDLE_FD RUST_C100_RSS RUST_C100_FD RUST_C100_DELTA RUST_C100_NOTE RUST_C1000_RSS RUST_C1000_FD RUST_C1000_DELTA RUST_C1000_NOTE \
    GO_STATUS GO_REASON GO_IDLE_RSS GO_IDLE_FD GO_C100_RSS GO_C100_FD GO_C100_DELTA GO_C100_NOTE GO_C1000_RSS GO_C1000_FD GO_C1000_DELTA GO_C1000_NOTE
python3 - << 'PYTHON_SCRIPT'
import json
import os
from datetime import datetime, timezone

def load(prefix: str):
    return {
        "status": os.environ.get(f"{prefix}_STATUS", "env_limited"),
        "reason": os.environ.get(f"{prefix}_REASON", ""),
        "binary": os.environ.get(f"{prefix}_BINARY", ""),
        "config": os.environ.get(f"{prefix}_CONFIG", ""),
        "measurements": {
            "idle": {
                "rss_kb": int(os.environ.get(f"{prefix}_IDLE_RSS", "0")),
                "fd_count": int(os.environ.get(f"{prefix}_IDLE_FD", "0")),
            },
            "connections_100": {
                "rss_kb": int(os.environ.get(f"{prefix}_C100_RSS", "0")),
                "fd_count": int(os.environ.get(f"{prefix}_C100_FD", "0")),
                "delta_over_idle_kb": int(os.environ.get(f"{prefix}_C100_DELTA", "0")),
                "note": os.environ.get(f"{prefix}_C100_NOTE", ""),
            },
            "connections_1000": {
                "rss_kb": int(os.environ.get(f"{prefix}_C1000_RSS", "0")),
                "fd_count": int(os.environ.get(f"{prefix}_C1000_FD", "0")),
                "delta_over_idle_kb": int(os.environ.get(f"{prefix}_C1000_DELTA", "0")),
                "note": os.environ.get(f"{prefix}_C1000_NOTE", ""),
            },
        },
    }

payload = {
    "timestamp": datetime.now(timezone.utc).isoformat(),
    "platform": os.uname().sysname + "-" + os.uname().machine,
    "rust": load("RUST"),
    "go": load("GO"),
}

report_file = os.environ["REPORT_FILE"]
os.makedirs(os.path.dirname(report_file), exist_ok=True)
with open(report_file, "w", encoding="utf-8") as f:
    json.dump(payload, f, indent=2, ensure_ascii=False)

print(f"Report written: {report_file}")
PYTHON_SCRIPT

echo "[bench-memory] completed"
