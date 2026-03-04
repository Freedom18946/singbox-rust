#!/usr/bin/env bash
if [[ "${BASH_VERSINFO[0]:-0}" -lt 4 ]]; then
    _script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    if _bash4="$("$_script_dir/../lib/bash4_detect.sh" 2>/dev/null)"; then
        exec "$_bash4" "$0" "$@"
    fi
    echo "ERROR: bash >= 4 is required" >&2
    exit 2
fi

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)"
OUT_DIR="$PROJECT_ROOT/reports/stability/tun_macos_longrun/$RUN_ID"
LATEST_JSON="$PROJECT_ROOT/reports/stability/tun_macos_longrun.json"
REPORT_JSON="$OUT_DIR/tun_macos_longrun_report.json"
LOG_FILE="$OUT_DIR/tun_macos_longrun.log"

DURATION_SEC="${TUN_MACOS_LONGRUN_DURATION_SEC:-600}"
TCP_TOTAL="${TUN_MACOS_LONGRUN_TCP_TOTAL:-10000}"
TCP_WORKERS="${TUN_MACOS_LONGRUN_TCP_WORKERS:-200}"
UDP_TOTAL="${TUN_MACOS_LONGRUN_UDP_TOTAL:-1200}"
DNS_TOTAL="${TUN_MACOS_LONGRUN_DNS_TOTAL:-800}"
DNS_JITTER_MS="${TUN_MACOS_LONGRUN_DNS_JITTER_MS:-200}"
UDP_JITTER_MS="${TUN_MACOS_LONGRUN_UDP_JITTER_MS:-120}"
SAMPLE_INTERVAL_SEC="${TUN_MACOS_LONGRUN_SAMPLE_INTERVAL_SEC:-2}"

SERVER_HOST="127.0.0.1"
TCP_PORT="${TUN_MACOS_LONGRUN_TCP_PORT:-28081}"
UDP_PORT="${TUN_MACOS_LONGRUN_UDP_PORT:-28082}"
DNS_PORT="${TUN_MACOS_LONGRUN_DNS_PORT:-28083}"

TARGET_PID=""
TARGET_CMD=""
FAKE=0

SERVICE_PID=""
TARGET_STARTED_PID=""
SAMPLER_PID=""
SAMPLE_JSON="$OUT_DIR/process_max.json"
SAMPLE_CSV="$OUT_DIR/process_samples.csv"

declare -a CASE_LINES=()

usage() {
    cat <<'EOF'
Usage: scripts/test/tun_macos_longrun.sh [options]

macOS TUN longrun profile (L19.4.2):
- 10k TCP connection workload
- UDP jitter workload
- DNS jitter workload
- optional target process resource sampling (RSS/FD/threads)
- output: reports/stability/tun_macos_longrun.json

Options:
  --duration-sec <n>      Upper bound of run duration (default: 600)
  --tcp-total <n>         Total TCP echo connections (default: 10000)
  --tcp-workers <n>       Concurrent workers for TCP phase (default: 200)
  --udp-total <n>         Total UDP datagrams (default: 1200)
  --dns-total <n>         Total DNS queries (default: 800)
  --dns-jitter-ms <n>     Max per-query DNS jitter (default: 200)
  --udp-jitter-ms <n>     Max per-packet UDP jitter (default: 120)
  --target-pid <pid>      Existing process pid to sample
  --target-cmd <cmd>      Spawn command and sample its process
  --out-dir <dir>         Artifacts directory
  --latest-json <path>    Latest summary report path
  --fake                  Generate deterministic fake pass report
  -h, --help              Show this help

Exit codes:
  0  PASS
  1  FAIL
  2  Invalid arguments
  77 SKIP (non-macos / missing dependencies)
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --duration-sec)
            DURATION_SEC="${2:-}"
            shift 2
            ;;
        --tcp-total)
            TCP_TOTAL="${2:-}"
            shift 2
            ;;
        --tcp-workers)
            TCP_WORKERS="${2:-}"
            shift 2
            ;;
        --udp-total)
            UDP_TOTAL="${2:-}"
            shift 2
            ;;
        --dns-total)
            DNS_TOTAL="${2:-}"
            shift 2
            ;;
        --dns-jitter-ms)
            DNS_JITTER_MS="${2:-}"
            shift 2
            ;;
        --udp-jitter-ms)
            UDP_JITTER_MS="${2:-}"
            shift 2
            ;;
        --target-pid)
            TARGET_PID="${2:-}"
            shift 2
            ;;
        --target-cmd)
            TARGET_CMD="${2:-}"
            shift 2
            ;;
        --out-dir)
            OUT_DIR="${2:-}"
            shift 2
            ;;
        --latest-json)
            LATEST_JSON="${2:-}"
            shift 2
            ;;
        --fake)
            FAKE=1
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "ERROR: unknown argument: $1" >&2
            usage >&2
            exit 2
            ;;
    esac
done

for v in DURATION_SEC TCP_TOTAL TCP_WORKERS UDP_TOTAL DNS_TOTAL DNS_JITTER_MS UDP_JITTER_MS SAMPLE_INTERVAL_SEC; do
    if ! [[ "${!v}" =~ ^[0-9]+$ ]]; then
        echo "ERROR: $v must be an integer" >&2
        exit 2
    fi
done

REPORT_JSON="$OUT_DIR/tun_macos_longrun_report.json"
LOG_FILE="$OUT_DIR/tun_macos_longrun.log"
SAMPLE_JSON="$OUT_DIR/process_max.json"
SAMPLE_CSV="$OUT_DIR/process_samples.csv"

mkdir -p "$OUT_DIR"
exec > >(tee -a "$LOG_FILE") 2>&1

log() {
    echo "[tun-macos-longrun] $*"
}

record_case() {
    local id="$1"
    local desc="$2"
    local status="$3"
    local note="${4:-}"
    CASE_LINES+=("${id}\t${desc}\t${status}\t${note}")
    log "case ${id}: ${status} (${desc}) ${note}"
}

need_cmd() {
    command -v "$1" >/dev/null 2>&1
}

emit_report() {
    local overall="$1"
    local reason="$2"
    local case_file="$OUT_DIR/cases.tsv"
    : >"$case_file"
    for line in "${CASE_LINES[@]:-}"; do
        printf "%b\n" "$line" >>"$case_file"
    done

    python3 - "$REPORT_JSON" "$RUN_ID" "$overall" "$reason" "$OUT_DIR" "$LOG_FILE" "$SAMPLE_JSON" "$SAMPLE_CSV" "$case_file" "$TARGET_PID" "$TARGET_STARTED_PID" <<'PY'
import json
import os
import sys
from datetime import datetime, timezone

(
    report_json,
    run_id,
    overall,
    reason,
    out_dir,
    log_file,
    sample_json,
    sample_csv,
    case_file,
    target_pid,
    started_pid,
) = sys.argv[1:]

cases = []
if os.path.exists(case_file):
    with open(case_file, "r", encoding="utf-8") as f:
        for raw in f:
            raw = raw.rstrip("\n")
            if not raw:
                continue
            parts = raw.split("\t")
            while len(parts) < 4:
                parts.append("")
            cid, desc, status, note = parts[:4]
            cases.append(
                {
                    "id": cid,
                    "description": desc,
                    "status": status,
                    "note": note,
                }
            )

process_max = {}
if os.path.exists(sample_json):
    try:
        with open(sample_json, "r", encoding="utf-8") as f:
            process_max = json.load(f)
    except Exception:
        process_max = {}

summary = {
    "total": len(cases),
    "pass": sum(1 for c in cases if c["status"] == "PASS"),
    "fail": sum(1 for c in cases if c["status"] == "FAIL"),
    "skip": sum(1 for c in cases if c["status"] == "SKIP"),
}

report = {
    "schema_version": "1.0.0",
    "run_id": run_id,
    "generated_at": datetime.now(timezone.utc).isoformat(),
    "profile": "l19.4.2-macos-tun-longrun",
    "overall": overall,
    "reason": reason,
    "target": {
        "pid": int(target_pid) if target_pid.isdigit() else None,
        "spawned_pid": int(started_pid) if started_pid.isdigit() else None,
    },
    "artifacts": {
        "output_dir": out_dir,
        "log_file": log_file,
        "process_max_file": sample_json if os.path.exists(sample_json) else "",
        "process_samples_csv": sample_csv if os.path.exists(sample_csv) else "",
    },
    "process_max": process_max,
    "summary": summary,
    "cases": cases,
}

with open(report_json, "w", encoding="utf-8") as f:
    json.dump(report, f, indent=2, ensure_ascii=False)
    f.write("\n")
PY

    cp "$REPORT_JSON" "$LATEST_JSON"
}

cleanup() {
    set +e
    if [[ -n "$SAMPLER_PID" ]]; then
        kill "$SAMPLER_PID" >/dev/null 2>&1 || true
        wait "$SAMPLER_PID" >/dev/null 2>&1 || true
    fi
    if [[ -n "$TARGET_STARTED_PID" ]]; then
        kill "$TARGET_STARTED_PID" >/dev/null 2>&1 || true
        wait "$TARGET_STARTED_PID" >/dev/null 2>&1 || true
    fi
    if [[ -n "$SERVICE_PID" ]]; then
        kill "$SERVICE_PID" >/dev/null 2>&1 || true
        wait "$SERVICE_PID" >/dev/null 2>&1 || true
    fi
}
trap cleanup EXIT

log "run_id=$RUN_ID"
log "out_dir=$OUT_DIR"

if [[ $FAKE -eq 1 ]]; then
    record_case "fake" "synthetic longrun result" "PASS" "fake mode"
    emit_report "PASS" "fake mode"
    log "report: $REPORT_JSON"
    exit 0
fi

if [[ "$(uname -s)" != "Darwin" ]]; then
    record_case "platform" "macos-only profile gate" "SKIP" "current platform: $(uname -s)"
    emit_report "SKIP" "non-macos platform"
    log "report: $REPORT_JSON"
    exit 77
fi

for cmd in python3; do
    if ! need_cmd "$cmd"; then
        record_case "dep_${cmd}" "dependency check: ${cmd}" "SKIP" "command not found"
        emit_report "SKIP" "missing dependency: $cmd"
        log "report: $REPORT_JSON"
        exit 77
    fi
done

log "starting local workload services"
python3 - "$SERVER_HOST" "$TCP_PORT" "$UDP_PORT" "$DNS_PORT" >/dev/null 2>&1 <<'PY' &
import socket
import struct
import sys
import threading

host = sys.argv[1]
tcp_port = int(sys.argv[2])
udp_port = int(sys.argv[3])
dns_port = int(sys.argv[4])


def tcp_echo():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((host, tcp_port))
    srv.listen(512)
    while True:
        conn, _ = srv.accept()
        threading.Thread(target=handle_tcp, args=(conn,), daemon=True).start()


def handle_tcp(conn):
    with conn:
        while True:
            data = conn.recv(4096)
            if not data:
                return
            conn.sendall(data)


def udp_echo():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((host, udp_port))
    while True:
        data, addr = s.recvfrom(2048)
        s.sendto(data, addr)


def dns_echo():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((host, dns_port))
    while True:
        q, addr = s.recvfrom(2048)
        if len(q) < 12:
            continue
        txid = q[:2]
        qd = q[4:6]
        question = q[12:]
        header = txid + b"\x81\x80" + qd + b"\x00\x01\x00\x00\x00\x00"
        answer = b"\xc0\x0c\x00\x01\x00\x01" + struct.pack("!I", 30) + b"\x00\x04" + socket.inet_aton("1.1.1.1")
        s.sendto(header + question + answer, addr)


threading.Thread(target=tcp_echo, daemon=True).start()
threading.Thread(target=udp_echo, daemon=True).start()
dns_echo()
PY
SERVICE_PID="$!"
sleep 1
if ! kill -0 "$SERVICE_PID" >/dev/null 2>&1; then
    record_case "service_boot" "start local tcp/udp/dns services" "FAIL" "service process exited"
    emit_report "FAIL" "local services failed"
    log "report: $REPORT_JSON"
    exit 1
fi
record_case "service_boot" "start local tcp/udp/dns services" "PASS" "pid=$SERVICE_PID"

if [[ -n "$TARGET_CMD" ]]; then
    log "starting target command"
    bash -lc "$TARGET_CMD" >/dev/null 2>&1 &
    TARGET_STARTED_PID="$!"
    TARGET_PID="$TARGET_STARTED_PID"
    sleep 1
    if ! kill -0 "$TARGET_PID" >/dev/null 2>&1; then
        record_case "target_start" "start target command" "FAIL" "target command exited"
    else
        record_case "target_start" "start target command" "PASS" "pid=$TARGET_PID"
    fi
fi

if [[ -n "$TARGET_PID" ]]; then
    if ! kill -0 "$TARGET_PID" >/dev/null 2>&1; then
        record_case "target_alive" "target process existence" "FAIL" "pid not alive: $TARGET_PID"
    else
        record_case "target_alive" "target process existence" "PASS" "pid=$TARGET_PID"
        "$SCRIPT_DIR/../lib/os_probe.sh" "$TARGET_PID" sampler "$SAMPLE_INTERVAL_SEC" "$SAMPLE_JSON" "$SAMPLE_CSV" &
        SAMPLER_PID="$!"
    fi
else
    record_case "target_alive" "target process existence" "SKIP" "no --target-pid/--target-cmd provided"
fi

log "case: tcp_10k"
if python3 - "$SERVER_HOST" "$TCP_PORT" "$TCP_TOTAL" "$TCP_WORKERS" <<'PY'
import concurrent.futures
import socket
import sys

host = sys.argv[1]
port = int(sys.argv[2])
total = int(sys.argv[3])
workers = int(sys.argv[4])
ok = 0


def once(i):
    payload = f"tcp-{i}".encode()
    try:
        s = socket.create_connection((host, port), timeout=2)
        s.sendall(payload)
        got = s.recv(1024)
        s.close()
        return got == payload
    except Exception:
        return False


with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, workers)) as ex:
    for success in ex.map(once, range(total)):
        if success:
            ok += 1

ratio = (ok / total) if total > 0 else 0.0
print(f"ok={ok} total={total} ratio={ratio:.4f}")
if ratio < 0.99:
    raise SystemExit(1)
PY
then
    record_case "tcp_10k" "10k tcp echo connections" "PASS" "total=$TCP_TOTAL workers=$TCP_WORKERS"
else
    record_case "tcp_10k" "10k tcp echo connections" "FAIL" "success ratio < 99%"
fi

log "case: udp_jitter"
if python3 - "$SERVER_HOST" "$UDP_PORT" "$UDP_TOTAL" "$UDP_JITTER_MS" <<'PY'
import random
import socket
import sys
import time

host = sys.argv[1]
port = int(sys.argv[2])
total = int(sys.argv[3])
jitter_ms = int(sys.argv[4])
ok = 0
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(1.5)
for i in range(total):
    payload = f"udp-{i}".encode()
    s.sendto(payload, (host, port))
    try:
        got, _ = s.recvfrom(2048)
        if got == payload:
            ok += 1
    except Exception:
        pass
    if jitter_ms > 0:
        time.sleep(random.randint(0, jitter_ms) / 1000.0)
ratio = (ok / total) if total > 0 else 0.0
print(f"ok={ok} total={total} ratio={ratio:.4f}")
if ratio < 0.95:
    raise SystemExit(1)
PY
then
    record_case "udp_jitter" "udp echo jitter workload" "PASS" "total=$UDP_TOTAL jitter_ms=$UDP_JITTER_MS"
else
    record_case "udp_jitter" "udp echo jitter workload" "FAIL" "success ratio < 95%"
fi

log "case: dns_jitter"
if python3 - "$SERVER_HOST" "$DNS_PORT" "$DNS_TOTAL" "$DNS_JITTER_MS" <<'PY'
import os
import random
import socket
import sys
import time

host = sys.argv[1]
port = int(sys.argv[2])
total = int(sys.argv[3])
jitter_ms = int(sys.argv[4])
ok = 0

for _ in range(total):
    txid = os.urandom(2)
    qname = b"\x07example\x03com\x00"
    query = txid + b"\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + qname + b"\x00\x01\x00\x01"
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(1.5)
    s.sendto(query, (host, port))
    try:
        data, _ = s.recvfrom(2048)
        if data[:2] == txid and socket.inet_aton("1.1.1.1") in data:
            ok += 1
    except Exception:
        pass
    finally:
        s.close()
    if jitter_ms > 0:
        time.sleep(random.randint(0, jitter_ms) / 1000.0)

ratio = (ok / total) if total > 0 else 0.0
print(f"ok={ok} total={total} ratio={ratio:.4f}")
if ratio < 0.95:
    raise SystemExit(1)
PY
then
    record_case "dns_jitter" "dns jitter workload" "PASS" "total=$DNS_TOTAL jitter_ms=$DNS_JITTER_MS"
else
    record_case "dns_jitter" "dns jitter workload" "FAIL" "success ratio < 95%"
fi

if [[ -n "$TARGET_PID" ]]; then
    if kill -0 "$TARGET_PID" >/dev/null 2>&1; then
        record_case "target_stability" "target process alive after workload" "PASS" "pid=$TARGET_PID"
    else
        record_case "target_stability" "target process alive after workload" "FAIL" "target exited"
    fi
else
    record_case "target_stability" "target process alive after workload" "SKIP" "no target process"
fi

FAIL_COUNT=0
for line in "${CASE_LINES[@]:-}"; do
    status="$(echo -e "$line" | awk -F'\t' '{print $3}')"
    if [[ "$status" == "FAIL" ]]; then
        FAIL_COUNT=$((FAIL_COUNT + 1))
    fi
done

if [[ $FAIL_COUNT -gt 0 ]]; then
    emit_report "FAIL" "one or more test cases failed"
    log "report: $REPORT_JSON"
    exit 1
fi

emit_report "PASS" "all test cases passed"
log "report: $REPORT_JSON"
log "latest: $LATEST_JSON"
exit 0
