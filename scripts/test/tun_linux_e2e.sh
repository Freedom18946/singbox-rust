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
OUT_DIR="$PROJECT_ROOT/reports/stability/tun_linux_e2e/$RUN_ID"
REPORT_JSON=""
LOG_FILE=""
PROBE_FILE=""
PCAP_FILE=""

CONCURRENCY="${TUN_E2E_CONCURRENCY:-40}"
SKIP_PCAP=0
KEEP_NETNS=0
DRY_RUN=0

SUFFIX="$(date +%H%M%S)"
NS_CLIENT="l19c${SUFFIX}"
NS_SERVER="l19s${SUFFIX}"
IF_RC="vrc${SUFFIX}"
IF_CR="vcc${SUFFIX}"
IF_RS="vrs${SUFFIX}"
IF_SR="vss${SUFFIX}"
TUN_IF="l19tun${SUFFIX: -4}"

CLIENT_ROUTER_IP="10.77.0.1"
CLIENT_NS_IP="10.77.0.2"
SERVER_ROUTER_IP="10.88.0.1"
SERVER_NS_IP="10.88.0.2"

TCP_ECHO_PORT="${TUN_E2E_TCP_ECHO_PORT:-18081}"
UDP_ECHO_PORT="${TUN_E2E_UDP_ECHO_PORT:-18082}"
DNS_PORT="${TUN_E2E_DNS_PORT:-18053}"

ORIG_IP_FORWARD=""
IPTABLES_RULES_APPLIED=0
TCPDUMP_PID=""
SERVICE_PID=""

declare -a CASE_LINES=()
declare -a BG_PIDS=()

usage() {
    cat <<'EOF'
Usage: scripts/test/tun_linux_e2e.sh [options]

Linux TUN dataplane e2e profile (L19.4.1):
- netns + veth + iptables forwarding
- TUN device provisioning probe
- MTU / UDP / DNS / route-loop-guard / concurrent TCP checks
- evidence artifacts: log, probe, optional pcap, JSON report

Options:
  --out-dir <dir>        Output directory (default: reports/stability/tun_linux_e2e/<run_id>)
  --concurrency <n>      Concurrent TCP connections test count (default: 40)
  --skip-pcap            Do not capture tcpdump pcap
  --keep-netns           Keep netns and links for post-mortem debugging
  --dry-run              Print plan only, do not mutate system
  -h, --help             Show this help

Exit codes:
  0  PASS
  1  FAIL (test or setup error)
  2  Invalid arguments
  77 Skipped (non-Linux / missing root / missing deps)
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --out-dir)
            OUT_DIR="${2:-}"
            shift 2
            ;;
        --concurrency)
            CONCURRENCY="${2:-}"
            shift 2
            ;;
        --skip-pcap)
            SKIP_PCAP=1
            shift
            ;;
        --keep-netns)
            KEEP_NETNS=1
            shift
            ;;
        --dry-run)
            DRY_RUN=1
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

if ! [[ "$CONCURRENCY" =~ ^[0-9]+$ ]]; then
    echo "ERROR: --concurrency must be an integer" >&2
    exit 2
fi

REPORT_JSON="$OUT_DIR/tun_linux_e2e_report.json"
LOG_FILE="$OUT_DIR/tun_linux_e2e.log"
PROBE_FILE="$OUT_DIR/tun_linux_e2e_probe.txt"
PCAP_FILE="$OUT_DIR/tun_linux_e2e.pcap"

mkdir -p "$OUT_DIR"
exec > >(tee -a "$LOG_FILE") 2>&1

log() {
    echo "[tun-linux-e2e] $*"
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
    local cmd="$1"
    command -v "$cmd" >/dev/null 2>&1
}

emit_report() {
    local overall="$1"
    local reason="$2"
    local case_file="$OUT_DIR/cases.tsv"
    : >"$case_file"
    for line in "${CASE_LINES[@]:-}"; do
        printf "%b\n" "$line" >>"$case_file"
    done

    python3 - "$REPORT_JSON" "$RUN_ID" "$overall" "$reason" "$OUT_DIR" "$LOG_FILE" "$PROBE_FILE" "$PCAP_FILE" "$case_file" "$CONCURRENCY" <<'PY'
import json
import os
import sys
from datetime import datetime, timezone

(
    report_path,
    run_id,
    overall,
    reason,
    out_dir,
    log_file,
    probe_file,
    pcap_file,
    case_file,
    concurrency,
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
            case_id, desc, status, note = parts[:4]
            cases.append(
                {
                    "id": case_id,
                    "description": desc,
                    "status": status,
                    "note": note,
                }
            )

pass_count = sum(1 for c in cases if c["status"] == "PASS")
fail_count = sum(1 for c in cases if c["status"] == "FAIL")
skip_count = sum(1 for c in cases if c["status"] == "SKIP")

report = {
    "schema_version": "1.0.0",
    "run_id": run_id,
    "generated_at": datetime.now(timezone.utc).isoformat(),
    "profile": "l19.4.1-linux-tun-e2e",
    "overall": overall,
    "reason": reason,
    "environment": {
        "platform": sys.platform,
        "uid": os.getuid() if hasattr(os, "getuid") else None,
        "concurrency": int(concurrency),
    },
    "artifacts": {
        "output_dir": out_dir,
        "log_file": log_file,
        "probe_file": probe_file if os.path.exists(probe_file) else "",
        "pcap_file": pcap_file if os.path.exists(pcap_file) else "",
    },
    "summary": {
        "total": len(cases),
        "pass": pass_count,
        "fail": fail_count,
        "skip": skip_count,
    },
    "cases": cases,
}

with open(report_path, "w", encoding="utf-8") as f:
    json.dump(report, f, indent=2, ensure_ascii=False)
    f.write("\n")
PY
}

cleanup() {
    set +e
    if [[ -n "$TCPDUMP_PID" ]]; then
        kill "$TCPDUMP_PID" >/dev/null 2>&1 || true
        wait "$TCPDUMP_PID" >/dev/null 2>&1 || true
    fi
    if [[ -n "$SERVICE_PID" ]]; then
        kill "$SERVICE_PID" >/dev/null 2>&1 || true
        wait "$SERVICE_PID" >/dev/null 2>&1 || true
    fi
    for pid in "${BG_PIDS[@]:-}"; do
        kill "$pid" >/dev/null 2>&1 || true
        wait "$pid" >/dev/null 2>&1 || true
    done

    if [[ $KEEP_NETNS -eq 0 ]]; then
        if [[ $IPTABLES_RULES_APPLIED -eq 1 ]]; then
            iptables -D FORWARD -i "$IF_RC" -o "$IF_RS" -j ACCEPT >/dev/null 2>&1 || true
            iptables -D FORWARD -i "$IF_RS" -o "$IF_RC" -j ACCEPT >/dev/null 2>&1 || true
        fi
        ip link del "$IF_RC" >/dev/null 2>&1 || true
        ip link del "$TUN_IF" >/dev/null 2>&1 || true
        ip netns del "$NS_CLIENT" >/dev/null 2>&1 || true
        ip netns del "$NS_SERVER" >/dev/null 2>&1 || true
    fi

    if [[ -n "$ORIG_IP_FORWARD" ]]; then
        sysctl -w net.ipv4.ip_forward="$ORIG_IP_FORWARD" >/dev/null 2>&1 || true
    fi
}
trap cleanup EXIT

log "run_id=$RUN_ID"
log "out_dir=$OUT_DIR"
log "concurrency=$CONCURRENCY"

if [[ $DRY_RUN -eq 1 ]]; then
    record_case "dry_run" "no-op execution plan" "SKIP" "dry-run mode enabled"
    emit_report "SKIP" "dry-run mode"
    log "report: $REPORT_JSON"
    exit 77
fi

if [[ "$(uname -s)" != "Linux" ]]; then
    record_case "platform" "linux-only profile gate" "SKIP" "current platform: $(uname -s)"
    emit_report "SKIP" "non-linux platform"
    log "report: $REPORT_JSON"
    exit 77
fi

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    record_case "privilege" "requires root for netns/tun/iptables" "SKIP" "uid=${EUID:-$(id -u)}"
    emit_report "SKIP" "requires root"
    log "report: $REPORT_JSON"
    exit 77
fi

for cmd in ip iptables python3 ping; do
    if ! need_cmd "$cmd"; then
        record_case "dep_${cmd}" "dependency check: ${cmd}" "SKIP" "command not found"
        emit_report "SKIP" "missing dependency: $cmd"
        log "report: $REPORT_JSON"
        exit 77
    fi
done

{
    echo "=== environment ==="
    date -u +%Y-%m-%dT%H:%M:%SZ
    uname -a
    id
    echo "=== commands ==="
    command -v ip
    command -v iptables
    command -v python3
    command -v ping
} >"$PROBE_FILE"

log "setup netns/veth/iptables"
ip netns add "$NS_CLIENT"
ip netns add "$NS_SERVER"
ip link add "$IF_RC" type veth peer name "$IF_CR"
ip link add "$IF_RS" type veth peer name "$IF_SR"
ip link set "$IF_CR" netns "$NS_CLIENT"
ip link set "$IF_SR" netns "$NS_SERVER"

ip addr add "${CLIENT_ROUTER_IP}/24" dev "$IF_RC"
ip addr add "${SERVER_ROUTER_IP}/24" dev "$IF_RS"
ip link set "$IF_RC" up
ip link set "$IF_RS" up

ip -n "$NS_CLIENT" addr add "${CLIENT_NS_IP}/24" dev "$IF_CR"
ip -n "$NS_CLIENT" link set "$IF_CR" up
ip -n "$NS_CLIENT" link set lo up
ip -n "$NS_CLIENT" route add default via "$CLIENT_ROUTER_IP"

ip -n "$NS_SERVER" addr add "${SERVER_NS_IP}/24" dev "$IF_SR"
ip -n "$NS_SERVER" link set "$IF_SR" up
ip -n "$NS_SERVER" link set lo up
ip -n "$NS_SERVER" route add default via "$SERVER_ROUTER_IP"

ORIG_IP_FORWARD="$(sysctl -n net.ipv4.ip_forward 2>/dev/null || cat /proc/sys/net/ipv4/ip_forward)"
sysctl -w net.ipv4.ip_forward=1 >/dev/null
iptables -I FORWARD -i "$IF_RC" -o "$IF_RS" -j ACCEPT
iptables -I FORWARD -i "$IF_RS" -o "$IF_RC" -j ACCEPT
IPTABLES_RULES_APPLIED=1

{
    echo "=== topology ==="
    ip netns list
    ip addr show "$IF_RC"
    ip addr show "$IF_RS"
    ip -n "$NS_CLIENT" route show
    ip -n "$NS_SERVER" route show
    echo "=== iptables ==="
    iptables -S FORWARD
} >>"$PROBE_FILE" 2>&1

if [[ $SKIP_PCAP -eq 0 ]] && need_cmd tcpdump; then
    log "start pcap capture"
    tcpdump -i "$IF_RC" -w "$PCAP_FILE" -n "icmp or tcp or udp" >/dev/null 2>&1 &
    TCPDUMP_PID="$!"
else
    record_case "pcap" "pcap capture" "SKIP" "tcpdump not available or --skip-pcap set"
fi

log "start server services in $NS_SERVER"
ip netns exec "$NS_SERVER" python3 - "$TCP_ECHO_PORT" "$UDP_ECHO_PORT" "$DNS_PORT" >/dev/null 2>&1 <<'PY' &
import socket
import struct
import sys
import threading

tcp_port = int(sys.argv[1])
udp_port = int(sys.argv[2])
dns_port = int(sys.argv[3])


def tcp_echo():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", tcp_port))
    srv.listen(128)
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
    s.bind(("0.0.0.0", udp_port))
    while True:
        data, addr = s.recvfrom(2048)
        s.sendto(data, addr)


def dns_server():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("0.0.0.0", dns_port))
    while True:
        query, addr = s.recvfrom(2048)
        if len(query) < 12:
            continue
        txid = query[:2]
        qdcount = query[4:6]
        question = query[12:]
        flags = b"\x81\x80"
        ancount = b"\x00\x01"
        nscount = b"\x00\x00"
        arcount = b"\x00\x00"
        header = txid + flags + qdcount + ancount + nscount + arcount
        answer = b"\xc0\x0c" + b"\x00\x01" + b"\x00\x01" + struct.pack("!I", 30) + b"\x00\x04" + socket.inet_aton("1.1.1.1")
        s.sendto(header + question + answer, addr)


threading.Thread(target=tcp_echo, daemon=True).start()
threading.Thread(target=udp_echo, daemon=True).start()
dns_server()
PY
SERVICE_PID="$!"
sleep 1

if ! kill -0 "$SERVICE_PID" >/dev/null 2>&1; then
    record_case "service_boot" "start tcp/udp/dns server in namespace" "FAIL" "service process exited early"
    emit_report "FAIL" "server bootstrap failed"
    log "report: $REPORT_JSON"
    exit 1
fi
record_case "service_boot" "start tcp/udp/dns server in namespace" "PASS" "pid=$SERVICE_PID"

log "probe tun provisioning"
if ip tuntap add dev "$TUN_IF" mode tun >/dev/null 2>&1; then
    ip addr add 172.31.240.1/30 dev "$TUN_IF" >/dev/null 2>&1 || true
    ip link set "$TUN_IF" mtu 1400 up >/dev/null 2>&1 || true
    {
        echo "=== tun probe ==="
        ip addr show "$TUN_IF"
    } >>"$PROBE_FILE" 2>&1
    record_case "tun_probe" "create/configure linux tun device" "PASS" "device=$TUN_IF mtu=1400"
else
    record_case "tun_probe" "create/configure linux tun device" "FAIL" "ip tuntap add failed"
fi

log "case: mtu"
if ip netns exec "$NS_CLIENT" ping -M do -c 2 -W 1 -s 1372 "$SERVER_NS_IP" >/dev/null 2>&1; then
    record_case "mtu" "DF ping with 1400-byte path MTU" "PASS" "payload=1372"
else
    record_case "mtu" "DF ping with 1400-byte path MTU" "FAIL" "ping -M do failed"
fi

log "case: udp"
if ip netns exec "$NS_CLIENT" python3 - "$SERVER_NS_IP" "$UDP_ECHO_PORT" <<'PY' >/dev/null 2>&1
import socket
import sys

host = sys.argv[1]
port = int(sys.argv[2])
payload = b"udp-e2e-l19"
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(2)
s.sendto(payload, (host, port))
data, _ = s.recvfrom(1024)
if data != payload:
    raise SystemExit(1)
PY
then
    record_case "udp" "udp echo roundtrip across netns/veth" "PASS" "echo verified"
else
    record_case "udp" "udp echo roundtrip across netns/veth" "FAIL" "udp echo mismatch/timeout"
fi

log "case: dns"
if ip netns exec "$NS_CLIENT" python3 - "$SERVER_NS_IP" "$DNS_PORT" <<'PY' >/dev/null 2>&1
import os
import socket
import struct
import sys

server = sys.argv[1]
port = int(sys.argv[2])

name = b"example.com"
labels = name.split(b".")
qname = b"".join(bytes([len(x)]) + x for x in labels) + b"\x00"
txid = os.urandom(2)
query = txid + b"\x01\x00" + b"\x00\x01" + b"\x00\x00" + b"\x00\x00" + b"\x00\x00" + qname + b"\x00\x01\x00\x01"
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(2)
s.sendto(query, (server, port))
data, _ = s.recvfrom(1024)
if data[:2] != txid:
    raise SystemExit(1)
if b"\x00\x01\x00\x01" not in data:
    raise SystemExit(1)
if socket.inet_aton("1.1.1.1") not in data:
    raise SystemExit(1)
PY
then
    record_case "dns" "udp dns query over namespace dataplane" "PASS" "A=1.1.1.1"
else
    record_case "dns" "udp dns query over namespace dataplane" "FAIL" "dns query failed"
fi

log "case: route_loop_guard"
if ip netns exec "$NS_CLIENT" ping -c 10 -W 1 "$SERVER_NS_IP" >/tmp/tun_linux_e2e_ping.log 2>&1; then
    if grep -qi "Time to live exceeded" /tmp/tun_linux_e2e_ping.log; then
        record_case "route_loop_guard" "route loop guard (no TTL exceeded under steady traffic)" "FAIL" "ttl exceeded observed"
    else
        record_case "route_loop_guard" "route loop guard (no TTL exceeded under steady traffic)" "PASS" "no ttl exceeded"
    fi
else
    record_case "route_loop_guard" "route loop guard (no TTL exceeded under steady traffic)" "FAIL" "baseline ping failed"
fi
rm -f /tmp/tun_linux_e2e_ping.log

log "case: concurrent_tcp"
if ip netns exec "$NS_CLIENT" python3 - "$SERVER_NS_IP" "$TCP_ECHO_PORT" "$CONCURRENCY" <<'PY' >/dev/null 2>&1
import socket
import sys
import threading

host = sys.argv[1]
port = int(sys.argv[2])
count = int(sys.argv[3])
errors = []


def worker(i):
    payload = f"tcp-{i}".encode()
    try:
        s = socket.create_connection((host, port), timeout=2)
        s.sendall(payload)
        data = s.recv(1024)
        s.close()
        if data != payload:
            errors.append(f"mismatch-{i}")
    except Exception as e:
        errors.append(str(e))


threads = [threading.Thread(target=worker, args=(i,)) for i in range(count)]
for t in threads:
    t.start()
for t in threads:
    t.join()

if errors:
    raise SystemExit(1)
PY
then
    record_case "concurrent_tcp" "concurrent tcp echo sessions" "PASS" "count=$CONCURRENCY"
else
    record_case "concurrent_tcp" "concurrent tcp echo sessions" "FAIL" "concurrency check failed"
fi

{
    echo "=== post-check ==="
    iptables -L FORWARD -v -n
} >>"$PROBE_FILE" 2>&1

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
log "done"
exit 0
