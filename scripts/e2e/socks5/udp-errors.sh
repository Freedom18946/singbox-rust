#!/usr/bin/env zsh
set -euo pipefail

echo "[INFO] e2e: socks5 udp error path (parse) -> inbound_error_total{socks_udp}"

# Config
SOCKS_LISTEN=${SOCKS_LISTEN:-127.0.0.1:11081}
PROM=${PROM_LISTEN:-127.0.0.1:19090}
CFG=${CFG_PATH:-}
FEATS=${FEATS:-acceptance,adapters}
REASON_FILE=${REASON_FILE:-/tmp/sb-udp-errors.reason}
CFG_TMP=""

: > "${REASON_FILE}"

if [[ -z "${CFG}" ]]; then
  CFG_TMP="$(mktemp -t sb-udp-errors-config.XXXX.yaml)"
  CFG="${CFG_TMP}"
  cat > "${CFG}" <<YAML
log:
  level: error
inbounds:
  - type: socks
    listen: "${SOCKS_LISTEN}"
outbounds:
  - type: direct
    tag: direct
route:
  rules:
    - outbound: direct
YAML
fi

# Helper to scrape and sum metric family values with filters
scrape_metric_sum(){
  local name="$1"; shift
  local lines
  lines="$(curl -fsS "http://${PROM}/metrics" | grep -E "^${name}\\{" || true)"
  for f in "$@"; do
    lines="$(printf '%s\n' "$lines" | grep -F "$f" || true)"
  done
  printf '%s\n' "$lines" | awk '{s+=$NF} END{if(s=="") s=0; print s}'
}

tmp_before="$(mktemp -t sbm_udp_err_before.XXXX)"
tmp_after="$(mktemp -t sbm_udp_err_after.XXXX)"
cleanup(){ rm -f "$tmp_before" "$tmp_after" "$CFG_TMP" || true; }
trap cleanup EXIT

echo "[RUN] launching app run with UDP inbound + metrics exporter"
launch_runtime() {
  if command -v setsid >/dev/null 2>&1; then
    setsid nohup env \
      SB_SOCKS_UDP_ENABLE=1 \
      target/debug/run \
      --config "${CFG}" \
      --prom-listen "${PROM}" \
      </dev/null >/tmp/sb-udp-errors.log 2>&1 &
  else
    nohup env \
      SB_SOCKS_UDP_ENABLE=1 \
      target/debug/run \
      --config "${CFG}" \
      --prom-listen "${PROM}" \
      </dev/null >/tmp/sb-udp-errors.log 2>&1 &
  fi
}

launch_runtime

APP_PID=$!
echo "${APP_PID}" > /tmp/sb-udp-errors.pid
trap 'kill ${APP_PID} 2>/dev/null || true' EXIT
for _ in {1..20}; do
  if ! kill -0 "${APP_PID}" 2>/dev/null; then
    echo "runtime-exited-before-metrics" > "${REASON_FILE}"
    echo "[FAIL] app runtime exited before metrics became reachable"
    exit 1
  fi
  if curl -fsS "http://${PROM}/metrics" >/dev/null 2>&1; then
    break
  fi
  sleep 0.5
done

echo "[SCRAPE] baseline inbound_error_total{protocol=\"socks_udp\"}"
base=$(scrape_metric_sum inbound_error_total 'protocol="socks_udp"')
echo "base=${base}" > "$tmp_before"

echo "[INJECT] negotiate UDP ASSOCIATE via ${SOCKS_LISTEN} and send malformed SOCKS5 UDP datagram"
if ! SOCKS_LISTEN="${SOCKS_LISTEN}" REASON_FILE="${REASON_FILE}" python3 - <<'PY'
import os
import socket
import struct
import sys
import time


def parse_socket_addr(value: str) -> tuple[str, int]:
    if value.startswith("["):
        host, rest = value[1:].split("]", 1)
        if not rest.startswith(":"):
            raise ValueError(f"invalid listen address: {value}")
        return host, int(rest[1:])
    host, port = value.rsplit(":", 1)
    return host, int(port)


def write_reason(reason: str) -> None:
    reason_file = os.environ["REASON_FILE"]
    with open(reason_file, "w", encoding="utf-8") as handle:
        handle.write(reason)


def recv_exact(sock: socket.socket, size: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < size:
        chunk = sock.recv(size - len(chunks))
        if not chunk:
            raise RuntimeError(f"short read: expected {size} bytes, got {len(chunks)}")
        chunks.extend(chunk)
    return bytes(chunks)


listen = os.environ["SOCKS_LISTEN"]
host, port = parse_socket_addr(listen)

try:
    control = socket.create_connection((host, port), timeout=3)
    control.settimeout(3)
    control.sendall(b"\x05\x01\x00")
    greeting = recv_exact(control, 2)
    if greeting != b"\x05\x00":
        raise RuntimeError(f"unexpected greeting reply: {greeting!r}")

    control.sendall(b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00")
    response = recv_exact(control, 4)
    ver, rep, _rsv, atyp = response
    if ver != 0x05 or rep != 0x00:
        raise RuntimeError(f"UDP ASSOCIATE failed: ver={ver} rep={rep}")

    if atyp == 0x01:
        addr_raw = recv_exact(control, 4)
        relay_host = socket.inet_ntop(socket.AF_INET, addr_raw)
    elif atyp == 0x04:
        addr_raw = recv_exact(control, 16)
        relay_host = socket.inet_ntop(socket.AF_INET6, addr_raw)
    elif atyp == 0x03:
        size_raw = recv_exact(control, 1)
        addr_raw = recv_exact(control, size_raw[0])
        relay_host = addr_raw.decode("utf-8")
    else:
        raise RuntimeError(f"invalid ATYP in UDP ASSOCIATE reply: {atyp}")

    port_raw = recv_exact(control, 2)
    relay_port = struct.unpack("!H", port_raw)[0]

    if relay_host in {"0.0.0.0", "::"}:
        relay_host = host

    udp = socket.socket(
        socket.AF_INET6 if ":" in relay_host else socket.AF_INET,
        socket.SOCK_DGRAM,
    )
    udp.settimeout(3)
    try:
        udp.sendto(b"\x01\x00\x00\x00", (relay_host, relay_port))
    except OSError as exc:
        write_reason("udp-relay-send-failed")
        raise RuntimeError(
            f"failed to send malformed datagram to relay {relay_host}:{relay_port}: {exc}"
        ) from exc
    print(f"[INFO] UDP relay discovered at {relay_host}:{relay_port}", file=sys.stderr)
    time.sleep(0.2)
    control.close()
    udp.close()
except Exception as exc:
    if not os.path.exists(os.environ["REASON_FILE"]) or not open(
        os.environ["REASON_FILE"], "r", encoding="utf-8"
    ).read().strip():
        write_reason("udp-associate-failed")
    print(f"[FAIL] udp associate probe failed: {exc}", file=sys.stderr)
    sys.exit(1)
PY
then
  reason="$(cat "${REASON_FILE}" 2>/dev/null || true)"
  if [[ -z "${reason}" ]]; then
    echo "udp-relay-send-failed" > "${REASON_FILE}"
  fi
  exit 1
fi

sleep 0.6

echo "[SCRAPE] compare inbound_error_total{protocol=\"socks_udp\"}"
after=$(scrape_metric_sum inbound_error_total 'protocol="socks_udp"')
echo "after=${after}" > "$tmp_after"

delta=$(( after - base ))
if (( delta > 0 )); then
  echo "[OK] inbound_error_total{protocol=socks_udp} increased by ${delta}"
else
  echo "metric-did-not-increase" > "${REASON_FILE}"
  echo "[FAIL] inbound_error_total{protocol=socks_udp} did not increase (Δ=${delta})"
  echo "[HINT] ensure metrics exporter bound at ${PROM} and SOCKS TCP inbound is reachable at ${SOCKS_LISTEN}"
  exit 1
fi

echo "[CLEANUP] shutting down"
kill ${APP_PID} 2>/dev/null || true
sleep 0.2
echo "[DONE]"
