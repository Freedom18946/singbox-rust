#!/usr/bin/env bash
# mock_infra_smoke.sh -- exercise the mock_public_infra.py surface without
# involving either kernel. Intended as a guard that the simulator still
# behaves deterministically before running the full dual-kernel acceptance.
set -u
set -o pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MOCK_PY="$SCRIPT_DIR/mock_public_infra.py"
HTTP="http://127.0.0.1:18080"
HTTPS="https://127.0.0.1:18443"
TCP_HOST="127.0.0.1"
TCP_PORT=18083
WS_HOST="127.0.0.1"
WS_PORT=18081
SUB_BEARER="mt-gui-02-sub-bearer"

echo "=== MT-GUI-02 mock_public_infra smoke test ==="
echo "Date: $(date -u +%Y-%m-%dT%H:%M:%SZ)"

MOCK_LOG="$(mktemp -t mt_gui_02_mock.XXXXXX.log)"
python3 "$MOCK_PY" >/tmp/mt_gui_02_mock_ready.json 2>"$MOCK_LOG" &
MOCK_PID=$!
trap '[[ -n "${MOCK_PID:-}" ]] && kill -TERM "$MOCK_PID" 2>/dev/null; wait "${MOCK_PID:-}" 2>/dev/null; rm -f "$MOCK_LOG" /tmp/mt_gui_02_mock_ready.json' EXIT

# wait for ready line
for _ in 1 2 3 4 5 6 7 8 9 10; do
  if [[ -s /tmp/mt_gui_02_mock_ready.json ]]; then break; fi
  sleep 0.25
done
if ! [[ -s /tmp/mt_gui_02_mock_ready.json ]]; then
  echo "FAIL: mock infra did not become ready"
  echo "---stderr---"; cat "$MOCK_LOG"
  exit 1
fi
echo "mock ready: $(cat /tmp/mt_gui_02_mock_ready.json)"
echo

echo "--- HTTP / banner ---"
curl -s -D - -o /dev/null "$HTTP/" | grep -Ei '^(HTTP|Server:|Content-Type:|Content-Length:)' || true

echo "--- HTTP /get ---"
curl -s -D - "$HTTP/get" | head -10

echo "--- HTTP /headers ---"
curl -s "$HTTP/headers"
echo

echo "--- HTTP /status/404 ---"
curl -s -o /dev/null -w 'status=%{http_code}\n' "$HTTP/status/404"
echo "--- HTTP /status/500 ---"
curl -s -o /dev/null -w 'status=%{http_code}\n' "$HTTP/status/500"
echo

echo "--- HTTP /redirect (no follow) ---"
curl -s -D - -o /dev/null "$HTTP/redirect" | head -5

echo "--- HTTP /redirect/3 (follow) ---"
curl -s -L -o /dev/null -w 'status=%{http_code} redirects=%{num_redirects} final=%{url_effective}\n' "$HTTP/redirect/3"
echo

echo "--- HTTP /chunked ---"
curl -s -D - "$HTTP/chunked" | head -15

echo "--- HTTP /large (1 MiB) ---"
curl -s -o /tmp/mt_gui_02_large.bin -w 'status=%{http_code} bytes=%{size_download}\n' "$HTTP/large"

echo "--- HTTP /slow?ms=500 ---"
{ time curl -s -o /dev/null -w 'status=%{http_code}\n' "$HTTP/slow?ms=500"; } 2>&1

echo "--- HTTP /sse ---"
curl -s "$HTTP/sse" | head -15
echo

echo "--- HTTP /sub/version ---"
curl -s "$HTTP/sub/version"; echo

echo "--- HTTP /sub/clash.json (no auth) ---"
curl -s -D /tmp/mt_gui_02_sub_hdr.txt -o /tmp/mt_gui_02_sub_body.json -w 'status=%{http_code}\n' "$HTTP/sub/clash.json"
ETAG=$(awk -F': ' 'tolower($1)=="etag"{print $2}' /tmp/mt_gui_02_sub_hdr.txt | tr -d '\r')
echo "etag=$ETAG"

echo "--- HTTP /sub/clash.json (wrong auth) ---"
curl -s -o /dev/null -w 'status=%{http_code}\n' -H 'Authorization: Bearer wrong' "$HTTP/sub/clash.json"

echo "--- HTTP /sub/clash.json (correct auth) ---"
curl -s -D /tmp/mt_gui_02_sub_hdr.txt -o /tmp/mt_gui_02_sub_body.json \
  -w 'status=%{http_code}\n' \
  -H "Authorization: Bearer $SUB_BEARER" "$HTTP/sub/clash.json"
echo "cache-control=$(awk -F': ' 'tolower($1)=="cache-control"{print $2}' /tmp/mt_gui_02_sub_hdr.txt | tr -d '\r')"
echo "bytes=$(wc -c </tmp/mt_gui_02_sub_body.json | tr -d ' ')"

echo "--- HTTP /sub/clash.json (correct auth + etag) ---"
curl -s -o /dev/null -w 'status=%{http_code}\n' \
  -H "Authorization: Bearer $SUB_BEARER" \
  -H "If-None-Match: $ETAG" "$HTTP/sub/clash.json"

echo
echo "--- HTTP /early-close ---"
curl -s -D - -o /dev/null "$HTTP/early-close" 2>&1 || echo "(curl exit $?)"

echo "--- HTTP /reset ---"
curl -s -o /dev/null "$HTTP/reset" 2>&1 || echo "(curl exit $?)"

echo
echo "--- HTTPS / banner (insecure) ---"
curl -sk -D - -o /dev/null "$HTTPS/" | grep -Ei '^(HTTP|Server:|Content-Type:|Content-Length:)' || true

echo
echo "--- TCP echo (nc) ---"
printf 'hello-tcp-echo\n' | nc -w2 "$TCP_HOST" "$TCP_PORT" || echo "(nc exit $?)"

echo
echo "--- WS handshake + echo ---"
python3 - "$WS_HOST" "$WS_PORT" <<'PYEOF'
import base64, os, socket, struct, sys
host, port = sys.argv[1], int(sys.argv[2])
s = socket.socket()
s.settimeout(5)
s.connect((host, port))
key = base64.b64encode(os.urandom(16)).decode()
s.sendall((
    "GET / HTTP/1.1\r\n"
    f"Host: {host}:{port}\r\n"
    "Upgrade: websocket\r\n"
    "Connection: Upgrade\r\n"
    f"Sec-WebSocket-Key: {key}\r\n"
    "Sec-WebSocket-Version: 13\r\n\r\n"
).encode())

# Buffered reader — handshake recv may overshoot into the first WS frame.
_buf = bytearray()

def _read(n):
    while len(_buf) < n:
        chunk = s.recv(4096)
        if not chunk:
            break
        _buf.extend(chunk)
    out = bytes(_buf[:n])
    del _buf[:n]
    return out

def _read_until(marker):
    while marker not in _buf:
        chunk = s.recv(4096)
        if not chunk:
            break
        _buf.extend(chunk)
    idx = _buf.index(marker) + len(marker)
    out = bytes(_buf[:idx])
    del _buf[:idx]
    return out

hdr = _read_until(b"\r\n\r\n")
status_line = hdr.split(b"\r\n", 1)[0].decode()
print("handshake:", status_line)

def _recv_frame():
    h = _read(2)
    if len(h) < 2:
        return None
    plen = h[1] & 0x7F
    if plen == 126:
        plen = struct.unpack("!H", _read(2))[0]
    elif plen == 127:
        plen = struct.unpack("!Q", _read(8))[0]
    data = _read(plen)
    return h[0] & 0x0F, data

op, data = _recv_frame()
print("first-frame opcode=", op, "data=", data)

payload = b"mt-gui-02-smoke"
mask = os.urandom(4)
masked = bytes(payload[i] ^ mask[i % 4] for i in range(len(payload)))
frame = bytes([0x81, 0x80 | len(payload)]) + mask + masked
s.sendall(frame)
op, data = _recv_frame()
print("echo opcode=", op, "data=", data)
s.close()
PYEOF

echo
echo "--- smoke done ---"
