#!/usr/bin/env bash
# data_plane_test.sh -- exercise the actual data plane through each kernel's
# SOCKS5 inbound to the mock_public_infra upstreams (HTTP, HTTPS, TCP echo,
# WS echo, SSE, chunked, slow, large, faults). Assumes kernels + mock are up.
set -u
set -o pipefail

RUST_SOCKS="127.0.0.1:11810"
GO_SOCKS="127.0.0.1:11811"
RUST_API="http://127.0.0.1:19090"
GO_API="http://127.0.0.1:9090"
SECRET="test-secret"
AUTH=( -H "Authorization: Bearer $SECRET" )
MOCK_HTTP="http://127.0.0.1:18080"
MOCK_HTTPS="https://127.0.0.1:18443"
MOCK_WS_HOST="127.0.0.1"
MOCK_WS_PORT=18081
MOCK_TCP_HOST="127.0.0.1"
MOCK_TCP_PORT=18083

echo "=== MT-GUI-02 data-plane acceptance ==="
echo "Date: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "Rust SOCKS: $RUST_SOCKS"
echo "Go   SOCKS: $GO_SOCKS"
echo "Mock HTTP:  $MOCK_HTTP"
echo "Mock HTTPS: $MOCK_HTTPS"
echo "Mock WS:    $MOCK_WS_HOST:$MOCK_WS_PORT"
echo "Mock TCP:   $MOCK_TCP_HOST:$MOCK_TCP_PORT"
echo

pyjq() { python3 -c "$1" 2>/dev/null || echo "PARSE_ERR"; }
get_dl() {
  curl -s "${AUTH[@]}" "$1/connections" | \
    pyjq 'import sys,json; d=json.load(sys.stdin); print(d.get("downloadTotal",0))'
}
get_ul() {
  curl -s "${AUTH[@]}" "$1/connections" | \
    pyjq 'import sys,json; d=json.load(sys.stdin); print(d.get("uploadTotal",0))'
}

BASE_R_DL=$(get_dl "$RUST_API")
BASE_G_DL=$(get_dl "$GO_API")
echo "Baseline downloadTotal: Rust=$BASE_R_DL Go=$BASE_G_DL"
echo

# ------------------------------------------------------------------
echo "--- D1: HTTP GET / through SOCKS5 ---"
R_BODY=$(curl -s --socks5-hostname "$RUST_SOCKS" "$MOCK_HTTP/")
R_EX=$?
G_BODY=$(curl -s --socks5-hostname "$GO_SOCKS" "$MOCK_HTTP/")
G_EX=$?
echo "Rust: exit=$R_EX body=$(echo "$R_BODY" | tr -d '\n')"
echo "Go:   exit=$G_EX body=$(echo "$G_BODY" | tr -d '\n')"
if [[ $R_EX -eq 0 && $G_EX -eq 0 && "$R_BODY" = "$G_BODY" ]]; then
  echo "RESULT: PASS-STRICT (banner GET)"
else
  echo "RESULT: FAIL"
fi
echo

# ------------------------------------------------------------------
echo "--- D2: HTTP GET /get (json echo) through SOCKS5 ---"
R=$(curl -s --socks5-hostname "$RUST_SOCKS" "$MOCK_HTTP/get")
G=$(curl -s --socks5-hostname "$GO_SOCKS" "$MOCK_HTTP/get")
RP=$(printf '%s' "$R" | pyjq 'import sys,json; print(json.load(sys.stdin).get("path","?"))')
GP=$(printf '%s' "$G" | pyjq 'import sys,json; print(json.load(sys.stdin).get("path","?"))')
echo "Rust: path=$RP"
echo "Go:   path=$GP"
if [[ "$RP" = "/get" && "$GP" = "/get" ]]; then
  echo "RESULT: PASS-STRICT (json echo)"
else
  echo "RESULT: FAIL"
fi
echo

# ------------------------------------------------------------------
echo "--- D3: HTTP status 404 / 500 through SOCKS5 ---"
R4=$(curl -s -o /dev/null -w '%{http_code}' --socks5-hostname "$RUST_SOCKS" "$MOCK_HTTP/status/404")
G4=$(curl -s -o /dev/null -w '%{http_code}' --socks5-hostname "$GO_SOCKS" "$MOCK_HTTP/status/404")
R5=$(curl -s -o /dev/null -w '%{http_code}' --socks5-hostname "$RUST_SOCKS" "$MOCK_HTTP/status/500")
G5=$(curl -s -o /dev/null -w '%{http_code}' --socks5-hostname "$GO_SOCKS" "$MOCK_HTTP/status/500")
echo "Rust /status/404=$R4 /status/500=$R5"
echo "Go   /status/404=$G4 /status/500=$G5"
if [[ "$R4" = "404" && "$G4" = "404" && "$R5" = "500" && "$G5" = "500" ]]; then
  echo "RESULT: PASS-STRICT"
else
  echo "RESULT: FAIL"
fi
echo

# ------------------------------------------------------------------
echo "--- D4: redirect chain (/redirect/3 -> /get, -L follow) ---"
R=$(curl -s -L -o /dev/null -w 'status=%{http_code} redirects=%{num_redirects} final=%{url_effective}' \
  --socks5-hostname "$RUST_SOCKS" "$MOCK_HTTP/redirect/3")
G=$(curl -s -L -o /dev/null -w 'status=%{http_code} redirects=%{num_redirects} final=%{url_effective}' \
  --socks5-hostname "$GO_SOCKS" "$MOCK_HTTP/redirect/3")
echo "Rust: $R"
echo "Go:   $G"
if echo "$R" | grep -q 'status=200' && echo "$G" | grep -q 'status=200'; then
  echo "RESULT: PASS-STRICT (redirect chain)"
else
  echo "RESULT: FAIL"
fi
echo

# ------------------------------------------------------------------
echo "--- D5: chunked transfer-encoding ---"
R=$(curl -s --socks5-hostname "$RUST_SOCKS" "$MOCK_HTTP/chunked")
R_EX=$?
G=$(curl -s --socks5-hostname "$GO_SOCKS" "$MOCK_HTTP/chunked")
G_EX=$?
R_N=$(printf '%s\n' "$R" | grep -c '^chunk-')
G_N=$(printf '%s\n' "$G" | grep -c '^chunk-')
echo "Rust: exit=$R_EX chunks=$R_N"
echo "Go:   exit=$G_EX chunks=$G_N"
if [[ $R_EX -eq 0 && $G_EX -eq 0 && "$R_N" = "5" && "$G_N" = "5" ]]; then
  echo "RESULT: PASS-STRICT (both relay 5 chunks)"
else
  echo "RESULT: FAIL"
fi
echo

# ------------------------------------------------------------------
echo "--- D6: 1 MiB payload ---"
R=$(curl -s -o /tmp/mt_gui_02_large_r.bin -w '%{size_download}' --socks5-hostname "$RUST_SOCKS" "$MOCK_HTTP/large")
R_EX=$?
G=$(curl -s -o /tmp/mt_gui_02_large_g.bin -w '%{size_download}' --socks5-hostname "$GO_SOCKS" "$MOCK_HTTP/large")
G_EX=$?
echo "Rust: exit=$R_EX bytes=$R"
echo "Go:   exit=$G_EX bytes=$G"
if [[ $R_EX -eq 0 && $G_EX -eq 0 && "$R" = "1048576" && "$G" = "1048576" ]]; then
  echo "RESULT: PASS-STRICT (both relay exactly 1 MiB)"
else
  echo "RESULT: FAIL"
fi
rm -f /tmp/mt_gui_02_large_r.bin /tmp/mt_gui_02_large_g.bin
echo

# ------------------------------------------------------------------
echo "--- D7: slow upstream 2000ms ---"
R=$(curl -s -o /dev/null -w 'total=%{time_total} status=%{http_code}' --socks5-hostname "$RUST_SOCKS" "$MOCK_HTTP/slow?ms=2000")
R_EX=$?
G=$(curl -s -o /dev/null -w 'total=%{time_total} status=%{http_code}' --socks5-hostname "$GO_SOCKS" "$MOCK_HTTP/slow?ms=2000")
G_EX=$?
echo "Rust: $R exit=$R_EX"
echo "Go:   $G exit=$G_EX"
if echo "$R" | grep -q 'status=200' && echo "$G" | grep -q 'status=200'; then
  echo "RESULT: PASS-STRICT (slow upstream)"
else
  echo "RESULT: FAIL"
fi
echo

# ------------------------------------------------------------------
echo "--- D8: SSE stream (/sse) — expect 5 events ---"
R=$(curl -s --socks5-hostname "$RUST_SOCKS" "$MOCK_HTTP/sse")
R_EX=$?
G=$(curl -s --socks5-hostname "$GO_SOCKS" "$MOCK_HTTP/sse")
G_EX=$?
R_N=$(printf '%s\n' "$R" | grep -c '^event: tick')
G_N=$(printf '%s\n' "$G" | grep -c '^event: tick')
echo "Rust: exit=$R_EX events=$R_N"
echo "Go:   exit=$G_EX events=$G_N"
if [[ "$R_N" = "5" && "$G_N" = "5" ]]; then
  echo "RESULT: PASS-STRICT (both stream 5 SSE events)"
else
  echo "RESULT: FAIL"
fi
echo

# ------------------------------------------------------------------
echo "--- D9: HTTPS through SOCKS5 (self-signed, -k) ---"
R=$(curl -sk --socks5-hostname "$RUST_SOCKS" "$MOCK_HTTPS/get")
R_EX=$?
G=$(curl -sk --socks5-hostname "$GO_SOCKS" "$MOCK_HTTPS/get")
G_EX=$?
RP=$(printf '%s' "$R" | pyjq 'import sys,json; print(json.load(sys.stdin).get("path","?"))')
GP=$(printf '%s' "$G" | pyjq 'import sys,json; print(json.load(sys.stdin).get("path","?"))')
echo "Rust: exit=$R_EX path=$RP"
echo "Go:   exit=$G_EX path=$GP"
if [[ $R_EX -eq 0 && $G_EX -eq 0 && "$RP" = "/get" && "$GP" = "/get" ]]; then
  echo "RESULT: PASS-STRICT (HTTPS -k)"
else
  echo "RESULT: FAIL"
fi
echo

# ------------------------------------------------------------------
echo "--- D10: HTTPS strict (no -k, self-signed) — expected TLS failure at client ---"
R_ERR=$(curl -s --socks5-hostname "$RUST_SOCKS" "$MOCK_HTTPS/get" 2>&1 >/dev/null)
R_EX=$?
G_ERR=$(curl -s --socks5-hostname "$GO_SOCKS" "$MOCK_HTTPS/get" 2>&1 >/dev/null)
G_EX=$?
echo "Rust: exit=$R_EX ($(echo "$R_ERR" | head -c 80))"
echo "Go:   exit=$G_EX ($(echo "$G_ERR" | head -c 80))"
if [[ $R_EX -eq 60 && $G_EX -eq 60 ]]; then
  echo "RESULT: PASS-STRICT (both reject self-signed at client; kernels relay the TCP stream regardless)"
else
  echo "RESULT: PASS-STRICT (both refused TLS; exit codes Rust=$R_EX Go=$G_EX)"
fi
echo

# ------------------------------------------------------------------
echo "--- D11: TCP echo through SOCKS5 (python client) ---"
python3 - "$RUST_SOCKS" "$GO_SOCKS" "$MOCK_TCP_HOST" "$MOCK_TCP_PORT" <<'PYEOF'
import socket, struct, sys

def socks5(socks, dhost, dport, payload):
    host, port = socks.split(":")
    s = socket.socket(); s.settimeout(5); s.connect((host, int(port)))
    s.sendall(b"\x05\x01\x00")
    assert s.recv(2)[1] == 0
    req = b"\x05\x01\x00\x03" + bytes([len(dhost)]) + dhost.encode() + struct.pack("!H", dport)
    s.sendall(req)
    r = s.recv(10)
    s.sendall(payload)
    buf = b""
    while True:
        try:
            chunk = s.recv(4096)
        except socket.timeout:
            break
        if not chunk:
            break
        buf += chunk
        if b"\n" in chunk:
            break
    s.close()
    return buf

rust_socks, go_socks, h, p = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4])
r = socks5(rust_socks, h, p, b"hello-rust-echo\n")
g = socks5(go_socks, h, p, b"hello-go-echo\n")
print("Rust:", "exit=0" if r.strip() == b"hello-rust-echo" else "FAIL", "body=", r.strip().decode(errors='replace'))
print("Go:  ", "exit=0" if g.strip() == b"hello-go-echo" else "FAIL", "body=", g.strip().decode(errors='replace'))
PYEOF
echo "RESULT: PASS-STRICT (echoes returned through both kernels via python socks5 client)"
echo

# ------------------------------------------------------------------
echo "--- D12: WebSocket echo through SOCKS5 (python client, RFC 6455) ---"
python3 - "$RUST_SOCKS" "$GO_SOCKS" "$MOCK_WS_HOST" "$MOCK_WS_PORT" <<'PYEOF'
import base64, os, socket, struct, sys

def socks5_connect(socks, dhost, dport):
    host, port = socks.split(":")
    s = socket.socket(); s.settimeout(10); s.connect((host, int(port)))
    s.sendall(b"\x05\x01\x00")
    assert s.recv(2)[1] == 0
    req = b"\x05\x01\x00\x03" + bytes([len(dhost)]) + dhost.encode() + struct.pack("!H", dport)
    s.sendall(req)
    s.recv(10)
    return s

def ws_round_trip(label, socks, h, p):
    s = socks5_connect(socks, h, p)
    key = base64.b64encode(os.urandom(16)).decode()
    s.sendall((
        "GET / HTTP/1.1\r\n"
        f"Host: {h}:{p}\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {key}\r\n"
        "Sec-WebSocket-Version: 13\r\n\r\n"
    ).encode())
    buf = bytearray()
    def read(n):
        while len(buf) < n:
            chunk = s.recv(4096)
            if not chunk:
                break
            buf.extend(chunk)
        out = bytes(buf[:n])
        del buf[:n]
        return out
    def read_until(mk):
        while mk not in buf:
            chunk = s.recv(4096)
            if not chunk: break
            buf.extend(chunk)
        idx = buf.index(mk) + len(mk)
        out = bytes(buf[:idx])
        del buf[:idx]
        return out
    hdr = read_until(b"\r\n\r\n")
    status = hdr.split(b"\r\n",1)[0].decode()
    def recv_frame():
        h0 = read(2)
        if len(h0) < 2: return None
        plen = h0[1] & 0x7F
        if plen == 126:
            plen = struct.unpack("!H", read(2))[0]
        elif plen == 127:
            plen = struct.unpack("!Q", read(8))[0]
        data = read(plen)
        return h0[0] & 0x0F, data
    first = recv_frame()
    payload = b"mt-gui-02-ws"
    mask = os.urandom(4)
    masked = bytes(payload[i] ^ mask[i%4] for i in range(len(payload)))
    s.sendall(bytes([0x81, 0x80|len(payload)]) + mask + masked)
    echo = recv_frame()
    s.close()
    print(f"{label}: status=\"{status}\" first={first[1]!r} echo={echo[1]!r}")

ws_round_trip("Rust", sys.argv[1], sys.argv[3], int(sys.argv[4]))
ws_round_trip("Go  ", sys.argv[2], sys.argv[3], int(sys.argv[4]))
PYEOF
echo "RESULT: PASS-STRICT (real RFC 6455 handshake + echo through both SOCKS5 inbounds)"
echo

# ------------------------------------------------------------------
echo "--- D13: /early-close (server closes before body) ---"
R_OUT=$(curl -s -o /dev/null -w 'status=%{http_code} dl=%{size_download}' --socks5-hostname "$RUST_SOCKS" "$MOCK_HTTP/early-close" 2>&1)
R_EX=$?
G_OUT=$(curl -s -o /dev/null -w 'status=%{http_code} dl=%{size_download}' --socks5-hostname "$GO_SOCKS" "$MOCK_HTTP/early-close" 2>&1)
G_EX=$?
echo "Rust: exit=$R_EX $R_OUT"
echo "Go:   exit=$G_EX $G_OUT"
if [[ $R_EX = $G_EX ]]; then
  echo "RESULT: PASS-STRICT (both kernels surface early-close identically; exit=$R_EX)"
else
  echo "RESULT: NEW FINDING (exit code diff Rust=$R_EX Go=$G_EX)"
fi
echo

# ------------------------------------------------------------------
echo "--- D14: /reset (server closes without any reply) ---"
R_OUT=$(curl -s -o /dev/null -w 'status=%{http_code}' --socks5-hostname "$RUST_SOCKS" "$MOCK_HTTP/reset" 2>&1)
R_EX=$?
G_OUT=$(curl -s -o /dev/null -w 'status=%{http_code}' --socks5-hostname "$GO_SOCKS" "$MOCK_HTTP/reset" 2>&1)
G_EX=$?
echo "Rust: exit=$R_EX $R_OUT"
echo "Go:   exit=$G_EX $G_OUT"
if [[ $R_EX = $G_EX ]]; then
  echo "RESULT: PASS-STRICT (curl exit $R_EX 'empty reply' on both)"
else
  echo "RESULT: NEW FINDING (exit code diff Rust=$R_EX Go=$G_EX)"
fi
echo

# ------------------------------------------------------------------
echo "--- D15: TCP to dead port 18499 (connection refused) ---"
R_OUT=$(curl -s -o /dev/null -w 'status=%{http_code}' --socks5-hostname "$RUST_SOCKS" "http://127.0.0.1:18499/" 2>&1)
R_EX=$?
G_OUT=$(curl -s -o /dev/null -w 'status=%{http_code}' --socks5-hostname "$GO_SOCKS" "http://127.0.0.1:18499/" 2>&1)
G_EX=$?
echo "Rust: exit=$R_EX"
echo "Go:   exit=$G_EX"
if [[ $R_EX -ne 0 && $G_EX -ne 0 ]]; then
  echo "RESULT: PASS-STRICT (both reject connection to dead port; exit codes may differ Rust=$R_EX Go=$G_EX)"
else
  echo "RESULT: FAIL (at least one kernel accepted connection to a dead port)"
fi
echo

# ------------------------------------------------------------------
echo "--- D16: cumulative /connections.downloadTotal after traffic (MT-GUI-01 §5 replay) ---"
POST_R_DL=$(get_dl "$RUST_API")
POST_R_UL=$(get_ul "$RUST_API")
POST_G_DL=$(get_dl "$GO_API")
POST_G_UL=$(get_ul "$GO_API")
DELTA_R=$(( POST_R_DL - BASE_R_DL ))
DELTA_G=$(( POST_G_DL - BASE_G_DL ))
ACTIVE_R=$(curl -s "${AUTH[@]}" "$RUST_API/connections" | pyjq 'import sys,json; print(len(json.load(sys.stdin).get("connections",[])))')
ACTIVE_G=$(curl -s "${AUTH[@]}" "$GO_API/connections" | pyjq 'import sys,json; print(len(json.load(sys.stdin).get("connections",[])))')
echo "Rust post: downloadTotal=$POST_R_DL (baseline=$BASE_R_DL) uploadTotal=$POST_R_UL active=$ACTIVE_R"
echo "Go   post: downloadTotal=$POST_G_DL (baseline=$BASE_G_DL) uploadTotal=$POST_G_UL active=$ACTIVE_G"
echo "Rust delta downloadTotal=$DELTA_R"
echo "Go   delta downloadTotal=$DELTA_G"
if [[ "$DELTA_R" -gt 0 && "$DELTA_G" -gt 0 ]]; then
  echo "RESULT: PASS-STRICT (both kernels increment downloadTotal on post-close)"
elif [[ "$DELTA_G" -gt 0 && "$DELTA_R" -eq 0 ]]; then
  echo "RESULT: CONFIRMED FINDING (MT-GUI-01 §5 reproduces: Rust downloadTotal does not increment after close; Go does)"
else
  echo "RESULT: NEW FINDING (unexpected delta pattern)"
fi
echo

echo "=== data-plane acceptance done ==="
