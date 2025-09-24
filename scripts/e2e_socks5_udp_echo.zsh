#!/usr/bin/env zsh
set -euo pipefail

# 环境
SB_SOCKS_ADDR="${SB_SOCKS_ADDR:-127.0.0.1:11080}"
ECHO_PORT="${ECHO_PORT:-19999}"
COUNT="${COUNT:-10}"

echo "[STEP] 启动本地 UDP echo ${ECHO_PORT}"
python3 - "$ECHO_PORT" <<'PY' &
import socket, sys
addr=("127.0.0.1", int(sys.argv[1]))
s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(addr)
while True:
    d,a = s.recvfrom(65535)
    s.sendto(d, a)
PY
ECHO_PID=$!
sleep 0.2

cleanup() { kill $ECHO_PID 2>/dev/null || true; }
trap cleanup EXIT

echo "[STEP] 经过 SOCKS5-UDP 发送 ${COUNT} 次"
python3 - "$SB_SOCKS_ADDR" "$ECHO_PORT" "$COUNT" <<'PY'
import socket, sys, struct
proxy_host, proxy_port = sys.argv[1].split(":"); proxy_port=int(proxy_port)
dst_port = int(sys.argv[2]); count=int(sys.argv[3])
cli = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
def pack(dst_host, dst_port, payload):
    # RSV(2)=0, FRAG=0, ATYP=1(IPV4), DST.ADDR=127.0.0.1, DST.PORT
    hdr = b"\x00\x00\x00\x01" + socket.inet_aton("127.0.0.1") + struct.pack("!H", dst_port)
    return hdr + payload
def unpack(buf):
    return buf[10:]
for i in range(count):
    p = pack("127.0.0.1", dst_port, f"hello-{i}".encode())
    cli.sendto(p, (proxy_host, proxy_port))
    cli.settimeout(1.0)
    d,_=cli.recvfrom(65535)
    assert unpack(d).startswith(b"hello-")
print("OK")
PY

echo "[OK] SOCKS5-UDP echo ok"