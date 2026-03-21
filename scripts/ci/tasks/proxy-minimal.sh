#!/usr/bin/env bash
set -euo pipefail
ROOT="$(CDPATH= cd -- "$(dirname -- "$0")"/../.. && pwd)"
cd "$ROOT"

changed="$(git status --porcelain || true)"
cleanup() {
  kill "${RUN_PID:-}" >/dev/null 2>&1 || true
  kill "${ECHO_PID:-}" >/dev/null 2>&1 || true
  rm -f "${cfg:-}"
}
trap cleanup EXIT

echo "[1/6] fmt/clippy/build/tests..."
cargo fmt --all
cargo clippy --all-targets --all-features -- -D warnings
cargo build --bins --tests
cargo test --all --tests

echo "[2/6] start echo..."
ECHO_PORT="${ECHO_PORT:-19079}"
ECHO_PORT="$ECHO_PORT" python - <<'PY' &
import socket, threading
import os
port=int(os.environ["ECHO_PORT"])
s=socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.bind(("127.0.0.1", port)); s.listen(128)
def h(c):
    try:
        while True:
            d=c.recv(65536)
            if not d: break
            c.sendall(d)
    finally:
        c.close()
def loop():
    while True:
        c,_=s.accept()
        threading.Thread(target=h,args=(c,),daemon=True).start()
loop()
PY
ECHO_PID=$!
sleep 0.1

echo "[3/6] start run with socks inbound..."
cfg="$(mktemp)"
cat > "$cfg" <<JSON
{"inbounds":[{"type":"socks","listen":"127.0.0.1","port":19080}]}
JSON
target/debug/run -c "$cfg" --format json >/tmp/run_started.json & RUN_PID=$!
sleep 0.3

echo "[4/6] probe through socks..."
ECHO_PORT="$ECHO_PORT" python - <<'PY' > /tmp/socks_probe.json
import socket, struct, json, time
import os
SOCKS=("127.0.0.1",19080)
TARGET=("127.0.0.1", int(os.environ["ECHO_PORT"]))
s=socket.socket(); s.settimeout(0.4); s.connect(SOCKS)
s.sendall(b"\x05\x01\x00"); s.recv(2)
req=b"\x05\x01\x00\x01"+socket.inet_aton(TARGET[0])+struct.pack("!H",TARGET[1])
s.sendall(req)
try:
    rep=s.recv(10); ok=(len(rep)==10 and rep[1]==0)
except Exception as e:
    ok=False
print(json.dumps({"ok":ok}))
PY

echo "[5/6] summary..."
cat <<EOF
{
  "task":"proxy_minimal",
  "git_status": $(jq -Rs . <<<"$changed"),
  "run_started": $(cat /tmp/run_started.json 2>/dev/null || echo '{"event":"started"}'),
  "socks_probe": $(cat /tmp/socks_probe.json 2>/dev/null || echo '{"ok":false}')
}
EOF
kill "${RUN_PID:-}" >/dev/null 2>&1 || true
kill "${ECHO_PID:-}" >/dev/null 2>&1 || true
