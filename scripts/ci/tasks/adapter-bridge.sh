#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

changed="$(git status --porcelain || true)"

echo "[1/6] build & test (scaffold on)..."
cargo fmt --all
cargo clippy --all-targets --all-features -D warnings
cargo test --features scaffold --all --tests

echo "[2/6] run in scaffold mode..."
cfg="$(mktemp)"; cat > "$cfg" <<'JSON'
{"inbounds":[{"type":"socks","listen":"127.0.0.1","port":19081}],"outbounds":[{"type":"direct","name":"direct"}]}
JSON
ADAPTER_FORCE=scaffold target/debug/run -c "$cfg" --format json > /tmp/run_started_scaffold.json &
PID1=$!
sleep 0.2

echo "[3/6] probe socks (scaffold)..."
python - <<'PY' > /tmp/probe_scaffold.json
import socket, struct, json
s=socket.socket(); s.settimeout(0.5); s.connect(("127.0.0.1",19081))
s.sendall(b"\x05\x01\x00"); s.recv(2)
s.sendall(b"\x05\x01\x00\x01"+b"\x7f\x00\x00\x01"+b"\x00\x09")
ok = True
try:
    s.recv(10)
except Exception:
    ok = False
print(json.dumps({"ok":ok}))
PY
kill $PID1 >/dev/null 2>&1 || true

echo "[4/6] (optional) adapter mode sanity..."
adapter_status="not_enabled"
if cargo tree -p sb-adapter >/dev/null 2>&1; then
  adapter_status="present"
  ADAPTER_FORCE=adapter target/debug/run -c "$cfg" --format json > /tmp/run_started_adapter.json &
  PID2=$!; sleep 0.2; kill $PID2 >/dev/null 2>&1 || true
fi

echo "[5/6] pack summary..."
cat <<EOF
{
  "task":"adapter_bridge",
  "git_status": $(jq -Rs . <<<"$changed"),
  "fmt_clippy_build_tests":"ok",
  "scaffold_run": $(cat /tmp/run_started_scaffold.json 2>/dev/null || echo "{}"),
  "probe_scaffold": $(cat /tmp/probe_scaffold.json 2>/dev/null || echo "{}"),
  "adapter_status": "$adapter_status",
  "adapter_run": $(cat /tmp/run_started_adapter.json 2>/dev/null || echo "{}")
}
EOF

echo "[6/6] done."