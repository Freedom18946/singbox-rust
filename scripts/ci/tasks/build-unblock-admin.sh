#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

changed="$(git status --porcelain || true)"

echo "[1/5] fmt/clippy/build/tests (scaffold default)..."
cargo fmt --all
cargo clippy --all-targets --all-features -D warnings
cargo build --bins --tests
cargo test --all --tests

echo "[2/5] run with admin http..."
cfg="$(mktemp)"; cat > "$cfg" <<'JSON'
{"inbounds":[{"type":"socks","listen":"127.0.0.1","port":19111}],
 "outbounds":[{"type":"direct","name":"direct"}],
 "route":{"default":"direct"}}
JSON
ADMIN_LISTEN=127.0.0.1:19199 target/debug/run -c "$cfg" --format json > /tmp/run_started_admin.json &
PID=$!
sleep 0.35

echo "[3/5] probe admin endpoints..."
health="$(printf "GET /healthz HTTP/1.1\r\nHost: x\r\n\r\n" | nc 127.0.0.1 19199 | sed -n '1,8p' || true)"
outs="$(printf "GET /outbounds HTTP/1.1\r\nHost: x\r\n\r\n" | nc 127.0.0.1 19199 | sed -n '1,12p' || true)"
expl="$(printf "POST /explain HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: 44\r\n\r\n{\"dest\":\"example.com:443\",\"network\":\"tcp\"}" | nc 127.0.0.1 19199 | sed -n '1,12p' || true)"

echo "[4/5] summarize..."
cat <<EOF
{
  "task":"build_unblock_admin",
  "git_status": $(jq -Rs . <<<"$changed"),
  "fmt_clippy_build_tests": "ok",
  "run_started": $(cat /tmp/run_started_admin.json 2>/dev/null || echo "{}"),
  "healthz_head": $(jq -Rs . <<<"$health"),
  "outbounds_head": $(jq -Rs . <<<"$outs"),
  "explain_head": $(jq -Rs . <<<"$expl")
}
EOF

echo "[5/5] teardown..."
kill $PID >/dev/null 2>&1 || true