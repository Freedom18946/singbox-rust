#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

changed="$(git status --porcelain || true)"

echo "[1/6] fmt/clippy/build/tests (default=scaffold, dns_http off)..."
cargo fmt --all
cargo clippy --all-targets --all-features -D warnings
cargo build --bins --tests
cargo test --all --tests

echo "[2/6] preflight sanity..."
cfg="$(mktemp)"; cat > "$cfg" <<'JSON'
{"inbounds":[{"type":"socks","listen":"127.0.0.1","port":19211}],
 "outbounds":[{"type":"direct","name":"direct"}],
 "route":{"default":"direct"}}
JSON
pjson="$( target/debug/preflight -c "$cfg" )"

echo "[3/6] run with admin http..."
ADMIN_LISTEN=127.0.0.1:19295 target/debug/run -c "$cfg" --format json > /tmp/run_started_break.json &
PID=$!
sleep 0.35

echo "[4/6] probe admin..."
health="$(printf "GET /healthz HTTP/1.1\r\nHost: x\r\n\r\n" | nc 127.0.0.1 19295 | sed -n '1,8p' || true)"
outs="$(printf "GET /outbounds HTTP/1.1\r\nHost: x\r\n\r\n" | nc 127.0.0.1 19295 | sed -n '1,12p' || true)"
expl="$(printf "POST /explain HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: 44\r\n\r\n{\"dest\":\"example.com:443\",\"network\":\"tcp\"}" | nc 127.0.0.1 19295 | sed -n '1,12p' || true)"

echo "[5/6] summarize..."
cat <<EOF
{
  "task":"break_cycle",
  "git_status": $(jq -Rs . <<<"$changed"),
  "fmt_clippy_build_tests": "ok",
  "preflight": $pjson,
  "run_started": $(cat /tmp/run_started_break.json 2>/dev/null || echo "{}"),
  "healthz_head": $(jq -Rs . <<<"$health"),
  "outbounds_head": $(jq -Rs . <<<"$outs"),
  "explain_head": $(jq -Rs . <<<"$expl")
}
EOF

echo "[6/6] teardown..."
kill $PID >/dev/null 2>&1 || true