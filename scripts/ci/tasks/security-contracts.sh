#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

changed="$(git status --porcelain || true)"

echo "[1/6] fmt/clippy/build/tests..."
cargo fmt --all
cargo clippy --all-targets --all-features -D warnings
cargo build --bins --tests
cargo test --all --tests

echo "[2/6] preflight (admin env flags baseline)..."
cfg="$(mktemp)"; cat > "$cfg" <<'JSON'
{"inbounds":[{"type":"http","listen":"127.0.0.1","port":19110,
              "basicAuth":{"username":"u","password":"p"}}],
 "outbounds":[{"type":"http","name":"B","server":"127.0.0.1","port":19181,
               "credentials":{"username":"u","password":"p"}}],
 "route":{"default":"B"}}
JSON
export ADMIN_LISTEN=127.0.0.1:19190
export ADMIN_TOKEN=topsecret
pre_json="$( target/debug/preflight -c "$cfg" )"

echo "[3/6] run with admin token..."
target/debug/run -c "$cfg" --format json --admin-token topsecret > /tmp/run_started_sec.json &
PID=$!
sleep 0.30

echo "[4/6] probe admin endpoints (with/without token)..."
head_wo="$(printf "GET /healthz HTTP/1.1\r\nHost: x\r\n\r\n" | nc 127.0.0.1 19190 | sed -n '1,4p' || true)"
head_wi="$(printf "GET /healthz HTTP/1.1\r\nHost: x\r\nX-Admin-Token: topsecret\r\n\r\n" | nc 127.0.0.1 19190 | sed -n '1,4p' || true)"

echo "[5/6] summarize..."
cat <<EOF
{
  "task":"security_contracts",
  "git_status": $(jq -Rs . <<<"$changed"),
  "fmt_clippy_build_tests": "ok",
  "preflight": $pre_json,
  "run_started": $(cat /tmp/run_started_sec.json 2>/dev/null || echo "{}"),
  "admin_wo_token_head": $(jq -Rs . <<<"$head_wo"),
  "admin_with_token_head": $(jq -Rs . <<<"$head_wi")
}
EOF

echo "[6/6] teardown..."
kill $PID >/dev/null 2>&1 || true