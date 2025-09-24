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

echo "[2/6] boot sample config..."
cfg="$(mktemp)"; cat > "$cfg" <<'JSON'
{"inbounds":[{"type":"http","listen":"127.0.0.1","port":19110}],
 "outbounds":[{"type":"http","name":"B","server":"127.0.0.1","port":19181}],
 "route":{"default":"B"}}
JSON

export ADMIN_LISTEN=127.0.0.1:19190
export ADMIN_TOKEN=topsecret

echo "[3/6] start run (json)..."
target/debug/run -c "$cfg" --format json --admin-token topsecret --grace 1500 --reload-path "$cfg" > /tmp/run_started_reload.json 2>/dev/null &
PID=$!
sleep 0.35

echo "[4/6] call /reload..."
reload_req="$(mktemp)"
# 切换 inbound 端口：19110 -> 19111
cat > "$reload_req" <<'JSON'
{"config":{
  "inbounds":[{"type":"http","listen":"127.0.0.1","port":19111}],
  "outbounds":[{"type":"http","name":"B","server":"127.0.0.1","port":19181}],
  "route":{"default":"B"}
}}
JSON

reload_resp="$(printf "POST /reload HTTP/1.1\r\nHost: x\r\nX-Admin-Token: topsecret\r\nContent-Type: application/json\r\nContent-Length: %s\r\n\r\n%s" \
  "$(wc -c < "$reload_req")" "$(cat "$reload_req")" \
  | nc 127.0.0.1 19190 | sed -n '1,200p' || true)"

echo "[5/6] summarize..."
head_wo="$(printf "GET /healthz HTTP/1.1\r\nHost: x\r\n\r\n" | nc 127.0.0.1 19190 | sed -n '1,6p' || true)"
head_wi="$(printf "GET /healthz HTTP/1.1\r\nHost: x\r\nX-Admin-Token: topsecret\r\n\r\n" | nc 127.0.0.1 19190 | sed -n '1,6p' || true)"

cat <<EOF
{
  "task":"hot_reload_graceful_shutdown",
  "git_status": $(jq -Rs . <<<"$changed"),
  "fmt_clippy_build_tests": "ok",
  "run_started": $(cat /tmp/run_started_reload.json 2>/dev/null || echo "{}"),
  "reload_result_raw": $(jq -Rs . <<<"$reload_resp"),
  "admin_wo_token_head": $(jq -Rs . <<<"$head_wo"),
  "admin_with_token_head": $(jq -Rs . <<<"$head_wi")
}
EOF

echo "[6/6] teardown (graceful SIGTERM)..."
kill $PID >/dev/null 2>&1 || true
wait $PID 2>/dev/null || true