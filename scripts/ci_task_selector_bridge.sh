#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

changed="$(git status --porcelain || true)"

echo "[1/5] fmt/clippy/build/tests..."
cargo fmt --all
cargo clippy --all-targets --all-features -D warnings
cargo build --bins --tests
cargo test --all --tests

echo "[2/5] preflight with selector..."
cfg="$(mktemp)"; cat > "$cfg" <<'JSON'
{"inbounds":[{"type":"socks","listen":"127.0.0.1","port":19083}],
 "outbounds":[
   {"type":"direct","name":"A"},
   {"type":"direct","name":"B"},
   {"type":"selector","name":"S","members":["A","B"]}
 ],
 "route":{"rules":[{"domain":["*"],"outbound":"S"}]}}
JSON
pre_json="$( target/debug/preflight -c "$cfg" )"

echo "[3/5] run with selector..."
target/debug/run -c "$cfg" --format json > /tmp/run_started_selector.json &
PID=$!
sleep 0.4

echo "[4/5] summarize..."
cat <<EOF
{
  "task":"selector_bridge",
  "git_status": $(jq -Rs . <<<"$changed"),
  "preflight": $pre_json,
  "run_started": $(cat /tmp/run_started_selector.json)
}
EOF

echo "[5/5] teardown..."
kill $PID >/dev/null 2>&1 || true