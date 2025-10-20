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

echo "[2/5] preflight http+selector..."
cfg="$(mktemp)"; cat > "$cfg" <<'JSON'
{"inbounds":[{"type":"http","listen":"127.0.0.1","port":19084}],
 "outbounds":[
   {"type":"socks","name":"A","server":"127.0.0.1","port":19180},
   {"type":"http","name":"B","server":"127.0.0.1","port":19181},
   {"type":"selector","name":"S","members":["A","B"]}
 ],
 "route":{"rules":[{"domain":["*"],"outbound":"S"}]}}
JSON
pre_json="$( target/debug/preflight -c "$cfg" )"

echo "[3/5] run http inbound (no proxies actually spawned here; tests cover E2E)..."
target/debug/run -c "$cfg" --format json > /tmp/run_started_http.json &
PID=$!
sleep 0.2

echo "[4/5] summarize..."
cat <<EOF
{
  "task":"inbounds_upstreams",
  "git_status": $(jq -Rs . <<<"$changed"),
  "preflight": $pre_json,
  "run_started": $(cat /tmp/run_started_http.json)
}
EOF

echo "[5/5] teardown..."
kill $PID >/dev/null 2>&1 || true