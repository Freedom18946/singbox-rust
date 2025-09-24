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

echo "[2/6] preflight..."
cfg="$(mktemp)"; cat > "$cfg" <<'JSON'
{"inbounds":[{"type":"socks","listen":"127.0.0.1","port":19082}],
 "outbounds":[{"type":"direct","name":"direct"}],
 "route":{"rules":[{"domain":["*"],"outbound":"direct"}]}}
JSON
pre_json="$( target/debug/preflight -c "$cfg" )"

echo "[3/6] run + health..."
PROM_LISTEN="${PROM_LISTEN:-}"
HEALTH=1 target/debug/run -c "$cfg" --format json > /tmp/run_started.json &
PID=$!
sleep 0.5

echo "[4/6] probe outbound_up (optional /metrics)..."
metrics=""
if [ -n "${PROM_LISTEN}" ]; then
  metrics="$(curl -sS "http://${PROM_LISTEN}/metrics" | grep -E "^outbound_up" | head -n 3 || true)"
fi

echo "[5/6] summarize..."
cat <<EOF
{
  "task":"runtime_health",
  "git_status": $(jq -Rs . <<<"$changed"),
  "preflight": $pre_json,
  "run_started": $(cat /tmp/run_started.json),
  "metrics_head": $(jq -Rs . <<<"$metrics")
}
EOF

echo "[6/6] teardown..."
kill $PID >/dev/null 2>&1 || true