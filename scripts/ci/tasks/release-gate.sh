#!/usr/bin/env bash
set -euo pipefail
ROOT="$(CDPATH= cd -- "$(dirname -- "$0")"/../.. && pwd)"
cd "$ROOT"

changed="$(git status --porcelain || true)"
cleanup() {
  kill "${pid:-}" >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "[1/6] build & unit/integration..."
cargo fmt --all
cargo clippy --all-targets --all-features -- -D warnings
cargo build --bins --tests
cargo test --all --tests

echo "[2/6] start exporter for metrics gate..."
PROM_ADDR="127.0.0.1:19090"
target/debug/run -c /dev/null --prom-listen "$PROM_ADDR" >/dev/null 2>&1 & pid=$!
sleep 0.3

echo "[3/6] metrics sanity..."
metrics_head="$(curl -fsS "http://${PROM_ADDR}/metrics" | head -n 20 || true)"
if bash scripts/tools/validation/validate-metrics.sh >/dev/null 2>&1; then
  metrics_ok=true
else
  metrics_ok=false
fi
metric_json="$(jq -n \
  --arg addr "$PROM_ADDR" \
  --arg head "$metrics_head" \
  --argjson ok "$metrics_ok" \
  '{addr: $addr, ok: $ok, head: $head}')"

echo "[4/6] cli json contract..."
contract_json="$( bash scripts/ci/tasks/json-contract.sh )"

echo "[5/6] make rc..."
rc_json="$( bash scripts/tools/release/make-rc.sh )"

echo "[6/6] summary..."
cat <<EOF
{
  "task":"release_gate",
  "git_status": $(jq -Rs . <<<"$changed"),
  "metrics": $metric_json,
  "contract": $contract_json,
  "rc": $rc_json
}
EOF
kill "${pid:-}" >/dev/null 2>&1 || true
