#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

changed="$(git status --porcelain || true)"

echo "[1/6] build & unit/integration..."
cargo fmt --all
cargo clippy --all-targets --all-features -D warnings
cargo build --bins --tests
cargo test --all --tests

echo "[2/6] start exporter for metrics gate..."
PROM_ADDR="127.0.0.1:19090"
target/debug/run -c /dev/null --prom-listen "$PROM_ADDR" >/dev/null 2>&1 & pid=$!
sleep 0.3

echo "[3/6] metrics sanity..."
metric_json="$( cargo run --quiet --bin metrics_sanity -- 127.0.0.1:19090 || true )"

echo "[4/6] cli json contract..."
contract_json="$( bash scripts/ci_task_json_contract.sh )"

echo "[5/6] make rc..."
rc_json="$( bash scripts/make_rc.sh )"

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
kill "$pid" >/dev/null 2>&1 || true