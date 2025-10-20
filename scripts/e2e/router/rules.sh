#!/usr/bin/env zsh
set -euo pipefail
echo "[INFO] e2e: router rules smoke"
R=${1:-examples/rules/basic-router.rules}
echo "[RUN] cargo run -q --example router_eval -- ${R}"
cd crates/sb-core && cargo run -q --example router_eval -- ../../${R}
echo "[OK] router_eval ran"

echo "[INFO] router unit tests"
cd ../.. && cargo test -q --test router_rules -- --nocapture
echo "[OK] tests passed"