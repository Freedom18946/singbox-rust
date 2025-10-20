#!/usr/bin/env zsh
set -euo pipefail
# 用法：scripts/explain_run.zsh --sni api.example.com --ip 1.2.3.4 --port 443
args=("$@")
target="--format json"
mkdir -p .e2e/reports .e2e/visualizations
./target/debug/sb-route-explain $target "$@" > .e2e/reports/explain.json
./target/debug/sb-route-explain --format dot "$@" > .e2e/visualizations/explain.dot
jq '.decision as $d | {phase: $d.phase, rule_id: $d.rule_id, reason: $d.reason}, ($d.steps[] | select(.matched==true) | {phase, rule_id, reason})' .e2e/reports/explain.json || true
echo "[OK] explain trace -> .e2e/reports/explain.json, .e2e/visualizations/explain.dot"
