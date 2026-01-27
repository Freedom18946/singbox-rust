#!/usr/bin/env bash
set -e
bash scripts/ci/tasks/docs-links.sh
bash scripts/ci/accept.sh

# 按平台判定门槛
if uname | grep -qi linux; then
  echo "[strict] Linux platform: requiring pprof.enabled=true and soak.passed=true"
  jq -e '.pprof.enabled==true and .soak.passed==true' target/acceptance.json >/dev/null
  jq -e '.release_matrix.sha256_lines>=3' target/acceptance.json >/dev/null
else
  echo "[strict] Non-Linux platform: requiring soak.passed=true only"
  jq -e '.soak.passed==true' target/acceptance.json >/dev/null
  jq -e '.release_matrix.sha256_lines>=2' target/acceptance.json >/dev/null
fi
