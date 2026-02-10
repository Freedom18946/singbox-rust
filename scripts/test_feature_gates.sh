#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/.." >/dev/null 2>&1 && pwd)"

cd "${REPO_ROOT}"
MODE="${SB_FEATURE_MATRIX_MODE:-smoke}"

if [[ "$MODE" == "full" ]]; then
  echo "[feature-matrix] Running full matrix via xtask"
  cargo run -p xtask -- feature-matrix "$@"
  exit 0
fi

echo "[feature-matrix] Running smoke gate checks (set SB_FEATURE_MATRIX_MODE=full for full matrix)"
cargo check -p app --features acceptance
cargo check -p sb-core --features router
cargo check -p sb-adapters --features "router,adapter-shadowsocks,shadowsocks"
