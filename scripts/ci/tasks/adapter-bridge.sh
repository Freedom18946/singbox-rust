#!/usr/bin/env bash
set -euo pipefail

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")"/../.. && pwd)"
cd "$ROOT"

echo "[1/4] registry hard-error contract"
cargo test -p app --test adapter_bridge_registry

echo "[2/4] workspace feature closure"
cargo check --workspace --all-features

echo "[3/4] retired feature scan"
if rg -n 'feature = "scaffold"|features = \[[^]]*"scaffold"' crates app; then
  echo "retired scaffold feature reference found" >&2
  exit 1
fi

echo "[4/4] formatting"
cargo fmt --all -- --check
