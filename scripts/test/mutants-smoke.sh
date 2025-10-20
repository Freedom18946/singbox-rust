#!/usr/bin/env bash
set -euo pipefail

if ! command -v cargo-mutants >/dev/null 2>&1; then
  echo "[mutants] installing cargo-mutants..."
  cargo install cargo-mutants >/dev/null 2>&1 || {
    echo "[mutants] install failed; please install manually"; exit 1; }
fi

crates=(sb-core sb-adapters)
for c in "${crates[@]}"; do
  echo "[mutants] running smoke on $c"
  cargo mutants -p "$c" --no-shuffle --in-place --timeout 60 || true
done

echo "[mutants] done (smoke)."

