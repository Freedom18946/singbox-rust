#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"

sync_one() {
  local src="$1" dst="$2"
  if [ ! -f "$src" ]; then
    echo "Source not found: $src" >&2
    exit 1
  fi
  mkdir -p "$(dirname "$dst")"
  # Only copy when content differs
  if [ ! -f "$dst" ] || ! cmp -s "$src" "$dst"; then
    cp "$src" "$dst"
    echo "Synced: $src -> $dst"
  else
    echo "Up to date: $dst"
  fi
}

# Root -> reports
sync_one "$ROOT_DIR/GO_PARITY_MATRIX.md" "$ROOT_DIR/reports/GO_PARITY_MATRIX.md"
sync_one "$ROOT_DIR/NEXT_STEPS.md" "$ROOT_DIR/reports/NEXT_STEPS.md"

# reports -> root (keeps both in sync if reports edited)
sync_one "$ROOT_DIR/reports/GO_PARITY_MATRIX.md" "$ROOT_DIR/GO_PARITY_MATRIX.md"
sync_one "$ROOT_DIR/reports/NEXT_STEPS.md" "$ROOT_DIR/NEXT_STEPS.md"

echo "✓ Parity docs synchronized in both locations"

