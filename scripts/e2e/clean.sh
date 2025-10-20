#!/usr/bin/env bash
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
OUT="$ROOT/.e2e"
mkdir -p "$OUT"
find "$OUT" -mindepth 1 -maxdepth 1 ! -name 'README.md' -exec rm -rf {} +
echo "[e2e] cleaned $OUT"

