#!/usr/bin/env bash
set -euo pipefail

# Compile all JSON rule-sets in a directory to .srs into an output directory.
#
# Usage:
#   scripts/tools/compile-rulesets.sh --in rules/ --out out/ [--version N] [--bin path]
#
# Defaults:
#   --bin target/debug/app (built via cargo build)

IN_DIR=""
OUT_DIR=""
VERSION=""
BIN="target/debug/app"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --in) IN_DIR="$2"; shift 2;;
    --out) OUT_DIR="$2"; shift 2;;
    --version) VERSION="$2"; shift 2;;
    --bin) BIN="$2"; shift 2;;
    *) echo "Unknown arg: $1" >&2; exit 2;;
  esac
done

if [[ -z "$IN_DIR" || -z "$OUT_DIR" ]]; then
  echo "Usage: $0 --in rules/ --out out/ [--version N] [--bin path]" >&2
  exit 2
fi

mkdir -p "$OUT_DIR"

shopt -s nullglob
count=0
for f in "$IN_DIR"/*.json; do
  base=$(basename "$f" .json)
  out="$OUT_DIR/$base.srs"
  if [[ -n "$VERSION" ]]; then
    "$BIN" rule-set compile "$f" --version "$VERSION" --output "$out"
  else
    "$BIN" rule-set compile "$f" --output "$out"
  fi
  count=$((count+1))
done
shopt -u nullglob

echo "[✓] Compiled $count rule-sets into $OUT_DIR"

