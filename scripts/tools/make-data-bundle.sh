#!/usr/bin/env bash
set -euo pipefail

# Create a tar.gz bundle including geoip/geosite databases and compiled rule-sets.
#
# Usage:
#   scripts/tools/make-data-bundle.sh --data ./data --rules ./out --out ./bundle

DATA_DIR="./data"
RULES_DIR="./out"
OUT_DIR="./bundle"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --data) DATA_DIR="$2"; shift 2;;
    --rules) RULES_DIR="$2"; shift 2;;
    --out) OUT_DIR="$2"; shift 2;;
    *) echo "Unknown arg: $1" >&2; exit 2;;
  esac
done

mkdir -p "$OUT_DIR"

TS=$(date +%Y%m%d%H%M%S)
PKG="singbox-data-$TS.tar.gz"

TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

mkdir -p "$TMPDIR/data" "$TMPDIR/rules"
cp -f "$DATA_DIR"/geoip.db "$DATA_DIR"/geosite.db "$TMPDIR/data/" 2>/dev/null || true
cp -f "$RULES_DIR"/*.srs "$TMPDIR/rules/" 2>/dev/null || true

tar czf "$OUT_DIR/$PKG" -C "$TMPDIR" .
(
  cd "$OUT_DIR"
  shasum -a 256 "$PKG" > "$PKG.sha256" 2>/dev/null || sha256sum "$PKG" > "$PKG.sha256"
)

echo "[✓] Created $OUT_DIR/$PKG"
cat "$OUT_DIR/$PKG.sha256"

