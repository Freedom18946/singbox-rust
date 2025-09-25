#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"

OUT_DIR=target/coverage
mkdir -p "$OUT_DIR"

if ! command -v cargo-llvm-cov >/dev/null 2>&1; then
  echo "[cov] installing cargo-llvm-cov..."
  cargo install cargo-llvm-cov >/dev/null 2>&1 || {
    echo "[cov] install failed; please install manually"; exit 1; }
fi

echo "[cov] running tests with coverage..."
cargo llvm-cov --workspace --all-features --html --lcov --output-path "$OUT_DIR/lcov.info" --html-output "$OUT_DIR/html"
genhtml "$OUT_DIR/lcov.info" --output-directory "$OUT_DIR" >/dev/null 2>&1 || true

echo "[cov] output: $OUT_DIR/index.html (or $OUT_DIR/html/index.html)"

