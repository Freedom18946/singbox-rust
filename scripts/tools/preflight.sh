#!/usr/bin/env bash
set -euo pipefail

echo "[preflight] Using rustc: $(rustc --version)"

echo "[preflight] Clippy (workspace all targets)"
cargo clippy --workspace --all-targets -- -D warnings

echo "[preflight] Unit + doc tests"
cargo test -q -- --nocapture
cargo test --doc -q

echo "[preflight] Schema contracts (JSON/SARIF locks via unit tests)"
cargo test -q -p app -- tests_schema_lock

echo "[preflight] MSRV toolchain check (1.79)"
rustup toolchain install 1.79.0 -q || true
RUSTUP_TOOLCHAIN=1.79.0 cargo check -q --workspace || { echo "MSRV check failed"; exit 1; }

echo "[preflight] cargo-deny"
if ! command -v cargo-deny >/dev/null 2>&1; then cargo install cargo-deny >/dev/null 2>&1 || true; fi
cargo deny check || true

echo "[preflight] Rustdoc warnings as errors"
cargo doc --no-deps -D warnings

echo "[preflight] Minimal feature matrix (check)"
cargo check -q -p app --no-default-features

echo "[preflight] Build release artifacts (host)"
cargo build -q --release --bins

echo "[preflight] Release manifest summary"
mkdir -p dist
BIN=$(ls target/release | head -n1)
SIZE=$(stat -f%z target/release/$BIN 2>/dev/null || stat -c%s target/release/$BIN)
echo "bin,$BIN,size,$SIZE" | tee dist/preflight-summary.csv
cargo tree -q > dist/deps.txt || true
cargo deny list -q > dist/licenses.txt || true
echo "[preflight] Summary written to dist/preflight-summary.csv"

