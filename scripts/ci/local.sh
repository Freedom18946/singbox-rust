#!/usr/bin/env bash
set -euo pipefail

cargo fmt --all
bash scripts/ci/tasks/docs-links.sh
cargo check -p app --features parity
cargo test  -p app --features parity -- --nocapture
cargo clippy --workspace --all-features -- -D warnings

cargo check --workspace --all-features
cargo build --workspace --all-features --bins
cargo test  --workspace --all-features -- --nocapture
