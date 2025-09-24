#!/usr/bin/env bash
set -euo pipefail

cargo fmt --all
cargo clippy --workspace --all-features -- -D warnings

cargo check --workspace --all-features
cargo test  --workspace --all-features -- --nocapture