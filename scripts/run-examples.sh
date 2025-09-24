#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

cfg="${1:-examples/configs/full_stack.json}"
export RUST_LOG="${RUST_LOG:-info}"
export SBR_CONFIG="$cfg"
echo "Using config: $SBR_CONFIG"
cargo run -p singbox-rust --all-features