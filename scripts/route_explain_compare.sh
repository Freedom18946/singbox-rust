#!/usr/bin/env bash
set -euo pipefail

# Compare Rust vs Go route explain outputs for a destination using the same config.
# Requirements:
# - singbox-rust compiled with features: router, explain
# - Go sing-box binary available as $GO_SINGBOX (optional)
# - jq installed

if [[ $# -lt 2 ]]; then
  echo "Usage: $0 <config.json|yaml> <dest-host:port>" >&2
  exit 1
fi

CFG="$1"
DEST="$2"

RUST_BIN="target/debug/app"
GO_BIN="${GO_SINGBOX:-}"

if [[ ! -x "$RUST_BIN" ]]; then
  echo "Rust CLI not found at $RUST_BIN. Build with: cargo build --features router,explain" >&2
  exit 1
fi

echo "[Rust] route --explain for $DEST"
RUST_JSON="$($RUST_BIN route -c "$CFG" --dest "$DEST" --explain --format json | jq -c .)"
echo "$RUST_JSON" | jq .

if [[ -n "$GO_BIN" ]]; then
  echo "[Go] sing-box route --explain for $DEST"
  GO_JSON="$($GO_BIN route --config "$CFG" --dest "$DEST" --explain --format json | jq -c .)"
  echo "$GO_JSON" | jq .
  echo "---";
  echo "Diff (Rust vs Go) on keys: matched_rule, chain, outbound"
  echo "Rust:"; echo "$RUST_JSON" | jq '{matched_rule, chain, outbound}'
  echo "Go  :"; echo "$GO_JSON" | jq '{matched_rule, chain, outbound}'
else
  echo "[Skip] GO_SINGBOX not set; only Rust output shown."
fi

