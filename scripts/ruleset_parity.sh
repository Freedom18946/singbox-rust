#!/usr/bin/env bash
# Compare Rust vs Go rule-set CLI output for a given subcommand.
# Usage: scripts/ruleset_parity.sh <subcommand> [args]
# Example: scripts/ruleset_parity.sh validate assets/ruleset.json

set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_ROOT/.."

usage() {
    cat <<'USAGE'
Usage: scripts/ruleset_parity.sh <subcommand> [args]

Examples:
  scripts/ruleset_parity.sh validate assets/demo-ruleset.json
  scripts/ruleset_parity.sh match assets/demo-ruleset.json --domain example.com

Environment:
  RUST_BIN   Path to Rust CLI (default: target/debug/app)
  GO_SINGBOX Path to Go sing-box binary for comparison (optional)
USAGE
}

if [[ $# -lt 1 ]]; then
    usage >&2
    exit 2
fi

RUST_BIN=${RUST_BIN:-target/debug/app}
GO_BIN=${GO_SINGBOX:-}

if [[ ! -x "$RUST_BIN" ]]; then
    echo "Rust CLI not found at $RUST_BIN. Build with 'cargo build --bin app'." >&2
    exit 1
fi

TMP_FILES=()
cleanup() {
    for f in "${TMP_FILES[@]}"; do
        [[ -f "$f" ]] && rm -f "$f"
    done
}
trap cleanup EXIT

run_capture() {
    local out_var=$1
    local status_var=$2
    shift 2

    local tmp
    tmp=$(mktemp)
    TMP_FILES+=("$tmp")

    if "$@" >"$tmp" 2>&1; then
        local status=0
        printf -v "$status_var" '%s' "$status"
    else
        local status=$?
        printf -v "$status_var" '%s' "$status"
    fi
    printf -v "$out_var" '%s' "$tmp"
}

echo "[Rust] singbox-rust ruleset $*"
run_capture RUST_OUT RUST_STATUS "$RUST_BIN" ruleset "$@"
echo "--- Rust output (status=$RUST_STATUS) ---"
cat "$RUST_OUT"

if [[ -z "$GO_BIN" ]]; then
    echo "[Skip] GO_SINGBOX not set; only Rust output shown."
    exit "$RUST_STATUS"
fi

if [[ ! -x "$GO_BIN" ]]; then
    echo "Go sing-box binary not found at $GO_BIN" >&2
    exit 1
fi

echo
echo "[Go] sing-box rule-set $*"
run_capture GO_OUT GO_STATUS "$GO_BIN" rule-set "$@"
echo "--- Go output (status=$GO_STATUS) ---"
cat "$GO_OUT"

if [[ "$RUST_STATUS" -ne "$GO_STATUS" ]]; then
    echo "Status mismatch (Rust=$RUST_STATUS, Go=$GO_STATUS)" >&2
    exit 1
fi

if diff -u "$GO_OUT" "$RUST_OUT"; then
    echo "Outputs match."
    exit 0
else
    echo "Outputs differ." >&2
    exit 1
fi
