#!/usr/bin/env bash
set -euo pipefail

# Prefetch CLI parity checker (Rust vs Go)
# Compares `tools prefetch stats --json` output across binaries.
# Requirements:
#   - Rust CLI built with `prefetch` + `admin_debug` features (default: target/debug/app)
#   - Optional Go sing-box binary (set via --go-bin or $GO_SINGBOX)
#   - jq

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m' # No color

usage() {
  cat <<'EOF'
Usage: scripts/prefetch_parity.sh [OPTIONS]

Compare `tools prefetch stats --json` output between the Rust CLI and a Go sing-box binary.

Options:
  --rust-bin PATH   Path to Rust CLI binary (default: $RUST_APP or target/debug/app)
  --go-bin PATH     Path to Go sing-box binary (default: $GO_SINGBOX if set)
  --strict          Exit with status 1 on mismatch (default: warn only)
  --ci              CI mode (enables --strict and GitHub log groups)
  --help            Show this help message

Examples:
  # Basic comparison (Rust only if GO_SINGBOX unset)
  scripts/prefetch_parity.sh

  # Provide explicit Go binary and run in strict mode
  scripts/prefetch_parity.sh --go-bin ~/bin/sing-box --strict

Environment:
  RUST_APP   Override path to Rust CLI (same as --rust-bin)
  GO_SINGBOX Override path to Go CLI (same as --go-bin)
EOF
}

STRICT=false
CI_MODE=false
RUST_BIN="${RUST_APP:-target/debug/app}"
GO_BIN="${GO_SINGBOX:-}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --rust-bin)
      RUST_BIN="$2"
      shift 2
      ;;
    --go-bin)
      GO_BIN="$2"
      shift 2
      ;;
    --strict)
      STRICT=true
      shift
      ;;
    --ci)
      CI_MODE=true
      STRICT=true
      shift
      ;;
    --help)
      usage
      exit 0
      ;;
    --)
      shift
      break
      ;;
    -*)
      echo "Unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
    *)
      echo "Unexpected positional argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [[ $# -gt 0 ]]; then
  echo "This script does not accept positional arguments: $*" >&2
  usage >&2
  exit 2
fi

if [[ ! -x "$RUST_BIN" ]]; then
  echo "Error: Rust CLI not found at $RUST_BIN" >&2
  echo "Hint: cargo build --features \"prefetch,admin_debug\"" >&2
  exit 2
fi

if ! command -v jq >/dev/null 2>&1; then
  echo "Error: jq is required but not installed" >&2
  exit 2
fi

run_rust() {
  local stderr_file
  stderr_file=$(mktemp)
  if ! RUST_OUTPUT=$("$RUST_BIN" tools prefetch stats --json 2>"$stderr_file"); then
    cat "$stderr_file" >&2 || true
    rm -f "$stderr_file"
    echo "Rust CLI command failed" >&2
    exit 2
  fi
  if [[ -s "$stderr_file" ]]; then
    cat "$stderr_file" >&2
  fi
  rm -f "$stderr_file"

  if [[ "$CI_MODE" == "true" ]]; then
    echo "::group::Rust prefetch stats"
    echo "$RUST_OUTPUT"
    echo "::endgroup::"
  else
    echo -e "${GREEN}[Rust]${NC} tools prefetch stats --json"
    echo "$RUST_OUTPUT"
  fi

  if ! RUST_JSON=$(printf '%s\n' "$RUST_OUTPUT" | jq -S '.'); then
    echo "Failed to parse Rust output as JSON" >&2
    exit 2
  fi
}

run_go() {
  if [[ -z "$GO_BIN" || ! -x "$GO_BIN" ]]; then
    if [[ "$STRICT" == "true" ]]; then
      echo -e "${YELLOW}Warning: Go binary not configured; skipping comparison${NC}" >&2
    else
      echo "[Skip] GO_SINGBOX not set; only Rust output shown."
    fi
    exit 0
  fi

  local stderr_file
  stderr_file=$(mktemp)
  set +e
  GO_OUTPUT=$("$GO_BIN" tools prefetch stats --json 2>"$stderr_file")
  local status=$?
  set -e
  local err
  err=$(cat "$stderr_file")
  rm -f "$stderr_file"

  if [[ $status -ne 0 ]]; then
    if grep -qi "unknown command" <<<"$err"; then
      if [[ "$STRICT" == "true" ]]; then
        echo -e "${YELLOW}Warning: Go binary does not support 'tools prefetch'; skipping${NC}" >&2
      else
        echo "[Skip] Go binary does not implement 'tools prefetch'; only Rust output shown."
      fi
      exit 0
    fi
    echo "$err" >&2
    echo "Go CLI command failed" >&2
    exit 2
  fi

  if [[ -n "$err" ]]; then
    echo "$err" >&2
  fi

  if [[ "$CI_MODE" == "true" ]]; then
    echo "::group::Go prefetch stats"
    echo "$GO_OUTPUT"
    echo "::endgroup::"
  else
    echo -e "${GREEN}[Go]${NC} tools prefetch stats --json"
    echo "$GO_OUTPUT"
  fi

  if ! GO_JSON=$(printf '%s\n' "$GO_OUTPUT" | jq -S '.'); then
    echo "Failed to parse Go output as JSON" >&2
    exit 2
  fi
}

compare_outputs() {
  if [[ "$RUST_JSON" == "$GO_JSON" ]]; then
    if [[ "$CI_MODE" == "true" ]]; then
      echo "::notice::Prefetch stats match between Rust and Go"
    else
      echo -e "${GREEN}✓ Prefetch stats outputs match${NC}"
    fi
    exit 0
  fi

  if [[ "$CI_MODE" == "true" ]]; then
    echo "::error::Prefetch stats mismatch between Rust and Go"
  else
    echo -e "${RED}✗ Prefetch stats mismatch${NC}"
    diff -u <(echo "$RUST_JSON") <(echo "$GO_JSON") || true
  fi

  if [[ "$STRICT" == "true" ]]; then
    exit 1
  else
    echo -e "${YELLOW}Warning: mismatch detected (non-strict mode)${NC}"
    exit 0
  fi
}

run_rust
run_go
compare_outputs
