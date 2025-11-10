#!/usr/bin/env bash
set -euo pipefail

# Comprehensive Go ↔ Rust route explain comparison with automated validation
# Requirements:
# - Rust CLI compiled with features: router, explain
# - Go sing-box binary (optional, set via GO_SINGBOX env var)
# - jq installed

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m' # No Color

usage() {
  cat <<EOF
Usage: $0 [OPTIONS] <config.json|yaml> <dest-host:port>

Compare Rust vs Go route explain outputs for routing parity validation.

OPTIONS:
  --strict        Fail on any mismatch (default: warn only)
  --ci            CI mode: machine-readable output, strict validation
  --go-bin PATH   Path to Go sing-box binary (default: \$GO_SINGBOX)
  --help          Show this help message

EXAMPLES:
  # Basic comparison (manual inspection)
  $0 config.json example.com:443

  # Strict mode for local validation
  $0 --strict config.json example.com:443

  # CI mode with custom Go binary
  $0 --ci --go-bin /usr/local/bin/sing-box config.json example.com:443

EXIT CODES:
  0  - Match (or Go binary not available)
  1  - Mismatch (in strict/CI mode)
  2  - Usage/runtime error
EOF
}

# Defaults
STRICT=false
CI_MODE=false
GO_BIN="${GO_SINGBOX:-}"
RUST_BIN="target/debug/app"

# Parse options
while [[ $# -gt 0 ]]; do
  case $1 in
    --strict)
      STRICT=true
      shift
      ;;
    --ci)
      CI_MODE=true
      STRICT=true
      shift
      ;;
    --go-bin)
      GO_BIN="$2"
      shift 2
      ;;
    --help)
      usage
      exit 0
      ;;
    -*)
      echo "Unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
    *)
      break
      ;;
  esac
done

if [[ $# -lt 2 ]]; then
  usage >&2
  exit 2
fi

CFG="$1"
DEST="$2"

# Validate inputs
if [[ ! -f "$CFG" ]]; then
  echo "Error: Config file not found: $CFG" >&2
  exit 2
fi

if [[ ! -x "$RUST_BIN" ]]; then
  echo "Error: Rust CLI not found at $RUST_BIN" >&2
  echo "Build with: cargo build --features router,explain" >&2
  exit 2
fi

if ! command -v jq &> /dev/null; then
  echo "Error: jq is required but not installed" >&2
  exit 2
fi

# Run Rust route explain
if [[ "$CI_MODE" == "true" ]]; then
  echo "::group::Rust route explain for $DEST"
fi
RUST_JSON="$($RUST_BIN route -c "$CFG" --dest "$DEST" --explain --format json 2>&1 | jq -c . 2>/dev/null || echo '{}')"
RUST_OUTBOUND=$(echo "$RUST_JSON" | jq -r '.outbound // "PARSE_ERROR"')
RUST_RULE=$(echo "$RUST_JSON" | jq -r '.matched_rule // "none"')
RUST_CHAIN=$(echo "$RUST_JSON" | jq -r '.chain | length // 0')

if [[ "$CI_MODE" == "true" ]]; then
  echo "Rust result: outbound=$RUST_OUTBOUND, rule=$RUST_RULE, chain_length=$RUST_CHAIN"
  echo "::endgroup::"
else
  echo -e "${GREEN}[Rust]${NC} route --explain for $DEST"
  echo "$RUST_JSON" | jq .
fi

# Check if Go binary is available
if [[ -z "$GO_BIN" ]] || [[ ! -x "$GO_BIN" ]]; then
  if [[ "$STRICT" == "true" ]]; then
    echo -e "${YELLOW}Warning: Go sing-box binary not available, skipping comparison${NC}" >&2
  else
    echo "[Skip] GO_SINGBOX not set; only Rust output shown."
  fi
  exit 0
fi

# Run Go route explain
if [[ "$CI_MODE" == "true" ]]; then
  echo "::group::Go route explain for $DEST"
fi
GO_JSON="$($GO_BIN route --config "$CFG" --dest "$DEST" --explain --format json 2>&1 | jq -c . 2>/dev/null || echo '{}')"
GO_OUTBOUND=$(echo "$GO_JSON" | jq -r '.outbound // "PARSE_ERROR"')
GO_RULE=$(echo "$GO_JSON" | jq -r '.matched_rule // "none"')
GO_CHAIN=$(echo "$GO_JSON" | jq -r '.chain | length // 0')

if [[ "$CI_MODE" == "true" ]]; then
  echo "Go result: outbound=$GO_OUTBOUND, rule=$GO_RULE, chain_length=$GO_CHAIN"
  echo "::endgroup::"
else
  echo -e "${GREEN}[Go]${NC} sing-box route --explain for $DEST"
  echo "$GO_JSON" | jq .
fi

# Compare results
MISMATCH=false

if [[ "$RUST_OUTBOUND" != "$GO_OUTBOUND" ]]; then
  MISMATCH=true
  if [[ "$CI_MODE" == "true" ]]; then
    echo "::error::Outbound mismatch: Rust=$RUST_OUTBOUND, Go=$GO_OUTBOUND"
  else
    echo -e "${RED}✗ Outbound mismatch:${NC} Rust=$RUST_OUTBOUND, Go=$GO_OUTBOUND"
  fi
fi

if [[ "$RUST_RULE" != "$GO_RULE" ]]; then
  MISMATCH=true
  if [[ "$CI_MODE" == "true" ]]; then
    echo "::warning::Matched rule mismatch: Rust=$RUST_RULE, Go=$GO_RULE"
  else
    echo -e "${YELLOW}⚠ Matched rule mismatch:${NC} Rust=$RUST_RULE, Go=$GO_RULE"
  fi
fi

if [[ "$RUST_CHAIN" != "$GO_CHAIN" ]]; then
  # Chain length mismatch is less critical, only warn
  if [[ "$CI_MODE" == "true" ]]; then
    echo "::warning::Chain length mismatch: Rust=$RUST_CHAIN, Go=$GO_CHAIN"
  else
    echo -e "${YELLOW}⚠ Chain length mismatch:${NC} Rust=$RUST_CHAIN, Go=$GO_CHAIN"
  fi
fi

# Detailed diff in non-CI mode
if [[ "$CI_MODE" == "false" ]]; then
  echo "---"
  echo "Detailed comparison (Rust vs Go):"
  echo -e "${GREEN}Rust:${NC}"
  echo "$RUST_JSON" | jq '{matched_rule, chain, outbound, dest}'
  echo -e "${GREEN}Go  :${NC}"
  echo "$GO_JSON" | jq '{matched_rule, chain, outbound, dest}'
fi

# Exit code
if [[ "$MISMATCH" == "true" ]]; then
  if [[ "$STRICT" == "true" ]]; then
    if [[ "$CI_MODE" == "true" ]]; then
      echo "::error::Route parity validation failed"
    else
      echo -e "${RED}✗ FAILED: Route explain outputs do not match${NC}"
    fi
    exit 1
  else
    echo -e "${YELLOW}⚠ WARN: Mismatches found but not in strict mode${NC}"
    exit 0
  fi
else
  if [[ "$CI_MODE" == "true" ]]; then
    echo "::notice::Route parity validation passed"
  else
    echo -e "${GREEN}✓ PASSED: Route explain outputs match${NC}"
  fi
  exit 0
fi
