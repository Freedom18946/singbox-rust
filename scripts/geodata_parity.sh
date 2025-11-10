#!/usr/bin/env bash
set -euo pipefail

# Comprehensive Go ↔ Rust geodata CLI comparison
# Validates geoip/geosite query outputs for parity
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
Usage: $0 [OPTIONS] <geoip|geosite> <query>

Compare Rust vs Go geodata query outputs for parity validation.

OPTIONS:
  --strict        Fail on any mismatch (default: warn only)
  --ci            CI mode: machine-readable output, strict validation
  --go-bin PATH   Path to Go sing-box binary (default: \$GO_SINGBOX)
  --data-dir PATH Data directory for geoip/geosite databases
  --help          Show this help message

EXAMPLES:
  # Check if IP belongs to CN geoip
  $0 geoip cn:8.8.8.8

  # Check if domain belongs to google geosite
  $0 geosite google:youtube.com

  # CI mode
  $0 --ci geoip cn:1.1.1.1

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
DATA_DIR="${GEODATA_DIR:-.}"

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
    --data-dir)
      DATA_DIR="$2"
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

TYPE="$1"  # geoip or geosite
QUERY="$2"

# Validate inputs
if [[ "$TYPE" != "geoip" && "$TYPE" != "geosite" ]]; then
  echo "Error: TYPE must be 'geoip' or 'geosite', got: $TYPE" >&2
  exit 2
fi

if [[ ! -x "$RUST_BIN" ]]; then
  echo "Error: Rust CLI not found at $RUST_BIN" >&2
  echo "Build with: cargo build --features router" >&2
  exit 2
fi

if ! command -v jq &> /dev/null; then
  echo "Error: jq is required but not installed" >&2
  exit 2
fi

# Run Rust geodata query
if [[ "$CI_MODE" == "true" ]]; then
  echo "::group::Rust $TYPE query for $QUERY"
fi

RUST_CMD="$RUST_BIN tools $TYPE match --query $QUERY"
if [[ "$TYPE" == "geoip" ]] && [[ -f "$DATA_DIR/geoip.db" ]]; then
  RUST_CMD="$RUST_CMD --geoip-db $DATA_DIR/geoip.db"
elif [[ "$TYPE" == "geosite" ]] && [[ -f "$DATA_DIR/geosite.db" ]]; then
  RUST_CMD="$RUST_CMD --geosite-db $DATA_DIR/geosite.db"
fi

RUST_RESULT=$($RUST_CMD 2>&1 || echo "ERROR")
RUST_MATCH=$(echo "$RUST_RESULT" | grep -q "match" && echo "true" || echo "false")

if [[ "$CI_MODE" == "true" ]]; then
  echo "Rust result: match=$RUST_MATCH"
  echo "::endgroup::"
else
  echo -e "${GREEN}[Rust]${NC} $TYPE query for $QUERY"
  echo "$RUST_RESULT"
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

# Run Go geodata query
if [[ "$CI_MODE" == "true" ]]; then
  echo "::group::Go $TYPE query for $QUERY"
fi

GO_CMD="$GO_BIN tools $TYPE match --query $QUERY"
if [[ "$TYPE" == "geoip" ]] && [[ -f "$DATA_DIR/geoip.db" ]]; then
  GO_CMD="$GO_CMD --geoip-db $DATA_DIR/geoip.db"
elif [[ "$TYPE" == "geosite" ]] && [[ -f "$DATA_DIR/geosite.db" ]]; then
  GO_CMD="$GO_CMD --geosite-db $DATA_DIR/geosite.db"
fi

GO_RESULT=$($GO_CMD 2>&1 || echo "ERROR")
GO_MATCH=$(echo "$GO_RESULT" | grep -q "match" && echo "true" || echo "false")

if [[ "$CI_MODE" == "true" ]]; then
  echo "Go result: match=$GO_MATCH"
  echo "::endgroup::"
else
  echo -e "${GREEN}[Go]${NC} $TYPE query for $QUERY"
  echo "$GO_RESULT"
fi

# Compare results
MISMATCH=false

if [[ "$RUST_MATCH" != "$GO_MATCH" ]]; then
  MISMATCH=true
  if [[ "$CI_MODE" == "true" ]]; then
    echo "::error::$TYPE match mismatch: Rust=$RUST_MATCH, Go=$GO_MATCH"
  else
    echo -e "${RED}✗ Match result mismatch:${NC} Rust=$RUST_MATCH, Go=$GO_MATCH"
  fi
fi

# Detailed output in non-CI mode
if [[ "$CI_MODE" == "false" ]]; then
  echo "---"
  echo "Comparison summary:"
  echo -e "  Rust match: $RUST_MATCH"
  echo -e "  Go match:   $GO_MATCH"
fi

# Exit code
if [[ "$MISMATCH" == "true" ]]; then
  if [[ "$STRICT" == "true" ]]; then
    if [[ "$CI_MODE" == "true" ]]; then
      echo "::error::Geodata parity validation failed"
    else
      echo -e "${RED}✗ FAILED: $TYPE query outputs do not match${NC}"
    fi
    exit 1
  else
    echo -e "${YELLOW}⚠ WARN: Mismatches found but not in strict mode${NC}"
    exit 0
  fi
else
  if [[ "$CI_MODE" == "true" ]]; then
    echo "::notice::Geodata parity validation passed"
  else
    echo -e "${GREEN}✓ PASSED: $TYPE query outputs match${NC}"
  fi
  exit 0
fi
