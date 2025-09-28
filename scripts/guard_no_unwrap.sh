#!/bin/bash
#
# guard_no_unwrap.sh - Zero unwrap/expect/panic guard for production code
#
# Scans src/ directories (excluding tests/, benches/, examples/, and build.rs)
# and ensures no .unwrap(), .expect(), or panic! calls exist in production code.
# Exits with code 1 if violations are found, 0 otherwise.
#
# Usage:
#   scripts/guard_no_unwrap.sh            # Enforce zero violations
#   scripts/guard_no_unwrap.sh --baseline # Allow violations for baseline setup

set -euo pipefail

# Parse arguments
BASELINE_MODE=0
if [[ "${1:-}" == "--baseline" ]]; then
    BASELINE_MODE=1
fi

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "🔍 Scanning for unwrap/expect/panic in production code..."

# Define search patterns
PATTERNS=(
    "\.unwrap\(\)"
    "\.expect\("
    "panic!\("
)

# Search paths - include src/ from workspace root and all crates
SEARCH_PATHS=(
    "app/src"
    "crates/sb-core/src"
    "crates/sb-adapters/src"
    "crates/sb-api/src"
    "crates/sb-config/src"
    "crates/sb-metrics/src"
    "crates/sb-platform/src"
    "crates/sb-proto/src"
    "crates/sb-runtime/src"
    "crates/sb-subscribe/src"
    "crates/sb-transport/src"
    "crates/sb-types/src"
)

# Exclusion patterns - files/directories to ignore
EXCLUDE_GLOBS=(
    "*/tests/*"
    "*/benches/*"
    "*/examples/*"
    "*/target/*"
    "**/build.rs"
    "**/*test*.rs"
    "**/*bench*.rs"
)

# Build exclusion arguments for ripgrep
EXCLUDE_ARGS=()
for glob in "${EXCLUDE_GLOBS[@]}"; do
    EXCLUDE_ARGS+=(--glob "!${glob}")
done

VIOLATIONS_FOUND=0
TOTAL_MATCHES=0

for pattern in "${PATTERNS[@]}"; do
    echo "  Checking pattern: ${pattern}"

    # Use ripgrep to search with exclusions
    MATCHES=$(rg "${pattern}" "${SEARCH_PATHS[@]}" "${EXCLUDE_ARGS[@]}" --line-number --column --no-heading --color=never || true)

    if [[ -n "$MATCHES" ]]; then
        echo -e "${RED}❌ Found violations for pattern: ${pattern}${NC}"
        echo "$MATCHES"
        echo
        VIOLATIONS_FOUND=1
        MATCH_COUNT=$(echo "$MATCHES" | wc -l | xargs)
        TOTAL_MATCHES=$((TOTAL_MATCHES + MATCH_COUNT))
    fi
done

if [[ $VIOLATIONS_FOUND -eq 1 ]]; then
    if [[ $BASELINE_MODE -eq 1 ]]; then
        echo -e "${YELLOW}⚠️  BASELINE MODE: Found ${TOTAL_MATCHES} unwrap/expect/panic violations in production code${NC}"
        echo -e "${YELLOW}   Allowing violations for initial setup, but these should be addressed${NC}"
        echo
        echo "Production code should not contain:"
        echo "  - .unwrap() calls (use proper error handling)"
        echo "  - .expect() calls (use proper error handling)"
        echo "  - panic!() calls (use Result<T, E> or graceful degradation)"
        echo
        echo "These are allowed only in:"
        echo "  - Test files (tests/, *test*.rs, *bench*.rs)"
        echo "  - Benchmark files (benches/)"
        echo "  - Example files (examples/)"
        echo "  - Build scripts (build.rs)"
        echo
        exit 0
    else
        echo -e "${RED}🚫 GUARD FAILED: Found ${TOTAL_MATCHES} unwrap/expect/panic violations in production code${NC}"
        echo
        echo "Production code must not contain:"
        echo "  - .unwrap() calls (use proper error handling)"
        echo "  - .expect() calls (use proper error handling)"
        echo "  - panic!() calls (use Result<T, E> or graceful degradation)"
        echo
        echo "These are allowed only in:"
        echo "  - Test files (tests/, *test*.rs, *bench*.rs)"
        echo "  - Benchmark files (benches/)"
        echo "  - Example files (examples/)"
        echo "  - Build scripts (build.rs)"
        echo
        echo "To set up the guard infrastructure despite existing violations, run:"
        echo "  scripts/guard_no_unwrap.sh --baseline"
        echo
        exit 1
    fi
else
    echo -e "${GREEN}✅ GUARD PASSED: No unwrap/expect/panic found in production code${NC}"
    exit 0
fi