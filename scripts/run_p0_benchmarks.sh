#!/usr/bin/env bash
#
# Run P0 protocol performance benchmarks
#
# Usage:
#   ./scripts/run_p0_benchmarks.sh [options]
#
# Options:
#   --baseline    Run baseline benchmarks only
#   --all         Run all protocol benchmarks (requires features)
#   --test        Run in test mode (faster, for CI)
#   --save NAME   Save results as baseline NAME
#   --compare NAME Compare with baseline NAME
#   --help        Show this help message

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default options
MODE="baseline"
TEST_MODE=""
SAVE_BASELINE=""
COMPARE_BASELINE=""

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --baseline)
            MODE="baseline"
            shift
            ;;
        --all)
            MODE="all"
            shift
            ;;
        --test)
            TEST_MODE="--test"
            shift
            ;;
        --save)
            SAVE_BASELINE="$2"
            shift 2
            ;;
        --compare)
            COMPARE_BASELINE="$2"
            shift 2
            ;;
        --help)
            grep '^#' "$0" | sed 's/^# \?//'
            exit 0
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

echo -e "${BLUE}=== P0 Protocol Performance Benchmarks ===${NC}"
echo ""

cd "$PROJECT_ROOT/app"

# Build benchmark arguments
BENCH_ARGS=()
if [[ -n "$TEST_MODE" ]]; then
    BENCH_ARGS+=("--" "$TEST_MODE")
fi

if [[ -n "$SAVE_BASELINE" ]]; then
    BENCH_ARGS+=("--" "--save-baseline" "$SAVE_BASELINE")
fi

if [[ -n "$COMPARE_BASELINE" ]]; then
    BENCH_ARGS+=("--" "--baseline" "$COMPARE_BASELINE")
fi

case $MODE in
    baseline)
        echo -e "${GREEN}Running baseline benchmarks...${NC}"
        echo "This measures TCP performance without protocol overhead"
        echo ""
        cargo bench --bench bench_p0_protocols "${BENCH_ARGS[@]}"
        ;;
    
    all)
        echo -e "${GREEN}Running all P0 protocol benchmarks...${NC}"
        echo "This requires all protocol features to be enabled"
        echo ""
        
        # Check if features are available
        echo -e "${YELLOW}Note: Some benchmarks may be skipped if features are not enabled${NC}"
        echo ""
        
        # Run with all features (those that exist)
        cargo bench --bench bench_p0_protocols \
            --features "adapter-hysteria" \
            "${BENCH_ARGS[@]}" || true
        
        echo ""
        echo -e "${YELLOW}Note: REALITY, ECH, Hysteria v2, SSH, and TUIC benchmarks${NC}"
        echo -e "${YELLOW}require additional features that may not be enabled.${NC}"
        ;;
    
    *)
        echo -e "${RED}Unknown mode: $MODE${NC}"
        exit 1
        ;;
esac

echo ""
echo -e "${GREEN}=== Benchmark Complete ===${NC}"
echo ""
echo "Results are saved in: target/criterion/"
echo ""
echo "To view HTML reports:"
echo "  open target/criterion/report/index.html"
echo ""
echo "To compare with a baseline:"
echo "  ./scripts/run_p0_benchmarks.sh --compare <baseline-name>"
echo ""
