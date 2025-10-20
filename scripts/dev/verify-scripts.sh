#!/usr/bin/env bash
# Verify all important scripts exist and are executable

set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$PROJECT_ROOT"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "=== Script Existence and Executability Check ==="
echo ""

# Critical scripts that must exist and be executable
CRITICAL_SCRIPTS=(
    # Main entry point
    "scripts/run"

    # CI scripts
    "scripts/ci/local.sh"
    "scripts/ci/accept.sh"
    "scripts/ci/strict.sh"
    "scripts/ci/warn-sweep.sh"
    "scripts/ci/tasks/adapter-bridge.sh"
    "scripts/ci/tasks/admin-http.sh"
    "scripts/ci/tasks/release-gate.sh"

    # E2E scripts
    "scripts/e2e/run.sh"
    "scripts/e2e/clean.sh"
    "scripts/e2e/diff.sh"
    "scripts/e2e/smoke.sh"

    # Test scripts
    "scripts/test/acceptance/explain-replay.sh"
    "scripts/test/acceptance/schema-v2.sh"
    "scripts/test/bench/run.sh"
    "scripts/test/bench/guard.sh"
    "scripts/test/stress/run.sh"
    "scripts/test/fuzz/analysis.sh"
    "scripts/test/cov.sh"
    "scripts/test/mutants-smoke.sh"

    # Tool scripts
    "scripts/tools/release/phase8-rc.sh"
    "scripts/tools/release/phase8-quick-start.sh"
    "scripts/tools/validation/guard-no-unwrap.sh"
    "scripts/tools/validation/validate-metrics.sh"
    "scripts/tools/preflight.sh"
    "scripts/tools/sbom.sh"

    # Dev scripts
    "scripts/dev/list-scripts.sh"
    "scripts/dev/validate-restructure.sh"

    # Lib scripts
    "scripts/lib/metrics.sh"
    "scripts/lib/prom.sh"
)

pass=0
fail=0
warn=0

for script in "${CRITICAL_SCRIPTS[@]}"; do
    if [ ! -f "$script" ]; then
        echo -e "${RED}✗${NC} MISSING: $script"
        ((fail++))
    elif [ ! -x "$script" ]; then
        echo -e "${YELLOW}⚠${NC} NOT EXECUTABLE: $script"
        ((warn++))
    else
        echo -e "${GREEN}✓${NC} $script"
        ((pass++))
    fi
done

echo ""
echo "=== Summary ==="
echo -e "${GREEN}Pass:${NC} $pass"
echo -e "${YELLOW}Warn:${NC} $warn"
echo -e "${RED}Fail:${NC} $fail"
echo ""

if [ "$fail" -eq 0 ] && [ "$warn" -eq 0 ]; then
    echo -e "${GREEN}✓ All critical scripts are present and executable!${NC}"
    exit 0
elif [ "$fail" -eq 0 ]; then
    echo -e "${YELLOW}⚠ Some scripts are not executable. Run: chmod +x scripts/**/*.sh${NC}"
    exit 0
else
    echo -e "${RED}✗ Some critical scripts are missing!${NC}"
    exit 1
fi
