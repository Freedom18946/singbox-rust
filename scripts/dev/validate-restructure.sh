#!/usr/bin/env bash
# Quick validation script to verify restructuring didn't break anything
# Usage: ./scripts/dev/validate-restructure.sh

set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$PROJECT_ROOT"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

PASS=0
FAIL=0
WARN=0

log_pass() {
    echo -e "${GREEN}✓${NC} $*"
    ((PASS++))
}

log_fail() {
    echo -e "${RED}✗${NC} $*"
    ((FAIL++))
}

log_warn() {
    echo -e "${YELLOW}⚠${NC} $*"
    ((WARN++))
}

log_info() {
    echo -e "${BLUE}ℹ${NC} $*"
}

echo "=== Scripts Restructure Validation ==="
echo ""

# Check directory structure
log_info "Checking directory structure..."
for dir in ci e2e test tools dev lib lint scenarios.d soak target; do
    if [ -d "scripts/$dir" ]; then
        log_pass "Directory exists: scripts/$dir"
    else
        log_fail "Directory missing: scripts/$dir"
    fi
done
echo ""

# Check README files
log_info "Checking README files..."
for readme in scripts/README.md scripts/ci/README.md scripts/e2e/README.md scripts/test/README.md scripts/tools/README.md; do
    if [ -f "$readme" ]; then
        lines=$(wc -l < "$readme")
        log_pass "README exists: $readme ($lines lines)"
    else
        log_fail "README missing: $readme"
    fi
done
echo ""

# Check main entry point
log_info "Checking main entry point..."
if [ -f "scripts/run" ] && [ -x "scripts/run" ]; then
    log_pass "scripts/run exists and is executable"

    # Test commands
    if ./scripts/run help &>/dev/null; then
        log_pass "scripts/run help works"
    else
        log_fail "scripts/run help failed"
    fi

    if ./scripts/run list &>/dev/null; then
        log_pass "scripts/run list works"
    else
        log_fail "scripts/run list failed"
    fi
else
    log_fail "scripts/run missing or not executable"
fi
echo ""

# Check script counts
log_info "Checking script counts..."
ci_count=$(find scripts/ci -name "*.sh" -type f | wc -l)
e2e_count=$(find scripts/e2e -name "*.sh" -type f | wc -l)
test_count=$(find scripts/test -name "*.sh" -type f | wc -l)
tools_count=$(find scripts/tools -name "*.sh" -o -name "*.py" -type f | wc -l)

log_pass "CI scripts: $ci_count"
log_pass "E2E scripts: $e2e_count"
log_pass "Test scripts: $test_count"
log_pass "Tool scripts: $tools_count"
echo ""

# Check all scripts are executable
log_info "Checking script permissions..."
non_exec=$(find scripts -name "*.sh" -type f ! -perm -u+x 2>/dev/null || true)
if [ -z "$non_exec" ]; then
    log_pass "All .sh files are executable"
else
    log_fail "Some scripts are not executable:"
    echo "$non_exec" | while read -r f; do
        echo "  - $f"
    done
fi
echo ""

# Check for shebangs
log_info "Checking shebangs..."
bad_shebang=0
find scripts -name "*.sh" -type f | while read -r script; do
    first_line=$(head -1 "$script")
    if [[ ! "$first_line" =~ ^#!/ ]]; then
        if [ "$bad_shebang" -eq 0 ]; then
            log_warn "Scripts without proper shebang:"
        fi
        echo "  - $script"
        ((bad_shebang++))
    fi
done

if [ "$bad_shebang" -eq 0 ]; then
    log_pass "All scripts have proper shebangs"
fi
echo ""

# Check critical scripts exist
log_info "Checking critical scripts..."
critical_scripts=(
    "scripts/ci/local.sh"
    "scripts/ci/accept.sh"
    "scripts/e2e/run.sh"
    "scripts/e2e/clean.sh"
    "scripts/test/acceptance/explain-replay.sh"
    "scripts/test/bench/run.sh"
    "scripts/tools/release/phase8-rc.sh"
    "scripts/tools/preflight.sh"
    "scripts/lib/metrics.sh"
)

for script in "${critical_scripts[@]}"; do
    if [ -f "$script" ]; then
        log_pass "Critical script exists: $(basename "$(dirname "$script")")/$(basename "$script")"
    else
        log_fail "Critical script missing: $script"
    fi
done
echo ""

# Check for old script locations
log_info "Checking for old script locations (should be empty)..."
old_scripts=$(find scripts -maxdepth 1 -name "ci_task_*.sh" -o -name "e2e_*.sh" -o -name "e2e_*.zsh" -o -name "A[0-9]_*.sh" 2>/dev/null || true)
if [ -z "$old_scripts" ]; then
    log_pass "No old script locations found"
else
    log_warn "Found scripts in old locations:"
    echo "$old_scripts" | while read -r f; do
        echo "  - $f"
    done
fi
echo ""

# Summary
echo "=== Summary ==="
echo -e "${GREEN}PASS:${NC} $PASS"
echo -e "${YELLOW}WARN:${NC} $WARN"
echo -e "${RED}FAIL:${NC} $FAIL"
echo ""

if [ "$FAIL" -eq 0 ]; then
    echo -e "${GREEN}✓ All validation checks passed!${NC}"
    exit 0
else
    echo -e "${RED}✗ Some validation checks failed${NC}"
    exit 1
fi
