#!/usr/bin/env bash
# Batch update script paths in codebase
# This script updates all references to old script paths to new restructured paths

set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$PROJECT_ROOT"

echo "Working directory: $PROJECT_ROOT"

echo "=== Updating Script Path References ==="
echo ""

# Define path mappings (old_path -> new_path)
declare -A PATH_MAPPINGS=(
    ["scripts/ci-local.sh"]="scripts/ci/local.sh"
    ["scripts/e2e-run.sh"]="scripts/e2e/run.sh"
    ["scripts/e2e-clean.sh"]="scripts/e2e/clean.sh"
    ["scripts/e2e-diff.sh"]="scripts/e2e/diff.sh"
    ["scripts/guard_no_unwrap.sh"]="scripts/tools/validation/guard-no-unwrap.sh"
    ["scripts/sbom.sh"]="scripts/tools/sbom.sh"
    ["scripts/fuzz-smoke.sh"]="scripts/test/fuzz/smoke.sh"
    ["scripts/cov.sh"]="scripts/test/cov.sh"
    ["scripts/mutants-smoke.sh"]="scripts/test/mutants-smoke.sh"
    ["scripts/generate_corpus.sh"]="scripts/test/fuzz/generate-corpus.sh"
    ["scripts/preflight.sh"]="scripts/tools/preflight.sh"
    ["scripts/audit_features.sh"]="scripts/tools/validation/audit-features.sh"
    ["scripts/bench-guard.sh"]="scripts/test/bench/guard.sh"
    ["scripts/run-examples.sh"]="scripts/tools/run-examples.sh"
    ["scripts/prefetch-heat.sh"]="scripts/tools/prefetch-heat.sh"
    ["scripts/run_stress_tests.sh"]="scripts/test/stress/run.sh"
    ["scripts/monitor_stress_test.sh"]="scripts/test/stress/monitor.sh"
    ["scripts/run_p0_benchmarks.sh"]="scripts/test/bench/run-p0.sh"
    ["scripts/explain_run.zsh"]="scripts/tools/explain/run.sh"
    ["scripts/e2e_router_rules.zsh"]="scripts/e2e/router/rules.sh"
    ["scripts/phase8-quick-start.sh"]="scripts/tools/release/phase8-quick-start.sh"
    ["scripts/phase8-rc.sh"]="scripts/tools/release/phase8-rc.sh"
)

# Files to update
FILES_TO_UPDATE=(
    ".github/workflows/ci.yml"
    ".github/workflows/e2e.yml"
    ".github/workflows/repro.yml"
    ".github/workflows/fuzz-smoke.yml"
    ".github/workflows/cov.yml"
    ".github/workflows/fuzz-extended.yml"
    ".github/workflows/preflight.yml"
    ".github/workflows/feature-audit.yml"
    ".github/workflows/release.yml"
    "README.md"
    "docs/04-development/README.md"
    "reports/README.md"
    "reports/stress-tests/README.md"
    ".e2e/README.md"
    "fuzz/README.md"
    "examples/VALIDATION_REPORT.md"
)

updated_count=0

# Function to update paths in a file
update_file() {
    local file="$1"

    if [ ! -f "$file" ]; then
        echo "⚠ Skipping $file (not found)"
        return
    fi

    local changes=0

    for old_path in "${!PATH_MAPPINGS[@]}"; do
        new_path="${PATH_MAPPINGS[$old_path]}"

        if grep -q "$old_path" "$file" 2>/dev/null; then
            sed -i.bak "s|$old_path|$new_path|g" "$file"
            changes=$((changes + 1))
        fi
    done

    if [ "$changes" -gt 0 ]; then
        rm -f "${file}.bak"
        echo "✓ Updated $file ($changes replacements)"
        updated_count=$((updated_count + 1))
    fi
}

# Update each file
for file in "${FILES_TO_UPDATE[@]}"; do
    update_file "$file"
done

echo ""
echo "=== Summary ==="
echo "Files updated: $updated_count"
echo ""
echo "Please review the changes with: git diff"
