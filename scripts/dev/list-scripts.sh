#!/usr/bin/env bash
# List all scripts with their descriptions and categories
# Usage: ./scripts/dev/list-scripts.sh [--format=tree|table|simple]

set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCRIPTS_DIR="${PROJECT_ROOT}/scripts"

FORMAT="${1:-simple}"
FORMAT="${FORMAT#--format=}"

extract_description() {
    local file="$1"
    # Extract first comment line that looks like a description
    head -10 "$file" | grep -E "^#" | grep -v "^#!/" | head -1 | sed 's/^# *//' || echo "(no description)"
}

list_tree() {
    echo "Scripts Directory Structure:"
    echo ""
    tree -L 3 -I '__pycache__|*.pyc' "${SCRIPTS_DIR}" 2>/dev/null || {
        echo "tree command not found, using find:"
        find "${SCRIPTS_DIR}" -type f \( -name "*.sh" -o -name "*.py" \) -print | sort
    }
}

list_table() {
    echo "Category|Script|Description"
    echo "--------|------|------------"

    for category in ci e2e test tools lib lint scenarios.d soak; do
        if [ -d "${SCRIPTS_DIR}/${category}" ]; then
            find "${SCRIPTS_DIR}/${category}" -type f \( -name "*.sh" -o -name "*.py" \) | sort | while read -r script; do
                name=$(basename "$script")
                desc=$(extract_description "$script")
                echo "${category}|${name}|${desc}"
            done
        fi
    done
}

list_simple() {
    echo "=== CI Scripts (scripts/ci/) ==="
    find "${SCRIPTS_DIR}/ci" -type f -name "*.sh" | sort | while read -r script; do
        name=$(basename "$script" .sh)
        desc=$(extract_description "$script")
        printf "  %-30s  %s\n" "$name" "$desc"
    done
    echo ""

    echo "=== E2E Tests (scripts/e2e/) ==="
    find "${SCRIPTS_DIR}/e2e" -type f -name "*.sh" | sort | while read -r script; do
        name=$(echo "$script" | sed "s|${SCRIPTS_DIR}/e2e/||" | sed 's|\.sh$||')
        desc=$(extract_description "$script")
        printf "  %-30s  %s\n" "$name" "$desc"
    done
    echo ""

    echo "=== Test Scripts (scripts/test/) ==="
    find "${SCRIPTS_DIR}/test" -type f -name "*.sh" | sort | while read -r script; do
        name=$(echo "$script" | sed "s|${SCRIPTS_DIR}/test/||" | sed 's|\.sh$||')
        desc=$(extract_description "$script")
        printf "  %-30s  %s\n" "$name" "$desc"
    done
    echo ""

    echo "=== Tools (scripts/tools/) ==="
    find "${SCRIPTS_DIR}/tools" -type f \( -name "*.sh" -o -name "*.py" \) | sort | while read -r script; do
        name=$(echo "$script" | sed "s|${SCRIPTS_DIR}/tools/||")
        desc=$(extract_description "$script")
        printf "  %-30s  %s\n" "$name" "$desc"
    done
    echo ""

    echo "=== Libraries (scripts/lib/) ==="
    find "${SCRIPTS_DIR}/lib" -type f -name "*.sh" | sort | while read -r script; do
        name=$(basename "$script" .sh)
        desc=$(extract_description "$script")
        printf "  %-30s  %s\n" "$name" "$desc"
    done
}

case "$FORMAT" in
    tree)
        list_tree
        ;;
    table)
        list_table
        ;;
    simple|*)
        list_simple
        ;;
esac
