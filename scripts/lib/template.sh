#!/usr/bin/env bash
# [Brief description of what this script does]
# Usage: ./script-name.sh [options] <args>
#   -h, --help      Show this help message
#   -v, --verbose   Enable verbose output
#
# Examples:
#   ./script-name.sh --verbose input.txt
#   ./script-name.sh -h
#
# Exit codes:
#   0 - Success
#   1 - General error
#   2 - Invalid arguments
#   77 - Skipped (optional dependencies missing)

set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$PROJECT_ROOT"

# Source common utilities if needed
# source "${PROJECT_ROOT}/scripts/lib/metrics.sh"

# Logging functions
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"
}

err() {
    echo "[ERROR] $*" >&2
}

# Show help message
show_help() {
    sed -n '/^# Usage:/,/^$/p' "$0" | sed 's/^# \?//'
    exit 0
}

# Cleanup on exit
cleanup() {
    set +e
    # Add cleanup logic here
    # Example: kill background processes, remove temp files
}

trap cleanup EXIT INT TERM

# Parse arguments
VERBOSE=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        -h|--help)
            show_help
            ;;
        -v|--verbose)
            VERBOSE=1
            shift
            ;;
        -*)
            err "Unknown option: $1"
            show_help
            exit 2
            ;;
        *)
            break
            ;;
    esac
done

# Main logic
main() {
    log "Script starting..."

    # Your code here

    log "Script completed successfully"
}

main "$@"
