# Scripts Directory

This directory contains all development, testing, CI/CD, and operational scripts for singbox-rust.

## Quick Start

```bash
# Run all tests
./scripts/run test

# Run E2E tests
./scripts/run e2e

# Run CI checks locally
./scripts/run ci

# List all available scripts
./scripts/run list

# Show help
./scripts/run help
```

## Directory Structure

```
scripts/
├── ci/              CI/CD pipeline scripts
├── e2e/             End-to-end integration tests
├── test/            Testing scripts (acceptance, bench, stress, fuzz)
├── tools/           Development and release tools
├── dev/             Development utilities
├── lib/             Shared shell libraries
├── lint/            Code quality checks
├── scenarios.d/     Test scenario definitions
├── soak/            Long-running soak tests
└── target/          Test target configurations
```

## Categories

### CI/CD (`ci/`)
Continuous integration and deployment scripts.
- `ci/local.sh` - Run CI checks locally
- `ci/tasks/` - Individual CI task scripts
- `ci/accept.sh` - Acceptance testing
- `ci/strict.sh` - Strict mode checks
- `ci/warn-sweep.sh` - Warning collection

### E2E Tests (`e2e/`)
End-to-end integration tests organized by subsystem.
- `e2e/run.sh` - Main E2E test runner
- `e2e/dns/` - DNS-related E2E tests
- `e2e/router/` - Router integration tests
- `e2e/udp/` - UDP protocol tests
- `e2e/socks5/` - SOCKS5 protocol tests
- `e2e/proxy/` - Proxy health and pool tests

### Testing (`test/`)
Various testing categories.
- `test/acceptance/` - Acceptance test suite (A1-A5 series)
- `test/bench/` - Performance benchmarks
- `test/stress/` - Stress and load tests
- `test/fuzz/` - Fuzzing tests

### Tools (`tools/`)
Development and operational tools.
- `tools/release/` - Release preparation scripts
- `tools/validation/` - Code validation tools
- `tools/explain/` - Router explain utilities
- Various utility scripts

### Libraries (`lib/`)
Shared shell functions and utilities.
- `lib/metrics.sh` - Prometheus metrics helpers
- `lib/prom*.sh` - Prometheus query utilities
- `lib/junit.sh` - JUnit XML generation
- `lib/labels.sh` - Label management
- `lib/os_probe.sh` - OS detection
- `lib/bash4_detect.sh` - Bash version detection

### Linting (`lint/`)
Code quality and linting scripts.
- `lint/no-unwrap-core.sh` - Check for unwrap usage

### Scenarios (`scenarios.d/`)
Individual test scenario scripts.
- SOCKS5 scenarios
- DNS protocol scenarios
- Schema validation scenarios
- Selector health scenarios

## Naming Conventions

All scripts follow these conventions:
- Use `.sh` extension for bash scripts
- Use kebab-case for filenames: `my-script.sh`
- Scripts should have execute permissions (`chmod +x`)
- All scripts should include usage documentation

## Script Template

Every script should follow this template:

```bash
#!/usr/bin/env bash
# Brief description of what this script does
# Usage: ./script-name.sh [options] <args>
#   -h, --help    Show this help message
#   -v, --verbose Enable verbose output
#
# Examples:
#   ./script-name.sh --verbose input.txt
#
# Exit codes:
#   0 - Success
#   1 - General error
#   2 - Invalid arguments

set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$PROJECT_ROOT"

# Source common utilities if needed
# source scripts/lib/metrics.sh

show_help() {
    sed -n '/^# Usage:/,/^$/p' "$0" | sed 's/^# \?//'
    exit 0
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        -h|--help) show_help ;;
        *) echo "Unknown option: $1"; exit 2 ;;
    esac
    shift
done

# Main logic here
main() {
    echo "Script executing..."
}

main "$@"
```

## Common Patterns

### Sourcing Libraries

```bash
# Always use absolute path from PROJECT_ROOT
source "${PROJECT_ROOT}/scripts/lib/metrics.sh"
```

### Error Handling

```bash
set -euo pipefail  # Exit on error, undefined vars, pipe failures

err() {
    echo "[ERROR] $*" >&2
    exit 1
}

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"
}
```

### Cleanup on Exit

```bash
cleanup() {
    set +e
    # Cleanup logic here
    kill_background_processes
    rm -f /tmp/temp-files
}

trap cleanup EXIT INT TERM
```

## Exit Codes

Scripts should use consistent exit codes:
- `0` - Success
- `1` - General error or test failure
- `2` - Invalid arguments or usage
- `77` - Skipped (optional dependencies missing)

## Dependencies

Common dependencies used across scripts:
- `bash` >= 4.0 (some scripts require bash 4+)
- `jq` - JSON processing
- `curl` - HTTP requests
- `cargo` - Rust build tool
- Optional: `ripgrep` (`rg`), `fd`, `shellcheck`

## Contributing

When adding new scripts:
1. Choose the correct category directory
2. Follow naming conventions
3. Include usage documentation
4. Add error handling and cleanup
5. Test locally before committing
6. Update this README if adding new categories

## Maintenance

### Finding Scripts

```bash
# List all scripts with descriptions
./scripts/run list

# Search for specific functionality
grep -r "DNS" scripts/ --include="*.sh"
```

### Validating Scripts

```bash
# Check syntax of all scripts
find scripts -name "*.sh" -exec bash -n {} \;

# Run shellcheck (if installed)
find scripts -name "*.sh" -exec shellcheck {} \;
```

## Legacy Notes

This directory was reorganized on 2025-10-19 to improve organization and maintainability.
Previous structure had 78 scripts in the root directory. New structure organizes them
into logical categories with better documentation.

For migration details, see `.scripts-analysis.txt` in the project root.
