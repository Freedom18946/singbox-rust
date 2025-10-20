# CI/CD Scripts

Continuous Integration and Deployment scripts for singbox-rust.

## Overview

This directory contains all CI-related automation, including:
- CI task scripts that run in GitHub Actions
- Local CI execution scripts
- Acceptance testing
- Build verification

## Main Scripts

### `local.sh`
Run complete CI suite locally before pushing.

```bash
./scripts/ci/local.sh
```

Exit codes:
- 0: All checks passed
- 1: Some checks failed

### `accept.sh`
Acceptance testing with feature gates.

```bash
FEATS="explain,selector_p3,metrics" ./scripts/ci/accept.sh
```

### `strict.sh`
Strict mode validation (clippy strict, no warnings).

```bash
./scripts/ci/strict.sh
```

### `warn-sweep.sh`
Collect and report all compiler warnings.

```bash
./scripts/ci/warn-sweep.sh
```

## Task Scripts (`tasks/`)

Individual CI tasks that can be run independently or as part of the pipeline.

### Contract Testing
- `adapter-bridge.sh` - Adapter bridge contract validation
- `config-ir-contract.sh` - Config IR contract testing
- `json-contract.sh` - JSON schema contract validation
- `security-contracts.sh` - Security contract verification

### Build Tasks
- `build-unblock-admin.sh` - Unblock admin builds
- `break-cycle.sh` - Break dependency cycles

### Feature Testing
- `admin-http.sh` - Admin HTTP API testing
- `selector-bridge.sh` - Selector bridge testing
- `selector-explain-real.sh` - Selector explain real scenarios
- `inbounds-upstreams.sh` - Inbound/upstream integration
- `proxy-minimal.sh` - Minimal proxy testing

### Metrics & Diagnostics
- `explain-nat-metrics.sh` - NAT metrics explanation
- `diag-and-subs.sh` - Diagnostics and subscriptions

### Quality Gates
- `release-gate.sh` - Release quality gate checks
- `min-guard-schema.sh` - Minimum guard schema validation
- `reload.sh` - Hot reload testing
- `runtime-and-health.sh` - Runtime and health checks

## Usage Patterns

### Running Single Task

```bash
./scripts/ci/tasks/admin-http.sh
```

### Running Multiple Tasks

```bash
for task in scripts/ci/tasks/*.sh; do
    echo "Running $(basename $task)..."
    "$task" || echo "FAILED: $task"
done
```

### In GitHub Actions

```yaml
- name: Run CI Task
  run: ./scripts/ci/tasks/adapter-bridge.sh
```

## Environment Variables

Common environment variables used:
- `FEATS` - Feature flags to enable
- `RUST_BACKTRACE` - Enable backtraces (default: 1)
- `CI` - Set to "true" in CI environments
- `CARGO_TERM_COLOR` - Cargo output coloring

## Exit Codes

- `0` - Success
- `1` - Tests failed or errors occurred
- `2` - Invalid arguments
- `77` - Skipped (dependencies not available)

## Adding New Tasks

1. Create script in `tasks/` directory
2. Follow naming convention: `feature-name.sh`
3. Include usage documentation
4. Use standard error handling
5. Return appropriate exit codes
6. Test locally before committing

## Dependencies

- `cargo` - Rust build system
- `jq` - JSON processing
- `curl` - HTTP testing
- Optional: `cargo-deny`, `cargo-audit` for security checks
