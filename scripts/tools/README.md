# Tools

Development and operational tools for singbox-rust.

## Overview

This directory contains:
- **release/** - Release preparation and packaging
- **validation/** - Code quality validation
- **explain/** - Router explain utilities
- Various development utilities

## Release Tools (`release/`)

### `phase8-rc.sh`
Complete RC preparation script with all steps.

```bash
# Run all steps
./scripts/tools/release/phase8-rc.sh all

# Run specific step
./scripts/tools/release/phase8-rc.sh build
./scripts/tools/release/phase8-rc.sh test
./scripts/tools/release/phase8-rc.sh security
```

Steps:
- A) Release artifacts (manpage, completions, version)
- B) Binary matrix build
- C) Security checks (cargo-deny, cargo-audit)
- D) Alignment tests
- E) Documentation verification
- F) Package creation

### `phase8-quick-start.sh`
Quick-start release preparation (minimal steps).

```bash
./scripts/tools/release/phase8-quick-start.sh
```

### `make-rc.sh`
Create release candidate package.

```bash
./scripts/tools/release/make-rc.sh
```

Outputs: `singbox-rust-rc.tar.gz`

## Validation Tools (`validation/`)

### `validate-metrics.sh`
Validate Prometheus metrics correctness.

```bash
./scripts/tools/validation/validate-metrics.sh
```

Checks:
- Metric naming conventions
- Label consistency
- Type correctness
- Help text presence

### `verify-quick-fixes.sh`
Verify quick fixes and patches.

```bash
./scripts/tools/validation/verify-quick-fixes.sh
```

### `guard-no-unwrap.sh`
Guard against unwrap() usage in core code.

```bash
./scripts/tools/validation/guard-no-unwrap.sh
```

Fails if unwrap() found in:
- `crates/sb-core/`
- `crates/sb-transport/`
- `crates/sb-adapters/`

### `audit-features.sh`
Audit feature flag usage.

```bash
./scripts/tools/validation/audit-features.sh
```

## Explain Tools (`explain/`)

Router explain utilities for debugging routing decisions.

### `run.sh`
Run router explain on configuration.

```bash
./scripts/tools/explain/run.sh examples/configs/routing/basic.json
```

### `example.sh`
Run explain on example configurations.

```bash
./scripts/tools/explain/example.sh
```

## Development Utilities

### `config-patch.sh`
Patch configuration files.

```bash
./scripts/tools/config-patch.sh config.json patch.json
```

### `cli-patch-and-test.sh`
Patch CLI and run tests.

```bash
./scripts/tools/cli-patch-and-test.sh
```

### `run-and-test.sh`
Build, run, and test in one command.

```bash
./scripts/tools/run-and-test.sh
```

### `run-examples.sh`
Run all example configurations.

```bash
./scripts/tools/run-examples.sh
```

### `prefetch-heat.sh`
Prefetch and heat caches for testing.

```bash
./scripts/tools/prefetch-heat.sh
```

### `scaffold-ws.sh`
Scaffold new workspace crate.

```bash
./scripts/tools/scaffold-ws.sh my-new-crate
```

### `sbom.sh`
Generate Software Bill of Materials.

```bash
./scripts/tools/sbom.sh
```

Outputs: `target/sbom.json`

### `triage.sh`
Triage test failures and issues.

```bash
./scripts/tools/triage.sh
```

### `preflight.sh`
Pre-flight checks before commits.

```bash
./scripts/tools/preflight.sh
```

Runs:
- Syntax checks
- Format checks
- Clippy lints
- Quick tests

## Python Utilities

### `probe_http.py`
HTTP proxy probe.

```bash
python3 scripts/tools/probe_http.py http://proxy:port
```

### `probe_http_multi.py`
Multi-target HTTP probe.

```bash
python3 scripts/tools/probe_http_multi.py targets.txt
```

### `probe_socks.py`
SOCKS5 proxy probe.

```bash
python3 scripts/tools/probe_socks.py socks5://proxy:port
```

## Usage Patterns

### Pre-commit Checks

```bash
./scripts/tools/preflight.sh
```

### Release Preparation

```bash
# Full RC preparation
./scripts/tools/release/phase8-rc.sh all

# Verify package
./scripts/test/acceptance/rc-package-verify.sh
```

### Code Validation

```bash
# Check for unwrap()
./scripts/tools/validation/guard-no-unwrap.sh

# Validate metrics
./scripts/tools/validation/validate-metrics.sh

# Audit features
./scripts/tools/validation/audit-features.sh
```

### Debugging Routing

```bash
# Explain routing decision
./scripts/tools/explain/run.sh config.json

# Run examples
./scripts/tools/explain/example.sh
```

## Environment Variables

- `RUST_VERSION` - Required Rust version (default: 1.90)
- `CARGO_PROFILE` - Build profile (release/dev)
- `RUSTFLAGS` - Additional Rust compiler flags

## Exit Codes

- `0` - Success
- `1` - Error or validation failed
- `2` - Invalid arguments

## Adding New Tools

1. Choose appropriate subdirectory
2. Follow naming conventions
3. Include usage documentation
4. Add to this README
5. Test thoroughly

## Dependencies

- `cargo` - Rust toolchain
- `jq` - JSON processing
- `tar` - Archive creation
- Optional: `cargo-deny`, `cargo-audit` for security
- Optional: `python3` for probe scripts
