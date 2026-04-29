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

### `check-doc-links.sh`
Validate markdown links under `docs/`.

```bash
./scripts/tools/check-doc-links.sh
./scripts/tools/check-doc-links.sh docs
```

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

### `probe-http.py`
HTTP proxy probe.

```bash
python3 scripts/tools/probe-http.py 127.0.0.1:18081 1710000000
```

### `probe-http-multi.py`
Multi-target HTTP probe.

```bash
python3 scripts/tools/probe-http-multi.py 127.0.0.1:18081 10
```

### `probe-socks.py`
SOCKS5 proxy probe.

```bash
python3 scripts/tools/probe-socks.py 127.0.0.1:11080 1710000000
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

### REALITY Probe Matrix

Build comparable app/minimal VLESS REALITY probe samples.

```bash
./scripts/tools/reality_vless_probe_matrix.sh \
  --config agents-only/mt_real_01_evidence/phase3_ip_direct.json \
  --outbound 'HK-A-BGP-0.3倍率' \
  --target example.com:80 \
  --timeout 10
```

Supporting tools:

```bash
python3 scripts/tools/reality_vless_env_from_config.py \
  --config config.json --outbound node --target example.com:80 --format env

python3 scripts/tools/reality_probe_compare.py \
  --app-json app.json --phase-json phase.json
```

The matrix wrapper writes `run.json`, `app.json`, `phase.json`, and `compare.json` so
REALITY live failures can be compared by class before treating a node failure
as a sampler or dataplane regression.

For multi-node collection:

```bash
python3 scripts/tools/reality_vless_probe_batch.py \
  --config agents-only/mt_real_01_evidence/phase3_ip_direct.json \
  --target example.com:80 \
  --limit 3 \
  --dry-run

python3 scripts/tools/reality_vless_probe_batch.py \
  --config agents-only/mt_real_01_evidence/phase3_ip_direct.json \
  --target example.com:80 \
  --include 'HK-A-BGP' \
  --limit 2 \
  --runs 2 \
  --timeout 10
```

Batch output includes `plan.json`, optional `results.jsonl`, and `summary.json`
with per-label, per-class, and per-outbound counts. With `--runs N`, each
selected ready outbound gets repeated sample directories under
`NNN-outbound/run-NNN`. The batch runner also applies a matrix-level hard
timeout so a wedged app/minimal probe pair cannot stall the whole batch; override
it with `--matrix-timeout SECONDS` when collecting intentionally slow samples.

Planner JSON can be passed directly into the batch runner; `selected[].name`
entries are merged with any explicit `--outbound` values while preserving order.

```bash
python3 scripts/tools/reality_vless_probe_batch.py \
  --config agents-only/mt_real_01_evidence/phase3_ip_direct.json \
  --plan-json /tmp/reality-vless-next-plan.json \
  --target example.com:80 \
  --runs 2
```

To turn a batch `summary.json` into a sanitized evidence file suitable for
`agents-only/mt_real_02_evidence`:

```bash
python3 scripts/tools/reality_vless_probe_evidence.py \
  --summary-json /tmp/reality-vless-probe-batch-live/summary.json \
  --output-json agents-only/mt_real_02_evidence/roundNN_summary.json \
  --round NN \
  --date 2026-04-26 \
  --description 'bounded live REALITY batch'
```

To roll multiple committed evidence files into a compact dashboard:

```bash
python3 scripts/tools/reality_vless_evidence_rollup.py \
  --evidence agents-only/mt_real_02_evidence/round*_summary.json \
  --output-json agents-only/mt_real_02_evidence/live_rollup.json \
  --output-md agents-only/mt_real_02_evidence/live_rollup.md
```

The rollup keeps both historical aggregate counts and each outbound's latest
round state. The planner uses latest labels when deciding `prior_non_all_ok`, so
nodes that recovered in a later targeted repeat are not queued forever. Rollup
JSON also classifies each outbound's latest state as `latest_all_ok`,
`latest_same_failure`, `latest_divergence`, or `latest_unknown`.

To plan the next bounded live batch from the current config and rollup:

```bash
python3 scripts/tools/reality_vless_probe_plan.py \
  --config agents-only/mt_real_01_evidence/phase3_ip_direct.json \
  --rollup-json agents-only/mt_real_02_evidence/live_rollup.json \
  --limit 5 \
  --output-json /tmp/reality-vless-next-plan.json
```

To target the latest health buckets directly:

```bash
python3 scripts/tools/reality_vless_probe_plan.py \
  --config agents-only/mt_real_01_evidence/phase3_ip_direct.json \
  --rollup-json agents-only/mt_real_02_evidence/live_rollup.json \
  --latest-health latest_divergence \
  --latest-run-health run_divergence \
  --latest-health latest_same_failure \
  --output-json /tmp/reality-vless-latest-health-plan.json
```

Rollup JSON keeps both outbound-level latest health and per-run latest health,
so mixed cases such as one divergent run plus one same-failure run can be
isolated before changing sampler/dataplane code.

Planner output excludes internal `__*` sentinel outbounds by default; pass
`--include-internal` only when intentionally planning smoke/negative samples.

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
