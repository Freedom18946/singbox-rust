# L18 Replacement Certification Report

## Scope

L18 objective is "replacement certification first, zero-regression performance in parallel" under macOS only.

- Topology: dual-kernel (Go + Rust) with GUI as the unified driver.
- Gate policy: `docker/gui/canary` are mandatory in L18.
- Go oracle source: `go_fork_source/sing-box-1.12.14` built locally for every run.

## Mandatory Gates

- `scripts/l18/preflight_macos.sh`
- `scripts/l18/build_go_oracle.sh`
- `scripts/l18/run_dual_kernel_cert.sh`
- `scripts/l18/gui_real_cert.sh`
- `scripts/l18/perf_gate.sh`
- `scripts/l18/l18_capstone.sh --profile daily|nightly|certify`

Capstone gate set:

- `boundaries`
- `parity`
- `workspace_test`
- `fmt`
- `clippy`
- `hot_reload`
- `signal`
- `docker`
- `gui_smoke`
- `canary`
- `dual_kernel_diff`
- `perf_gate`

## Performance KPI

Relative to Go baseline:

- p95 latency <= +5%
- RSS peak <= +10%
- startup time <= +10%

## Artifacts Contract

- `reports/l18/baseline.lock.json`
- `reports/l18/oracle/go/<run_id>/oracle_manifest.json`
- `reports/l18/dual_kernel/<run_id>/summary.json`
- `reports/l18/dual_kernel/<run_id>/diff_gate.json`
- `reports/l18/gui_real_cert.json`
- `reports/l18/gui_real_cert.md`
- `reports/l18/perf_gate.json`
- `reports/l18/l18_capstone_status.json`

## Execution Profiles

- `daily`: P0/P1 dual-kernel diff + 1h canary
- `nightly`: full both-kernel diff + 24h canary
- `certify`: full both-kernel diff + 7d canary (required to close L18)

## Failure Attribution Policy

- Any missing precondition is `FAIL` and blocks certification.
- No `SKIP`/`BLOCKED` for L18 certification gates.
- External unstable subscriptions are excluded from blocking set.

## Exemption Policy

Default: no exemptions.

If an exemption is required, add a dated waiver entry with:

- explicit owner
- risk impact
- expiration date
- compensating controls

Without all four fields, waiver is invalid.

## Current Status

- Status: `IN_PROGRESS`
- Stage: detailed design implemented into scripts/workflow/document contracts.
- Closure criteria pending:
  - at least one `certify` (7d canary) pass
  - all mandatory gate evidence uploaded from self-hosted macOS CI
