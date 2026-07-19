# A2.3 Runtime Status JSON Rehearsal

Date: 2026-07-19

## Outcome

A2.3 rehearsal is complete: fixed-profile L18 produced a terminal
`l18_capstone_status.json` after running every local gate. Status remained `FAILED`, not promoted,
because the strict performance gate reproduced a real Rust startup regression. All other local
implementation gates proved or were explicitly advisory/untested by the selected local profile.

## Fixes validated

- TLS client configuration installs the ring rustls provider when no process default exists. This
  removes the all-feature workspace panic caused by simultaneous ring/aws-lc availability.
- L18 clippy uses repository policy (`make clippy`) instead of an incompatible blanket
  `-D warnings` invocation.
- Memory benchmarking launches binaries as argument arrays and tracks the runtime PID directly;
  paths and shell metacharacters remain literal.
- Dual-kernel certification retains each case command output and extracts `run_dir` even when the
  case exits non-zero, making startup failures diagnosable from the certificate artifact.

## Rehearsal evidence

Fixed-profile run:
`/private/tmp/singbox-rust-a23-latest/a23-runtime-status/r1/l18_capstone_status.json`

- `preflight`, `oracle`, `reality_local`, `boundaries`, `parity`, `workspace_test`, `fmt`,
  `clippy`, `hot_reload`, `signal`, and `canary`: `PROVEN`.
- Docker: `ADVISORY` under `--require-docker 0`; GUI: `UNTESTED` under `--gui-mode core`.
- Initial dual certificate had two run failures with zero diff failures. Direct replay showed one
  transient pass and one fallback-build timeout; both cases passed with the frozen release app.
- Full frozen-release daily rerun:
  `/private/tmp/singbox-rust-a23-dual-rerun-1784446310/report/20260719T073150Z-daily-d2095e28/diff_gate.json`
  passed all selected cases with zero run or diff failures.
- Strict perf rerun:
  `/private/tmp/singbox-rust-a23-perf-rerun-1784446524/perf.json` kept latency and RSS within
  limits, but startup failed at Rust 36 ms versus Go 20 ms (`+80%`, limit `+10%`). No threshold was
  widened. This is the remaining local L18 blocker, separate from A2.3 status generation.
- Post-run dynamic ports were released; no Docker state was modified.

## Latest subscription audit

User-supplied source SHA-256
`0f40004fc36a6ab17cb664f30f7a205b5330b7396d66002d1866c7e07e94b6b9` exactly matches the R93
banked source. Intake classified all 19 entries as duplicates, R81 schema dry-run passed 19/19, and
production `probe-outbound --validate-config-only` passed 19/19 without network access. No live
probe was repeated because this source cannot add fresh evidence or advance the external
camouflage blocker. No raw credential or endpoint was committed.

## Validation

- `cargo test --workspace`
- `cargo test -p sb-transport --features transport_tls tls_secure --lib`
- `python3 -m unittest -v scripts/l18/test_l18_capstone_contract.py`
- `cargo fmt --all -- --check`
- `bash -n scripts/bench_memory.sh scripts/l18/l18_capstone.sh scripts/l18/run_dual_kernel_cert.sh`
- `git diff --check`

## Boundary

No parity/BHV movement, REALITY camouflage sufficiency, ServerHello borrowing, Docker acceptance,
or GUI acceptance is claimed. Current frontier remains external controlled deployment and
multi-vantage measurement; local L18 performance work remains the startup gap above.
