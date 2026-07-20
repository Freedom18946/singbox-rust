# A2.3 Runtime Status JSON Rehearsal

Date: 2026-07-20

## Outcome

A2.3 is accepted locally. Fixed-profile L18 produced a terminal
`l18_capstone_status.json` with no failed local implementation gate. Status is `PARTIAL`
by design: Docker is `ADVISORY` with `--require-docker 0`, and GUI is `UNTESTED` under
the selected `--gui-mode core` profile. Every other selected gate is `PROVEN`.

## Implementation fixes

- TLS client configuration installs the ring rustls provider when no process default exists;
  the all-feature workspace panic is removed.
- L18 clippy uses repository policy (`make clippy`); memory benchmarking uses literal argv
  arrays and direct runtime PIDs; dual certification retains failed-case output and run dirs.
- `ConnectionManager` defers public-suffix parsing until TLS fragmentation is used, removing
  duplicate startup parsing from the supervisor/bridge construction path.
- Fixed-profile capstone gates use a per-run `CARGO_TARGET_DIR`; the REALITY fixture resolves
  Rust binaries from that target, so concurrent Cargo activity cannot corrupt the run.
- DHCP resolver tests now use an explicit temporary resolv.conf through `DhcpResolver::from_spec`.
  `SystemUpstream` returns literal IPs directly, and the RDRC Sled persistence test explicitly
  releases its writer before reopen.

## Terminal evidence

Fixed-profile run:
`/private/tmp/singbox-rust-a23-final-isolated/a23-runtime-status-final-isolated/r1/l18_capstone_status.json`

- `preflight`, `oracle`, `reality_local`, `boundaries`, `parity`, `workspace_test`, `fmt`,
  `clippy`, `hot_reload`, `signal`, `canary`, `dual_kernel_diff`, and `perf_gate`: `PROVEN`.
- REALITY local fixture: config validation PASS; Go->Go 20/20, Go->Rust 20/20,
  Rust->Go 20/20, phase probe 20/20; all negative controls PASS.
- Daily dual certificate: 34 selected both-kernel strict cases, 0 run failures, 0 diff failures.
- Strict perf report:
  `/private/tmp/singbox-rust-a23-final-isolated/a23-runtime-status-final-isolated/r1/perf/perf_gate.json`
  reports startup Rust/Go 17/17 ms, p95 1.219/1.377 ms, RSS 22208/29680 KiB; all thresholds PASS.
- Post-run ports: released, no busy ports. Docker state was not modified.

## Subscription audit

User-supplied source SHA-256
`0f40004fc36a6ab17cb664f30f7a205b5330b7396d66002d1866c7e07e94b6b9` exactly matches the R93
banked source. Intake classified all 19 entries as duplicates, R81 schema dry-run passed 19/19,
and production `probe-outbound --validate-config-only` passed 19/19 without network access.
No live probe was repeated; no raw credential or endpoint was committed.

## Validation

- `cargo test --workspace` via the terminal fixed-profile capstone (`RUST_TEST_THREADS=1`)
- `cargo test -p sb-core --lib`: 560 passed, 8 ignored; RDRC persistence stress 50/50
- `cargo test -p sb-core --test dhcp_resolver`: repeated 20/20 PASS
- `python3 -m unittest -v scripts/l18/test_l18_capstone_contract.py`: 7/7 PASS
- `make verify-reality-local`: 20/20 matrix PASS with negative controls
- `cargo fmt --all -- --check`, shell syntax checks, and `git diff --check`: PASS

## Boundary

No parity/BHV movement, REALITY camouflage sufficiency, ServerHello borrowing, Docker
acceptance, or GUI acceptance is claimed. Remaining frontier is external controlled Rust
deployment and multi-vantage camouflage measurement.
