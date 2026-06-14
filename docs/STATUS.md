# Project Status

**Repository Mode**: Active post-FABLE calibration

**Current Reading Rule**: live project state, package closure, capability
snapshots, and behavior evidence are tracked separately.

> Live status, gates, and the recommended next step are maintained in
> [`agents-only/active_context.md`](../agents-only/active_context.md).
>
> Capability snapshots are documented in [capabilities.md](capabilities.md) and
> generated from `reports/capabilities.json`; that ledger is docs-only and is not
> a GUI readiness or runtime parity certificate.
>
> Historical reports under `reports/` remain useful context, but they are not the sole source of truth for current status.

## Current Authority Chain

Use these in order:

1. `agents-only/active_context.md` for volatile status, gates, and next step.
2. `agents-only/fable5审计报告/post_fable_packages/README.md` for post-FABLE package state.
3. `labs/interop-lab/docs/dual_kernel_golden_spec.md` for the behavior parity ledger.
4. `agents-only/reference/GO_PARITY_MATRIX.md` for historical acceptance closure accounting.
5. `docs/capabilities.md` and `reports/capabilities.json` for docs-only capability snapshots.

## Current Status Summary

- L1-L25 are closed, but the repository remains on the GUI.for SingBox 1.19.0
  drop-in replacement path rather than pure maintenance.
- `GO_PARITY_MATRIX.md` expresses closure status, not blanket proof that every closed item has full behavior-level parity evidence.
- `reports/capabilities.json` remains `docs-only` / `snapshot_unverified`; it is a capability ledger, not a substitute for runtime proof.
- Historical L18/L3 reports remain in the tree as historical snapshots and provenance, not as live certification.
- MT-GUI-04, BHV, REALITY/T3, and ledger counts are scoped evidence. They must
  not be read as current GUI ready, drop-in ready, or full behavior parity claims.

## Capability Highlights

- `tls.ech.tcp`: `implemented_unverified`
- `tls.ech.quic`: `scaffold_stub`
- `tls.utls`: `implemented_unverified`
- `tun.macos.tun2socks`: `scaffold_stub`
- `inbound.redirect`: `scaffold_stub`
- `inbound.tproxy`: `scaffold_stub`

See [capabilities.md](capabilities.md) for the full index and semantics.

## Local Verification Baseline

Historical local gate examples. For the current gate posture, read
`agents-only/active_context.md` first:

```bash
./agents-only/06-scripts/check-boundaries.sh
cargo fmt --check
cargo clippy --workspace --all-features -- -D warnings
cargo test --workspace
cargo build -p app --features parity --release
./target/release/app version
./target/release/app check -c test_config.json
```

Feature / test entry points:

```bash
cargo xtask feature-matrix
cargo test -p sb-adapters --features adapter-shadowsocks --test shadowsocks_integration
cargo test -p sb-adapters --features adapter-trojan --test trojan_integration
cargo test -p sb-adapters --features adapter-vless --test vless_integration
cargo test -p app --features net_e2e --test dns_outbound_e2e
```

## Notes

- Workflow automation is disabled in this repository; status language should not depend on GitHub Actions or workflow contracts.
- Historical benchmark and verification reports should be read through `reports/README.md`.
