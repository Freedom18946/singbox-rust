# Project Status

**Repository Mode**: Maintenance  
**Current Reading Rule**: closure, capability state, and behavior evidence are tracked separately

> Capability facts are maintained in [capabilities.md](capabilities.md) and generated from `reports/capabilities.json`.
>
> Historical reports under `reports/` remain useful context, but they are not the sole source of truth for current status.

## Current Authority Chain

Use these in order:

1. `labs/interop-lab/docs/dual_kernel_golden_spec.md`
2. `agents-only/active_context.md`
3. `agents-only/workpackage_latest.md`
4. `agents-only/reference/GO_PARITY_MATRIX.md`
5. `docs/capabilities.md`

## Current Status Summary

- The repository is in maintenance mode; L1-L25 are closed.
- `GO_PARITY_MATRIX.md` expresses closure status, not blanket proof that every closed item has full behavior-level parity evidence.
- `reports/capabilities.json` remains `docs-only` / `snapshot_unverified`; it is a capability ledger, not a substitute for runtime proof.
- Historical L18/L3 reports remain in the tree as historical snapshots and provenance, not as live certification.

## Capability Highlights

- `tls.ech.tcp`: `implemented_unverified`
- `tls.ech.quic`: `scaffold_stub`
- `tls.utls`: `implemented_unverified`
- `tun.macos.tun2socks`: `scaffold_stub`
- `inbound.redirect`: `scaffold_stub`
- `inbound.tproxy`: `scaffold_stub`

See [capabilities.md](capabilities.md) for the full index and semantics.

## Local Verification Baseline

Primary local gate chain:

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
