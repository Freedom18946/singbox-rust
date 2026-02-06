# cargo-deny Offline Workflow

This directory provides a local, offline-friendly entry point for `cargo deny`
as part of the P2 local gate.

## Online Preparation (required once per cache refresh)

Run these commands when the network is available to populate local caches:

- `tools/deny/refresh.sh`

These populate:

- `~/.cargo/advisory-db` (RustSec advisory database)
- `~/.cargo/registry` (crate index + cache)

## Offline Check

Run:

- `tools/deny/check.sh`

If prerequisites are missing, the script exits with instructions.

Note: `cargo deny` runs `cargo metadata`; if crate sources are missing, offline
mode will fail. Use `tools/deny/refresh.sh` online to prefetch dependencies.
