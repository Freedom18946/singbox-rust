# Build System Overview

Workspace build structure and common entry points.

## Workspace

- Root `Cargo.toml` defines the workspace
- `app/` builds the CLI binaries
- `crates/` contains core libraries

## Key Files

- `rust-toolchain.toml` (MSRV/toolchain)
- `Cargo.toml` / `Cargo.lock`
- `scripts/ci/` for CI automation

## References

- Feature flags: `feature-flags.md`
- CI matrix: `ci-matrix.md`
