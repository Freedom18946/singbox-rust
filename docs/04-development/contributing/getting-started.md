# Contributing: Getting Started

Quick steps for setting up a local dev environment.

## Prerequisites

- Rust toolchain: see `rust-toolchain.toml`
- Recommended: `cargo` + `rustup`

## Basic Workflow

```bash
cargo build --workspace
cargo test --workspace
cargo clippy --workspace -- -D warnings
```

## Local CI

```bash
./scripts/ci/local.sh
```

## References

- CI scripts: `scripts/ci/README.md`
- Project structure: `../../../PROJECT_STRUCTURE_NAVIGATION.md`
