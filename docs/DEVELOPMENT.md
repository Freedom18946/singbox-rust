# Development & Quality Gates

## MSRV
- Minimum Supported Rust Version (MSRV): 1.79

## One-liners
- Workspace warnings as errors: `cargo clippy --workspace --all-targets -- -D warnings`
- Strict clippy (lib-only, pedantic+nursery) example:
  ```bash
  cargo clippy -p sb-core --lib --features metrics -- \
    -D warnings -W clippy::pedantic -W clippy::nursery \
    -D clippy::unwrap_used -D clippy::expect_used -D clippy::panic \
    -D clippy::todo -D clippy::unimplemented -D clippy::undocumented_unsafe_blocks -D dead_code
  ```

## Docs & Coverage
- Doc tests: `cargo test --doc -q`
- Coverage (HTML + lcov): `scripts/cov.sh` → `target/coverage/index.html`
- Mutation smoke: `scripts/mutants-smoke.sh` (non-blocking)

## Preflight (RC Gate)
- Local preflight checklist and report: `scripts/preflight.sh`
- CI job: `preflight` (manual dispatch or PR label `preflight`)

## E2E
- Non-blocking e2e run: `scripts/e2e-run.sh` → `.e2e/summary.json`

