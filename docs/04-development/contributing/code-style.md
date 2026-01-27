# Code Style

House style for Rust in this workspace.

## Baseline Rules

- Avoid `unwrap()`/`expect()` in library code
- Prefer explicit error types (`thiserror`) and `?`
- Use `tracing` for logging

## Tooling

- `cargo fmt`
- `cargo clippy --workspace -- -D warnings`

## References

- Lint config: `clippy.toml`
- Lint baselines: `docs/STATUS.md`
