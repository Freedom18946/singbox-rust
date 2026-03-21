# Documentation

This documentation set is kept aligned with the current repository state, not historical phase reports.

## Start Here

- `00-getting-started/README.md`
  Build from source and validate a first config.
- `02-cli-reference/README.md`
  Current CLI surface for `app`.
- `03-operations/README.md`
  Deployment and runtime operations.
- `05-api-reference/README.md`
  Admin HTTP surface exposed by `app run --admin-listen`.
- `08-examples/README.md`
  User-facing example walkthroughs.

## Scope Notes

- Historical material remains under `docs/archive/`.
- `docs/examples/` is for transport-planning and developer inspection, not end-user deployment.
- Live docs should match the current help output from:

```bash
cargo run -p app -- --help
cargo run -p app -- run --help
cargo run -p app -- check --help
cargo run -p app -- route --help
cargo run -p app -- completion --help
```

## External Links

- Repository: <https://github.com/Freedom18946/singbox-rust>
- Issues: <https://github.com/Freedom18946/singbox-rust/issues>
- Discussions: <https://github.com/Freedom18946/singbox-rust/discussions>
