# CLI Reference

The repository currently exposes the CLI through the `app` binary.

Top-level commands confirmed from live help:

- `check`
- `auth`
- `prom`
- `completion`
- `generate`
- `merge`
- `format`
- `geoip`
- `geosite`
- `ruleset`
- `run`
- `route`
- `dns`
- `version`

## Canonical Invocation

```bash
cargo run -p app -- <command> [args...]
```

## High-Traffic Commands

- `check`
  Validate config without starting I/O.
- `run`
  Start the service.
- `route`
  Explain routing for a destination.
- `completion`
  Generate shell completions.

## Current Admin Flags

The `run` command accepts:

- `--admin-listen <ADDR>`
- `--admin-token <TOKEN>`

The fallback environment variables are:

- `ADMIN_LISTEN`
- `ADMIN_TOKEN`

`--admin-impl` is not part of the current CLI.

## Linked Pages

- `check.md`
- `run.md`
- `route-explain.md`
- `completions.md`
- `environment-variables.md`
