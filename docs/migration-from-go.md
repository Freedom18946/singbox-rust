# Migration From Go

Use the current Rust CLI and validator as the migration oracle.

## Verify A Migrated Config

```bash
cargo run -p app -- check -c ./config.json
```

## Explain A Route Decision

```bash
cargo run -p app -- route -c ./config.json --dest example.com:443 --explain --with-trace
```

## Important Differences Called Out In Live Docs

- The maintained command is `completion`, not `gen-completions`.
- The maintained route command is `route`, not `route-explain`.
- Admin exposure is configured with `--admin-listen` / `--admin-token` or `ADMIN_LISTEN` / `ADMIN_TOKEN`.
- A top-level `admin:` section is not accepted by the current validator.
