# Admin API

## Enable The Listener

```bash
ADMIN_LISTEN=127.0.0.1:19090 \
ADMIN_TOKEN=change-me \
cargo run -p app -- run -c examples/quick-start/01-minimal.yaml
```

The current `run` command also accepts `--admin-listen` and `--admin-token`.

## Health

```bash
curl -H 'X-Admin-Token: change-me' http://127.0.0.1:19090/healthz
```

## Metrics

```bash
curl -H 'X-Admin-Token: change-me' http://127.0.0.1:19090/metricsz
```

## Reload

```bash
curl \
  -X POST \
  -H 'Content-Type: application/json' \
  -H 'X-Admin-Token: change-me' \
  -d '{"path":"examples/quick-start/01-minimal.yaml"}' \
  http://127.0.0.1:19090/reload
```

Notes:

- Use CLI flags or `ADMIN_*` env vars to expose the listener.
- Do not add `admin:` blocks to config files; the current validator rejects them.
