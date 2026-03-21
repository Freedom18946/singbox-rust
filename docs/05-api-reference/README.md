# API Reference

The current admin surface is enabled from the `run` command, not from a top-level `admin:` config section.

Enable it with:

```bash
ADMIN_LISTEN=127.0.0.1:19090 \
ADMIN_TOKEN=change-me \
cargo run -p app -- run -c examples/quick-start/01-minimal.yaml
```

Current endpoints confirmed from source and runtime:

- `GET /healthz`
- `GET /metricsz`
- `POST /reload`

Authentication:

- If `ADMIN_TOKEN` is set, send `X-Admin-Token: <token>`.

Related pages:

- `admin-api/README.md`
- `v2ray-stats/README.md`
