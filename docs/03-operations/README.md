# Operations

Use this section for deployment, health checks, metrics, and runtime safety checks.

## Current Admin Surface

Enable the admin HTTP server with CLI flags or the documented fallback env vars:

```bash
ADMIN_LISTEN=0.0.0.0:19090 \
ADMIN_TOKEN=change-me \
cargo run -p app -- run -c /etc/singbox/config.json
```

Do not use an `admin:` top-level config block. The current schema rejects it.

## Current Admin Endpoints

- `GET /healthz`
- `GET /metricsz`
- `POST /reload`

If `ADMIN_TOKEN` is set, send it as `X-Admin-Token`.

## Deployment Assets

- `deployments/systemd/singbox-rust.service`
- `deployments/docker/Dockerfile`
- `deployments/docker/docker-compose.yml`
- `deployments/docker-compose/docker-compose.yml`
- `deployments/kubernetes/deployment.yaml`
- `deployments/helm/singbox-rust/`

## Related Pages

- `deployment/README.md`
- `monitoring/README.md`
- `env-toggles.md`
