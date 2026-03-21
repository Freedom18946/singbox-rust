# Docker

Two maintained Docker entry points exist:

- `deployments/docker/`
  Local image build from this repository.
- `deployments/docker-compose/`
  Multi-service deployment samples using published images.

Both use the same runtime contract:

- command: `app run -c /etc/singbox/config.json`
- admin env: `ADMIN_LISTEN`, `ADMIN_TOKEN`
- health path: `GET /healthz`
- metrics path: `GET /metricsz`
