# Deployment Summary

The maintained deployment assets live under `deployments/`.

Use:

- `docs/03-operations/README.md`
- `docs/03-operations/deployment/README.md`
- `deployments/docker/`
- `deployments/docker-compose/`
- `deployments/kubernetes/deployment.yaml`
- `deployments/helm/singbox-rust/`

Current runtime contract:

- process: `app run -c /etc/singbox/config.json`
- admin env: `ADMIN_LISTEN`, `ADMIN_TOKEN`
- health endpoint: `GET /healthz`
- metrics endpoint: `GET /metricsz`
