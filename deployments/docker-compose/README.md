# Docker Compose Deployment

This directory contains a maintained multi-service sample based on the current `app` CLI.

## Services

- `singbox-rust`
  Uses `deployments/config-template.json`
- `prometheus`
  Scrapes `/metricsz` from the service on admin port `19090`

## Start

```bash
docker compose -f deployments/docker-compose/docker-compose.yml up -d
```

## Validate Config Before Start

```bash
cargo run -p app -- check -c deployments/config-template.json
```

## Runtime Contract

- container command: `app run -c /etc/singbox/config.json`
- admin env: `ADMIN_LISTEN=0.0.0.0:19090`
- health endpoint: `GET /healthz`
- metrics endpoint: `GET /metricsz`

## Notes

- `SINGBOX_IMAGE` can override the default image reference.
- `deployments/config-examples/client-multi-hop.json` remains available as a separate validated client-side sample.
- Grafana is no longer promised by this sample because the compose file does not provision a complete dashboard stack.
