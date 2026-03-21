# Grafana Dashboards

The repository still ships Grafana assets under `grafana/`, but the deployment examples now assume metrics come from the admin endpoint on port `19090`.

Runtime example:

```bash
ADMIN_LISTEN=0.0.0.0:19090 \
cargo run -p app -- run -c /etc/singbox/config.json
```

Prometheus scrape target:

- `http://singbox-rust:19090/metricsz`

Health endpoint:

- `http://singbox-rust:19090/healthz`
