# Prometheus Metrics

## Overview

singbox-rust exposes Prometheus metrics via the admin HTTP server.

## Endpoint

- Default: `http://127.0.0.1:18088/__metrics`

## Enable metrics

```bash
SB_ADMIN_ENABLE=1 SB_ADMIN_LISTEN=127.0.0.1:18088 singbox-rust run -c config.yaml
```

## Example scrape config

```yaml
scrape_configs:
  - job_name: "singbox-rust"
    static_configs:
      - targets: ["127.0.0.1:18088"]
```

## Related

- [Grafana Dashboards](grafana-dashboards.md)
- [Metrics Catalog](../../METRICS_CATALOG.md)
