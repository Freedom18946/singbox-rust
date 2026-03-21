# Grafana Dashboards

The repository ships five Grafana dashboards under `grafana/dashboards/`. They have been aligned to the current implementation and only reference live metric names and label sets.

## Dashboards

- `singbox-overview`: build info, uptime, request rates, cache/NAT size, retries, component error rates
- `singbox-dns`: DNS query rate, RTT distribution, success/failure, cache hit rate, cache size
- `singbox-proxy`: proxy selection, selection score, endpoint health, RTT, circuit transitions, outbound errors
- `singbox-udp`: upstream packet/byte traffic, NAT size, heap length, TTL, evictions, failures, errors
- `singbox-routing`: HTTP response rate, HTTP connect duration, HTTP errors, route explain, adapter retries

## Scrape Setup

Prometheus can scrape the existing admin metrics endpoint:

```bash
export SB_ADMIN_ENABLE=1
export SB_ADMIN_LISTEN=0.0.0.0:18088
singbox-rust run -c config.yaml
```

```yaml
scrape_configs:
  - job_name: "singbox-rust"
    metrics_path: /__metrics
    static_configs:
      - targets: ["localhost:18088"]
```

Or it can scrape the dedicated Prometheus exporter:

```bash
export SB_METRICS_ADDR=127.0.0.1:19090
singbox-rust run -c config.yaml
```

```yaml
scrape_configs:
  - job_name: "singbox-rust"
    metrics_path: /metrics
    static_configs:
      - targets: ["localhost:19090"]
```

## Provisioning

```bash
sudo cp grafana/provisioning/datasources.yml /etc/grafana/provisioning/datasources/datasources.yml
sudo cp grafana/provisioning/dashboards.yml /etc/grafana/provisioning/dashboards/singbox-rust.yml
sudo mkdir -p /var/lib/grafana/dashboards/singbox-rust
sudo cp grafana/dashboards/*.json /var/lib/grafana/dashboards/singbox-rust/
sudo systemctl restart grafana-server
```

For Docker Compose, mount the files into Grafana's actual provisioning subdirectories instead of mounting the repo directory wholesale.

## Current Dashboard Conventions

- `overview.json` keeps the existing UID-based cross-links to the four specialized dashboards.
- Ratio panels use zero-traffic guards so idle periods do not produce divide-by-zero artifacts.
- Variables only exist where they are actually used in PromQL:
  - `dns.json`: `qtype`
  - `route.json`: `code`
- Proxy dashboards no longer assume a historical `pool/endpoint` model for selection metrics; they follow the labels the code exports today.
- HTTP latency panels track the currently exported HTTP connect histogram, not the removed request-duration histogram.

## Alert Rules

Prometheus alert rules live in `grafana/alerts/rules.yml`. They now only target metrics that exist in the current implementation and use the currently exported labels in annotations.

```yaml
rule_files:
  - /path/to/grafana/alerts/rules.yml
```

## Validation

Useful spot checks:

```bash
curl -s http://127.0.0.1:18088/__metrics | grep dns_query_total
curl -s http://127.0.0.1:18088/__metrics | grep http_connect_duration_ms_bucket
curl -s http://127.0.0.1:18088/__metrics | grep proxy_up
curl -s http://127.0.0.1:18088/__metrics | grep udp_nat_size
```

If you use `SB_METRICS_ADDR`, swap the base URL to that exporter and use `/metrics`.

## Related Files

- `grafana/README.md`
- `grafana/alerts/rules.yml`
- `docs/METRICS_CATALOG.md`
