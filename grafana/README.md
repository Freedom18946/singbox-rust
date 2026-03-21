# Grafana Dashboards for SingBox-Rust

These dashboards track the metrics that are currently exported by the repository today. The files in `grafana/dashboards/` intentionally match the live metric names and labels used in code; historical or speculative panels have been removed.

## Included Dashboards

- `overview.json`: build info, uptime, request rates, cache/NAT size, retry and error overview
- `dns.json`: DNS query rate, RTT, success/failure, cache hit rate and cache size
- `proxy.json`: proxy selection, proxy health, RTT, circuit state changes, outbound connection/error metrics
- `udp.json`: UDP upstream traffic, NAT size, TTL, evictions, upstream failures and errors
- `route.json`: HTTP response rate, HTTP connect latency, error classes, route explain, adapter retries

## Recommended Metrics Source

Prometheus can scrape either of the following:

1. Admin debug endpoint

```yaml
scrape_configs:
  - job_name: "singbox-rust"
    metrics_path: /__metrics
    static_configs:
      - targets: ["localhost:18088"]
```

Start singbox-rust with:

```bash
export SB_ADMIN_ENABLE=1
export SB_ADMIN_LISTEN=0.0.0.0:18088
singbox-rust run -c config.yaml
```

2. Dedicated Prometheus exporter

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

## Manual Import

1. Open Grafana.
2. Go to `+` -> `Import`.
3. Upload JSON files from `grafana/dashboards/`.
4. Select your Prometheus datasource.

## Provisioning

Copy datasource and dashboard provider files into the correct Grafana provisioning directories:

```bash
sudo cp grafana/provisioning/datasources.yml /etc/grafana/provisioning/datasources/datasources.yml
sudo cp grafana/provisioning/dashboards.yml /etc/grafana/provisioning/dashboards/singbox-rust.yml
sudo mkdir -p /var/lib/grafana/dashboards/singbox-rust
sudo cp grafana/dashboards/*.json /var/lib/grafana/dashboards/singbox-rust/
sudo systemctl restart grafana-server
```

## Docker Compose Example

```yaml
services:
  grafana:
    image: grafana/grafana:latest
    volumes:
      - grafana-data:/var/lib/grafana
      - ./grafana/provisioning/datasources.yml:/etc/grafana/provisioning/datasources/datasources.yml:ro
      - ./grafana/provisioning/dashboards.yml:/etc/grafana/provisioning/dashboards/singbox-rust.yml:ro
      - ./grafana/dashboards:/var/lib/grafana/dashboards/singbox-rust:ro
    ports:
      - "3000:3000"
```

## Alert Rules

`grafana/alerts/rules.yml` contains Prometheus alert rules that only reference metrics present in the current implementation. Import them from `prometheus.yml`:

```yaml
rule_files:
  - /path/to/grafana/alerts/rules.yml
```

## Troubleshooting

Verify admin metrics:

```bash
curl -s http://127.0.0.1:18088/__metrics | grep -E "^(dns_|http_|proxy_|outbound_|udp_|route_explain_total|adapter_retries_total)"
```

Verify dedicated exporter metrics:

```bash
curl -s http://127.0.0.1:19090/metrics | grep -E "^(dns_|http_|proxy_|outbound_|udp_|route_explain_total|adapter_retries_total)"
```

If a panel shows `No data`, confirm that:

- Prometheus is scraping the endpoint you actually enabled.
- The feature path producing that metric has traffic. Some metrics such as proxy RTT, circuit state, TCP connect latency, and retries are event-driven.
- The Grafana datasource points at the same Prometheus instance used for the scrape.

## Related Docs

- `docs/03-operations/monitoring/grafana-dashboards.md`
- `docs/METRICS_CATALOG.md`
