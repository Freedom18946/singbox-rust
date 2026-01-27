# Grafana Dashboards

Pre-configured Grafana dashboards for monitoring singbox-rust in production.

---

## Overview

SingBox-Rust provides 5 production-ready Grafana dashboards covering all aspects of system performance and health:

1. **Overview** - System-wide health and KPIs
2. **DNS** - DNS query performance and cache metrics
3. **Proxy & Outbound** - Proxy selection and connection monitoring
4. **UDP & NAT** - UDP relay and NAT table tracking
5. **Routing & HTTP** - HTTP responses and routing metrics

All dashboards are located in the `/grafana` directory of this repository.

---

## Quick Start

### 1. Prerequisites

Ensure you have:
- **Grafana** (v9.0+) running
- **Prometheus** configured and scraping singbox-rust metrics
- **SingBox-Rust** with admin API enabled

```bash
# Enable metrics in singbox-rust
export SB_ADMIN_ENABLE=1
export SB_ADMIN_LISTEN=0.0.0.0:18088
singbox-rust run -c config.yaml
```

### 2. Import Dashboards

**Option A: Manual Import**

1. Open Grafana → **+** → **Import**
2. Upload dashboard JSON from `grafana/dashboards/`
3. Select Prometheus datasource
4. Click **Import**

**Option B: Auto-provisioning** (Recommended)

```bash
# Copy provisioning configs
sudo cp grafana/provisioning/*.yml /etc/grafana/provisioning/datasources/
sudo cp grafana/provisioning/dashboards.yml /etc/grafana/provisioning/dashboards/

# Copy dashboards
sudo mkdir -p /var/lib/grafana/dashboards/singbox-rust
sudo cp grafana/dashboards/*.json /var/lib/grafana/dashboards/singbox-rust/

# Restart Grafana
sudo systemctl restart grafana-server
```

### 3. Configure Prometheus

Add singbox-rust to `prometheus.yml`:

```yaml
scrape_configs:
  - job_name: 'singbox-rust'
    static_configs:
      - targets: ['localhost:18088']
    scrape_interval: 15s
```

---

## Dashboard Details

### Overview Dashboard

**UID**: `singbox-overview`
**Use Cases**: First-stop monitoring, incident response, daily health checks

**Key Metrics**:
- System health (uptime, memory, CPU)
- Overall QPS (DNS, HTTP, outbound, proxy)
- Success rates across all components
- Resource utilization (NAT sessions, cache sizes)
- Error trends by component

**Links**: Provides quick navigation to specialized dashboards

### DNS Dashboard

**UID**: `singbox-dns`
**Use Cases**: DNS performance tuning, cache optimization, resolution troubleshooting

**Panels**:
- Query rate by type (A, AAAA, OTHER)
- RTT distribution (P50, P95, P99)
- Error rate by class (timeout, name_error, network_error)
- Success rate tracking
- Cache hit rate and size
- Cache operations (hits/misses per second)

**Variables**:
- `qtype`: Filter by DNS query type

### Proxy & Outbound Dashboard

**UID**: `singbox-proxy`
**Use Cases**: Load balancing, endpoint health, connection monitoring

**Panels**:
- Proxy selections by pool/endpoint
- Endpoint RTT (EMA)
- Selection scores
- Connection rate by protocol
- TCP connect duration (P50, P95, P99)
- Outbound success rate
- Error classification
- Proxy health status
- Circuit breaker state changes

**Variables**:
- `pool`: Filter by proxy pool
- `endpoint`: Filter by endpoint
- `outbound_kind`: Filter by protocol type

### UDP & NAT Dashboard

**UID**: `singbox-udp`
**Use Cases**: UDP performance, NAT capacity planning, session tracking

**Panels**:
- Upstream packet rate
- Upstream byte rate (in/out)
- NAT map size (current and over time)
- NAT heap length
- Active sessions
- Eviction rate by reason (ttl, capacity)
- Session TTL distribution (P50, P90, P99)
- Failure and error rates by class
- Generation mismatches

**Variables**: None (global view)

### Routing & HTTP Dashboard

**UID**: `singbox-routing`
**Use Cases**: HTTP API monitoring, routing analysis, circuit breaker tracking

**Panels**:
- HTTP response rate by status code
- Request duration percentiles
- Success rate (2xx/3xx)
- 4xx vs 5xx error trends
- Error rate by class
- Active HTTP connections
- Circuit breaker state changes
- Proxy health status
- Route explain invocations
- Adapter retries

**Variables**:
- `code`: Filter by HTTP status code

---

## Panel Types

### Time Series
Line graphs showing metrics over time with configurable refresh intervals.

### Stat
Single-value panels with threshold-based color coding:
- **Green**: Healthy/normal operation
- **Yellow**: Warning threshold
- **Red**: Critical threshold

### Gauge
Visual representation of current value against capacity limits.

### Table
Detailed breakdowns of metrics with multiple dimensions.

---

## Customization

### Adjusting Thresholds

Thresholds are defined in `fieldConfig.defaults.thresholds`:

```json
"thresholds": {
  "mode": "absolute",
  "steps": [
    { "value": 0, "color": "red" },
    { "value": 90, "color": "yellow" },
    { "value": 99, "color": "green" }
  ]
}
```

**Example**: Change DNS success rate warning from 90% to 95%:

1. Open `grafana/dashboards/dns.json`
2. Find panel ID 12 ("Success Rate %")
3. Modify threshold values:
   ```json
   { "value": 95, "color": "yellow" }  // Changed from 90
   ```
4. Re-import dashboard

### Adding Panels

To add custom panels:

1. Edit dashboard in Grafana UI
2. Add panel → Configure query and visualization
3. Save dashboard
4. Export JSON: **Share** → **Export** → **Save to file**
5. Update `grafana/dashboards/*.json`

### Modifying Queries

All PromQL queries are in the `targets` array of each panel. Example:

```json
"targets": [
  {
    "expr": "sum by (qtype) (rate(dns_query_total[1m]))",
    "legendFormat": "{{qtype}}",
    "refId": "A"
  }
]
```

**Common Modifications**:
- Change time range: `[1m]` → `[5m]`
- Add filters: `{qtype="A"}`
- Aggregate differently: `sum` → `avg`, `max`, `count`

---

## Alerting Integration

Grafana supports alerting directly from dashboard panels. However, we recommend using Prometheus alerts (see `grafana/alerts/rules.yml`) for:

- Centralized alert management
- Alert grouping and routing
- Integration with Alertmanager

**To view Prometheus alerts in Grafana**:

1. Navigate to **Alerting** → **Alert rules**
2. Select Prometheus datasource
3. Alerts will appear with firing status

**Recommended Alerts**:
- High DNS/HTTP/Outbound error rates
- NAT table capacity warnings
- Proxy endpoint health degradation
- System resource exhaustion

See [Alerting Rules](../../../grafana/alerts/rules.yml) for complete configuration.

---

## Troubleshooting

### Dashboard Shows "No Data"

**Causes**:
1. Prometheus not scraping singbox-rust
2. Metrics not enabled in singbox-rust
3. Wrong datasource selected

**Solutions**:
```bash
# Check metrics endpoint
curl http://localhost:18088/__metrics | grep dns_query_total

# Check Prometheus targets
curl http://localhost:9090/api/v1/targets

# Verify datasource in Grafana
Grafana UI → Configuration → Data Sources → Prometheus → Test
```

### Metrics Missing or Incorrect

**Verify metric names** match dashboard queries:

```bash
# List all singbox-rust metrics
curl http://localhost:18088/__metrics | grep -E "^(dns|http|udp|proxy|outbound)_"
```

**Common Issues**:
- Metric renamed in newer version → Update dashboard query
- Labels changed → Adjust `by (label)` clauses
- Metric type mismatch → Use appropriate query function

### Panel Query Errors

**Test queries in Prometheus** before adding to Grafana:

1. Open Prometheus UI: `http://localhost:9090`
2. Navigate to **Graph**
3. Paste query, click **Execute**
4. Verify results before using in Grafana

### High Cardinality Warnings

If you see warnings about high cardinality:

1. **Review labels**: Too many unique label combinations
2. **Limit label values**: Use relabeling in Prometheus
3. **Reduce retention**: Lower `scrape_interval`
4. **Use recording rules**: Pre-aggregate expensive queries

Example recording rule:

```yaml
groups:
  - name: singbox_aggregates
    interval: 30s
    rules:
      - record: dns:query_rate:1m
        expr: sum(rate(dns_query_total[1m]))
```

---

## Performance Optimization

### Query Performance

**Slow dashboard loading**:

1. **Increase step size**: Use longer time ranges in queries (`[5m]` instead of `[1m]`)
2. **Reduce panel count**: Collapse non-essential rows
3. **Use recording rules**: Pre-compute expensive aggregations
4. **Limit time range**: Default to 6h instead of 24h

**Example Recording Rule**:

```yaml
- record: http:success_rate:5m
  expr: |
    100 * sum(rate(http_respond_total{code=~"2..|3.."}[5m]))
    / sum(rate(http_respond_total[5m]))
```

Then use in dashboard:
```promql
http:success_rate:5m  # Much faster than original query
```

### Resource Usage

**Grafana server optimization**:

```ini
# /etc/grafana/grafana.ini
[database]
max_open_conn = 100
max_idle_conn = 100

[dataproxy]
timeout = 30
```

**Prometheus optimization**:

```yaml
# prometheus.yml
global:
  scrape_interval: 15s      # Balance between freshness and load
  evaluation_interval: 15s
```

---

## Best Practices

### Dashboard Organization

1. **Start with Overview**: Get system-wide view first
2. **Drill down to specific dashboards**: Navigate using links
3. **Use time range synchronization**: Keep consistent time windows
4. **Leverage variables**: Filter data instead of creating duplicate dashboards

### Monitoring Strategy

1. **Daily**: Check Overview dashboard for anomalies
2. **Weekly**: Review error trends and resource utilization
3. **Monthly**: Analyze capacity planning metrics (NAT table, cache sizes)
4. **During incidents**: Use specialized dashboards for deep troubleshooting

### Alert Configuration

1. **Set reasonable thresholds**: Avoid alert fatigue
2. **Use multi-level severity**: info → warning → critical
3. **Group related alerts**: Use Alertmanager routing
4. **Document runbooks**: Link alerts to remediation steps

---

## Related Documentation

- **[Grafana README](../../../grafana/README.md)** - Dashboard usage guide
- **[Prometheus Metrics](metrics.md)** - Available metrics catalog
- **[Alerting Rules](../../../grafana/alerts/rules.yml)** - Prometheus alert definitions
- **[Operations Guide](../)** - Production deployment and monitoring

---

## Support

**Issues with dashboards**:
- Check dashboard JSON syntax: `jq . dashboard.json`
- Validate PromQL queries in Prometheus UI
- Review Grafana logs: `journalctl -u grafana-server -f`

**Feature requests**:
- File an issue on GitHub with proposed panel/query
- Include use case and expected benefit
- Provide sample PromQL query if applicable

---

**Questions?** See the [Troubleshooting Guide](../../01-user-guide/troubleshooting.md) or open a GitHub issue.
