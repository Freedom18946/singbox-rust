# Grafana Dashboards for SingBox-Rust

Complete set of Grafana dashboards for monitoring and observing singbox-rust in production.

## 📊 Available Dashboards

### 1. **Overview Dashboard** (`overview.json`)

Comprehensive system overview showing:
- **System Health**: Build info, uptime, memory, CPU usage
- **Traffic Overview**: Combined QPS across all components
- **Success Rates**: DNS, HTTP, outbound connection health
- **Resource Utilization**: NAT sessions, cache sizes, active connections
- **Error Trends**: Error rates by component

**Use cases**: First stop for troubleshooting, SRE daily monitoring, incident response

### 2. **DNS Dashboard** (`dns.json`)

DNS query performance and cache metrics:
- Query rate by type (A, AAAA, OTHER)
- RTT percentiles (P50, P95, P99)
- Error tracking by class (timeout, name_error, network_error, other)
- Cache hit rate and size monitoring
- Success vs failure rates

**Use cases**: DNS performance optimization, cache tuning, troubleshooting resolution issues

### 3. **Proxy & Outbound Dashboard** (`proxy.json`)

Proxy selection and outbound connection metrics:
- Proxy selections by pool/endpoint
- Endpoint RTT and selection scores
- Connection rate by protocol type
- TCP connect duration percentiles
- Health status and circuit breaker states
- Error classification

**Use cases**: Load balancing optimization, endpoint health monitoring, connection troubleshooting

### 4. **UDP & NAT Dashboard** (`udp.json`)

UDP relay and NAT table monitoring:
- Packet and byte rates (in/out)
- NAT map size and heap length
- Session TTL distribution
- Eviction rates by reason (ttl, capacity)
- Failure and error tracking by class
- Generation mismatch detection

**Use cases**: UDP performance tuning, NAT table capacity planning, session management

### 5. **Routing & HTTP Dashboard** (`route.json`)

HTTP response and routing metrics:
- HTTP response rate by status code
- Request duration percentiles
- 4xx vs 5xx error trends
- Circuit breaker state changes
- Proxy health status
- Route explain invocations

**Use cases**: HTTP API monitoring, routing troubleshooting, circuit breaker analysis

## 🚀 Quick Start

### Option 1: Manual Import

1. **Access Grafana UI**: Navigate to your Grafana instance (default: `http://localhost:3000`)

2. **Import Dashboard**:
   - Click **+** → **Import**
   - Upload JSON file from `grafana/dashboards/`
   - Select Prometheus datasource
   - Click **Import**

3. **Repeat** for each dashboard

### Option 2: Provisioning (Recommended)

Automatically provision all dashboards using Grafana's provisioning system:

1. **Copy provisioning configs** to your Grafana configuration directory:

   ```bash
   sudo cp grafana/provisioning/*.yml /etc/grafana/provisioning/dashboards/
   ```

2. **Create dashboard directory** and copy dashboard files:

   ```bash
   sudo mkdir -p /var/lib/grafana/dashboards/singbox-rust
   sudo cp grafana/dashboards/*.json /var/lib/grafana/dashboards/singbox-rust/
   ```

3. **Restart Grafana**:

   ```bash
   sudo systemctl restart grafana-server
   ```

Dashboards will appear automatically in Grafana under the **SingBox-Rust** folder.

### Option 3: Docker Compose

Add to your `docker-compose.yml`:

```yaml
services:
  grafana:
    image: grafana/grafana:latest
    volumes:
      - ./grafana/provisioning:/etc/grafana/provisioning
      - ./grafana/dashboards:/var/lib/grafana/dashboards
    environment:
      - GF_AUTH_ANONYMOUS_ENABLED=true
      - GF_AUTH_ANONYMOUS_ORG_ROLE=Viewer
    ports:
      - "3000:3000"
```

## 📋 Prerequisites

### Prometheus Datasource

All dashboards require a Prometheus datasource configured in Grafana:

1. Go to **Configuration** → **Data Sources**
2. Click **Add data source** → **Prometheus**
3. Set URL: `http://localhost:9090` (or your Prometheus address)
4. Click **Save & Test**

### SingBox-Rust Metrics Export

Enable metrics export in singbox-rust:

```bash
# Enable admin API and metrics
export SB_ADMIN_ENABLE=1
export SB_ADMIN_LISTEN=0.0.0.0:18088

# Start singbox-rust
singbox-rust run -c config.yaml
```

### Prometheus Scrape Configuration

Add to `prometheus.yml`:

```yaml
scrape_configs:
  - job_name: 'singbox-rust'
    static_configs:
      - targets: ['localhost:18088']
    scrape_interval: 15s
    scrape_timeout: 10s
```

## 🎨 Dashboard Variables

Each dashboard supports template variables for filtering:

### DNS Dashboard
- **qtype**: Filter by query type (A, AAAA, OTHER, All)

### Proxy Dashboard
- **pool**: Filter by proxy pool name
- **endpoint**: Filter by endpoint (depends on selected pool)
- **outbound_kind**: Filter by outbound protocol type

### Routing Dashboard
- **code**: Filter by HTTP status code

## 🔔 Alerting

See `grafana/alerts/rules.yml` for recommended Prometheus alerting rules:

- **High DNS Error Rate**: Triggered when DNS errors exceed threshold
- **High HTTP Error Rate**: Triggered on elevated HTTP errors
- **NAT Table Capacity**: Warns when NAT table fills up
- **Outbound Connection Failures**: Alerts on connection issues
- **Proxy Health Degradation**: Detects proxy endpoint failures

Import these rules into Prometheus:

```yaml
# prometheus.yml
rule_files:
  - /path/to/grafana/alerts/rules.yml
```

## 📊 Dashboard Features

### Shared Features

All dashboards include:
- **Auto-refresh**: Default 10s refresh interval (configurable)
- **Time Range Selector**: Quick access to common time ranges
- **Cross-linking**: Navigate between related dashboards
- **Templating**: Filter data using variables
- **Annotations**: Support for event markers

### Panel Types

- **Time Series**: Line graphs for trends over time
- **Stat**: Single value with threshold-based coloring
- **Gauge**: Visual representation of capacity/limits
- **Table**: Detailed metric breakdowns

### Color Thresholds

Consistent color scheme across all dashboards:
- **Green**: Normal/healthy operation
- **Yellow**: Warning threshold
- **Red**: Critical threshold

## 🛠 Customization

### Modifying Dashboards

1. **Edit in Grafana UI**:
   - Open dashboard → Click gear icon → **Settings**
   - Make changes → **Save dashboard**
   - Export JSON: **Share** → **Export** → **Save to file**

2. **Edit JSON directly**:
   ```bash
   vim grafana/dashboards/dns.json
   # Make changes
   # Re-import to Grafana
   ```

### Adding Custom Panels

All dashboards use the Grafana schema version 38. To add panels:

1. Copy existing panel block from JSON
2. Increment panel `id`
3. Adjust `gridPos` (x, y, w, h) for layout
4. Update `targets` with your Prometheus queries
5. Configure `fieldConfig` for units and thresholds

### Adjusting Thresholds

Example: Change DNS success rate warning threshold from 90% to 95%:

```json
"thresholds": {
  "mode": "absolute",
  "steps": [
    { "value": 0, "color": "red" },
    { "value": 95, "color": "yellow" },  // Changed from 90
    { "value": 99, "color": "green" }
  ]
}
```

## 📁 Directory Structure

```
grafana/
├── README.md                    # This file
├── dashboards/                  # Grafana dashboard JSON files
│   ├── overview.json           # Overall system health
│   ├── dns.json                # DNS metrics
│   ├── proxy.json              # Proxy & outbound
│   ├── udp.json                # UDP & NAT
│   └── route.json              # Routing & HTTP
├── provisioning/                # Grafana provisioning configs
│   ├── datasources.yml         # Prometheus datasource
│   └── dashboards.yml          # Dashboard provider
└── alerts/                      # Prometheus alerting rules
    └── rules.yml               # Alert definitions
```

## 🔍 Troubleshooting

### Dashboard Shows "No Data"

**Possible causes**:
1. Prometheus datasource not configured → Check **Configuration** → **Data Sources**
2. Singbox-rust metrics not enabled → Verify `SB_ADMIN_ENABLE=1`
3. Prometheus not scraping → Check Prometheus targets: `http://localhost:9090/targets`
4. Wrong datasource selected → Edit dashboard, check datasource variable

### Metrics Missing or Incorrect

**Verify metrics are exported**:
```bash
curl http://localhost:18088/metrics | grep dns_query_total
```

**Check metric names** match dashboard queries:
- DNS: `dns_query_total`, `dns_rtt_ms`, `dns_error_total`
- HTTP: `http_respond_total`, `http_errors_total`
- Proxy: `proxy_select_total`, `outbound_connect_total`
- UDP: `udp_nat_size`, `udp_upstream_fail_total`

### Panel Query Errors

**Invalid query syntax**: Verify PromQL query in Prometheus UI first:
```
http://localhost:9090/graph
```

**Missing labels**: Ensure your singbox-rust version exports expected labels

## 📚 Related Documentation

- **[Prometheus Metrics](../../docs/03-operations/monitoring/metrics.md)** - Metrics catalog and export configuration
- **[Grafana Dashboards Guide](../../docs/03-operations/monitoring/grafana-dashboards.md)** - Detailed dashboard documentation
- **[Operations Guide](../../docs/03-operations/)** - Production deployment and monitoring

## 🤝 Contributing

To contribute improvements to dashboards:

1. Make changes in Grafana UI
2. Export updated JSON
3. Validate JSON format: `jq . dashboard.json`
4. Test import on clean Grafana instance
5. Submit pull request with description

## 📝 License

These dashboards are part of the singbox-rust project and follow the same license.

---

**Questions?** See [Troubleshooting Guide](../../docs/01-user-guide/troubleshooting.md) or file an issue on GitHub.
