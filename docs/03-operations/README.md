# Operations Guide

Production deployment, monitoring, and maintenance guide for singbox-rust.

---

## 📖 Documentation Sections

### Deployment

- **[Systemd Deployment](deployment/systemd.md)** - Linux systemd service setup
- **[Docker Deployment](deployment/docker.md)** - Containerized deployment
- **[Kubernetes](deployment/kubernetes.md)** - K8s deployment manifests
- **[Windows Service](deployment/windows-service.md)** - Windows service installation

### Monitoring

- **[Prometheus Metrics](monitoring/metrics.md)** - Metrics exposition and collection
- **[Logging](monitoring/logging.md)** - Log configuration and aggregation
- **[Grafana Dashboards](monitoring/grafana-dashboards.md)** - Pre-built dashboards

### Performance

- **[Optimization Guide](performance/optimization-guide.md)** - Performance tuning strategies
- **[Optimization Checklist](performance/optimization-checklist.md)** - Quick optimization steps
- **[Quick Start](performance/quick-start.md)** - Fast performance wins

### Security

- **[Hardening Guide](security/hardening.md)** - System and application hardening
- **[TLS Best Practices](security/tls-best-practices.md)** - TLS security configuration
- **[Credential Management](security/credential-management.md)** - Secrets and key management

---

## Quick Start

### 1. Deploy with Systemd (Linux)

```bash
# Install binary
sudo cp singbox-rust /usr/local/bin/

# Create config directory
sudo mkdir -p /etc/singbox
sudo cp config.yaml /etc/singbox/

# Install systemd service
sudo cp packaging/systemd/singbox-rs.service /etc/systemd/system/

# Enable and start
sudo systemctl daemon-reload
sudo systemctl enable --now singbox-rs

# Check status
sudo systemctl status singbox-rs
```

See [Systemd Deployment](deployment/systemd.md).

### 2. Deploy with Docker

```bash
# Build image
docker build -t singbox-rust:latest -f packaging/docker/Dockerfile.musl .

# Run container
docker run -d \
  --name singbox-rust \
  -v /path/to/config.yaml:/etc/singbox/config.yaml:ro \
  -p 1080:1080 \
  -p 18088:18088 \
  --restart unless-stopped \
  singbox-rust:latest \
  run -c /etc/singbox/config.yaml
```

See [Docker Deployment](deployment/docker.md).

### 3. Enable Monitoring

```bash
# Enable admin API and metrics
export SB_ADMIN_ENABLE=1
export SB_ADMIN_LISTEN=0.0.0.0:18088

# Start with metrics
singbox-rust run -c config.yaml

# Scrape metrics
curl http://127.0.0.1:18088/metrics
```

See [Prometheus Metrics](monitoring/metrics.md).

---

## Deployment Patterns

### Pattern 1: Standalone Server

Simple single-server deployment:

```
┌─────────────────────┐
│   singbox-rust      │
│   - Systemd service │
│   - Local config    │
│   - Metrics enabled │
└─────────────────────┘
```

**Best for**: Personal use, small teams, development

See [Systemd Deployment](deployment/systemd.md).

### Pattern 2: Docker Container

Containerized deployment with volume mounts:

```
┌─────────────────────────────┐
│       Docker Host           │
│  ┌─────────────────────┐   │
│  │  singbox-rust       │   │
│  │  - Config volume    │   │
│  │  - Port mappings    │   │
│  │  - Healthcheck      │   │
│  └─────────────────────┘   │
└─────────────────────────────┘
```

**Best for**: Cloud deployments, CI/CD, multi-environment

See [Docker Deployment](deployment/docker.md).

### Pattern 3: Kubernetes Cluster

Scalable K8s deployment with ConfigMaps:

```
┌──────────────────────────────────┐
│      Kubernetes Cluster          │
│  ┌────────────────────────┐     │
│  │   singbox-rust pods    │     │
│  │   - ConfigMap mount    │     │
│  │   - Service LB         │     │
│  │   - Health probes      │     │
│  └────────────────────────┘     │
└──────────────────────────────────┘
```

**Best for**: Large-scale deployments, high availability

See [Kubernetes Deployment](deployment/kubernetes.md).

### Pattern 4: High Availability

Multi-instance deployment with load balancing:

```
┌─────────────────────────────────────┐
│          Load Balancer              │
│                                     │
│  ┌───────┐  ┌───────┐  ┌───────┐  │
│  │ Inst1 │  │ Inst2 │  │ Inst3 │  │
│  └───────┘  └───────┘  └───────┘  │
│                                     │
│  ┌───────────────────────────┐     │
│  │  Prometheus + Grafana     │     │
│  └───────────────────────────┘     │
└─────────────────────────────────────┘
```

**Best for**: Production, mission-critical services

Combine [Kubernetes](deployment/kubernetes.md) + [Monitoring](monitoring/).

---

## Configuration Management

### Environment-Based Configs

Manage multiple environments:

```bash
configs/
├── base.yaml          # Common settings
├── dev.yaml           # Development overrides
├── staging.yaml       # Staging overrides
└── prod.yaml          # Production overrides
```

**Merge configs**:

```bash
# Development
singbox-rust merge -c configs/base.yaml -c configs/dev.yaml config.yaml

# Production
singbox-rust merge -c configs/base.yaml -c configs/prod.yaml config.yaml
```

### Secrets Management

**DO NOT** commit secrets to version control:

```yaml
# BAD - Password in config
outbounds:
  - type: shadowsocks
    password: my-secret-password # ❌ NEVER DO THIS
```

**GOOD - Environment variables**:

```yaml
outbounds:
  - type: shadowsocks
    password: ${SS_PASSWORD} # ✅ From environment
```

**Or use Docker secrets**:

```bash
docker run -d \
  --name singbox-rust \
  -e SS_PASSWORD=$(cat /run/secrets/ss_password) \
  ...
```

See [Credential Management](security/credential-management.md).

---

## Monitoring & Observability

### Metrics

singbox-rust exposes Prometheus metrics at `/metrics`:

**Key metrics**:

- `sb_connections_total{protocol, direction}` - Connection counts
- `sb_traffic_bytes{protocol, direction}` - Bandwidth usage
- `sb_latency_seconds{protocol}` - Connection latency
- `sb_errors_total{protocol, error_type}` - Error counts
- `sb_udp_nat_sessions` - Active UDP NAT sessions

**Prometheus config**:

```yaml
scrape_configs:
  - job_name: "singbox-rust"
    static_configs:
      - targets: ["localhost:18088"]
    scrape_interval: 15s
```

See [Prometheus Metrics](monitoring/metrics.md).

### Logging

Configure structured logging:

```bash
# Log levels
RUST_LOG=info singbox-rust run -c config.yaml           # Info level
RUST_LOG=debug singbox-rust run -c config.yaml          # Debug level
RUST_LOG=sb_tls=debug,sb_core=info singbox-rust run ... # Per-module

# JSON output
APP_LOG_JSON=1 RUST_LOG=info singbox-rust run -c config.yaml
```

**Log aggregation**:

```bash
# Systemd journal
journalctl -u singbox-rs -f

# Docker logs
docker logs -f singbox-rust

# File output
singbox-rust run -c config.yaml >> /var/log/singbox.log 2>&1
```

See [Logging](monitoring/logging.md).

### Health Checks

**HTTP endpoint**:

```bash
# Metrics endpoint (also serves as health check)
curl -f http://127.0.0.1:18088/metrics || exit 1

# Admin ping (if admin API enabled)
curl -f http://127.0.0.1:18088/admin/ping || exit 1
```

**Systemd health check**:

```ini
[Service]
ExecStart=/usr/local/bin/singbox-rust run -c /etc/singbox/config.yaml
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=5s
```

**Docker health check**:

```dockerfile
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:18088/metrics || exit 1
```

---

## Performance Tuning

### Quick Wins

1. **Enable Connection Pooling** (SSH outbound)

   ```yaml
   outbounds:
     - type: ssh
       connection_pool_size: 10 # Default: 5
   ```

2. **Use Multiplex** for multiple connections

   ```yaml
   outbounds:
     - type: vmess
       multiplex:
         enabled: true
         max_streams: 8
   ```

3. **Optimize UDP NAT Table**

   ```bash
   SB_UDP_NAT_MAX=10000 singbox-rust run -c config.yaml
   ```

4. **Use Native Process Matching**
   - macOS: 149x faster than command-line tools
   - Windows: 20-50x faster
   - No additional config needed!

See [Optimization Quick Start](performance/quick-start.md).

### System Tuning

**Linux**:

```bash
# Increase file descriptor limit
ulimit -n 1000000

# Increase network buffers
sysctl -w net.core.rmem_max=26214400
sysctl -w net.core.wmem_max=26214400

# Increase connection tracking
sysctl -w net.netfilter.nf_conntrack_max=1000000
```

**Systemd service**:

```ini
[Service]
LimitNOFILE=1000000
```

See [Optimization Guide](performance/optimization-guide.md).

---

## Security Hardening

### System Level

1. **Run as non-root user**:

   ```bash
   # Create dedicated user
   sudo useradd -r -s /bin/false singbox

   # Grant TUN capability (if needed)
   sudo setcap cap_net_admin+ep /usr/local/bin/singbox-rust
   ```

2. **Restrict file permissions**:

   ```bash
   sudo chmod 600 /etc/singbox/config.yaml
   sudo chown singbox:singbox /etc/singbox/config.yaml
   ```

3. **Use systemd sandboxing**:
   ```ini
   [Service]
   User=singbox
   Group=singbox
   PrivateTmp=yes
   NoNewPrivileges=true
   ProtectSystem=strict
   ProtectHome=true
   ReadWritePaths=/var/lib/singbox
   ```

### Application Level

1. **Enable TLS certificate verification**:

   ```yaml
   tls:
     skip_cert_verify: false # Always verify in production!
   ```

2. **Use JWT authentication** for admin API:

   ```yaml
   admin:
     jwt:
       enabled: true
       secret: ${JWT_SECRET} # From environment
   ```

3. **Configure rate limiting**:
   ```yaml
   admin:
     rate_limit:
       qps: 100
       burst: 200
   ```

See [Security Hardening](security/hardening.md).

---

## Troubleshooting

### Service Won't Start

**Check logs**:

```bash
# Systemd
sudo journalctl -u singbox-rs -n 50 --no-pager

# Docker
docker logs singbox-rust --tail 50
```

**Common issues**:

- Configuration validation failed → Run `singbox-rust check -c config.yaml`
- Port already in use → Check with `sudo lsof -i :1080`
- Permission denied (TUN) → Grant `CAP_NET_ADMIN` capability

### High Memory Usage

**Check metrics**:

```bash
curl http://127.0.0.1:18088/metrics | grep memory
```

**Possible causes**:

- Too many concurrent connections → Reduce `max_connections`
- Large UDP NAT table → Reduce `SB_UDP_NAT_MAX`
- Memory leak → Enable debug logging and report issue

### High CPU Usage

**Profile performance**:

```bash
# Enable perf-friendly symbols
cargo build --profile release-with-debug

# Profile with perf
perf record -g singbox-rust run -c config.yaml
perf report
```

**Common causes**:

- High connection rate → Enable connection pooling
- Expensive routing rules → Optimize rule order
- DNS resolution overhead → Use DoH/DoT with caching

See [Troubleshooting Guide](../01-user-guide/troubleshooting.md).

---

## Backup and Recovery

### Configuration Backup

```bash
# Backup config
tar czf singbox-backup-$(date +%Y%m%d).tar.gz \
  /etc/singbox/config.yaml \
  /etc/singbox/geoip.db \
  /etc/singbox/geosite.db

# Restore config
tar xzf singbox-backup-20251018.tar.gz -C /
sudo systemctl restart singbox-rs
```

### State Backup

```bash
# Backup runtime state (if applicable)
cp -r /var/lib/singbox /backup/singbox-state-$(date +%Y%m%d)
```

---

## Maintenance

### Update Procedure

```bash
# 1. Backup current config
sudo cp /etc/singbox/config.yaml /etc/singbox/config.yaml.bak

# 2. Download new binary
curl -LO https://github.com/your-repo/releases/latest/download/singbox-rust

# 3. Stop service
sudo systemctl stop singbox-rs

# 4. Replace binary
sudo mv singbox-rust /usr/local/bin/
sudo chmod +x /usr/local/bin/singbox-rust

# 5. Validate config (in case of schema changes)
singbox-rust check -c /etc/singbox/config.yaml

# 6. Start service
sudo systemctl start singbox-rs

# 7. Verify
sudo systemctl status singbox-rs
```

### Database Updates

```bash
# Update GeoIP/Geosite databases
wget https://github.com/SagerNet/sing-geoip/releases/latest/download/geoip.db
wget https://github.com/SagerNet/sing-geosite/releases/latest/download/geosite.db

# Move to config directory
sudo mv geoip.db geosite.db /etc/singbox/

# Reload (if hot-reload supported)
sudo systemctl reload singbox-rs
```

---

## Resource Planning

### Small Deployment (< 100 users)

- **CPU**: 2 cores
- **RAM**: 512 MB
- **Network**: 100 Mbps
- **Storage**: 100 MB

### Medium Deployment (100-1000 users)

- **CPU**: 4 cores
- **RAM**: 2 GB
- **Network**: 1 Gbps
- **Storage**: 1 GB

### Large Deployment (> 1000 users)

- **CPU**: 8+ cores
- **RAM**: 4+ GB
- **Network**: 10+ Gbps
- **Storage**: 10+ GB (for logs/metrics)

**Note**: Actual requirements vary by traffic patterns and enabled features.

---

## Related Documentation

- **[Systemd Deployment](deployment/systemd.md)** - Linux service setup
- **[Docker Deployment](deployment/docker.md)** - Container deployment
- **[Prometheus Metrics](monitoring/metrics.md)** - Monitoring setup
- **[Performance Tuning](performance/optimization-guide.md)** - Optimization guide
- **[Security Hardening](security/hardening.md)** - Security best practices

---

**Need Help?**

- [Troubleshooting Guide](../01-user-guide/troubleshooting.md)
- [GitHub Issues](https://github.com/your-repo/issues)
- [User Guide](../01-user-guide/)
