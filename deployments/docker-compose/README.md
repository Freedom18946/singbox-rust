# Docker Compose Deployment Guide

## Quick Start

```bash
# 1. Create directory structure
mkdir -p singbox-deployment/{config-examples,certs}
cd singbox-deployment

# 2. Copy configuration files
cp /path/to/deployments/config-examples/*.json config-examples/
cp /path/to/deployments/docker-compose/docker-compose.yml .

# 3. Edit configuration files
vim config-examples/trojan-server.json
vim config-examples/shadowsocks-server.json

# 4. Create/copy TLS certificates (for Trojan)
# Using Let's Encrypt:
certbot certonly --standalone -d example.com
cp /etc/letsencrypt/live/example.com/fullchain.pem certs/
cp /etc/letsencrypt/live/example.com/privkey.pem certs/

# 5. Start services
docker-compose up -d

# 6. Check status
docker-compose ps
docker-compose logs -f
```

## Configuration

### Environment Variables

Edit `docker-compose.yml` to adjust:

**Rate Limiting**:
```yaml
environment:
  SB_INBOUND_RATE_LIMIT_PER_IP: 100
  SB_INBOUND_RATE_LIMIT_WINDOW_SEC: 10
  SB_INBOUND_RATE_LIMIT_QPS: 1000
```

**UDP Limits**:
```yaml
environment:
  SB_UDP_OUTBOUND_BPS_MAX: 104857600  # 100 MB/s
  SB_UDP_OUTBOUND_PPS_MAX: 100000     # 100k pps
```

### Resource Limits

Adjust based on your server:

```yaml
deploy:
  resources:
    limits:
      cpus: '2.0'       # Maximum CPU
      memory: 1G        # Maximum memory
    reservations:
      cpus: '0.5'       # Reserved CPU
      memory: 256M      # Reserved memory
```

## Services

### Trojan Server
- **Port**: 443 (HTTPS)
- **Protocol**: Trojan over TLS
- **Users**: Configured in `trojan-server.json`

### Shadowsocks Server
- **Port**: 8388 (TCP + UDP)
- **Method**: ChaCha20-Poly1305
- **Password**: Configured in `shadowsocks-server.json`

### Prometheus (Optional)
- **Port**: 9090
- **Purpose**: Metrics collection
- **Access**: http://localhost:9090

### Grafana (Optional)
- **Port**: 3000
- **Default Login**: admin/admin
- **Access**: http://localhost:3000

## Management Commands

```bash
# Start all services
docker-compose up -d

# Stop all services
docker-compose down

# Restart a specific service
docker-compose restart trojan-server

# View logs
docker-compose logs -f trojan-server
docker-compose logs -f shadowsocks-server

# Check resource usage
docker stats

# Update configuration
vim config-examples/trojan-server.json
docker-compose restart trojan-server

# Scale services (if needed)
docker-compose up -d --scale shadowsocks-server=3
```

## Monitoring

### Prometheus Queries

Access Prometheus at http://localhost:9090 and run:

```promql
# Active connections
active_connections{protocol="trojan"}

# Rate limited requests
rate(rate_limited_total[5m])

# Data transfer
rate(bytes_sent_total[5m])
```

### Grafana Dashboards

1. Access Grafana: http://localhost:3000
2. Login: admin/admin
3. Add Prometheus data source: http://prometheus:9090
4. Import dashboard or create custom panels

## Security Best Practices

### 1. Change Default Passwords

```bash
# Edit config files
vim config-examples/trojan-server.json
# Change all passwords to strong random strings
```

### 2. Firewall Rules

```bash
# Allow only necessary ports
sudo ufw allow 443/tcp  # Trojan
sudo ufw allow 8388     # Shadowsocks (if exposed)
sudo ufw enable
```

### 3. TLS Certificates

Use valid certificates from Let's Encrypt:

```bash
# Install certbot
sudo apt install certbot

# Get certificate
sudo certbot certonly --standalone -d your-domain.com

# Auto-renewal
sudo crontab -e
# Add: 0 0 * * * certbot renew --quiet --post-hook "docker-compose restart trojan-server"
```

### 4. Regular Updates

```bash
# Pull latest image
docker-compose pull

# Restart with new image
docker-compose up -d
```

## Troubleshooting

### Service Won't Start

```bash
# Check logs
docker-compose logs trojan-server

# Validate config
docker run --rm -v $PWD/config-examples:/etc/singbox \
  ghcr.io/freedom18946/singbox-rust:v1.0.0 \
  singbox-rust check --config /etc/singbox/trojan-server.json
```

### Port Already in Use

```bash
# Find what's using the port
sudo lsof -i :443
sudo netstat -tulpn | grep :443

# Change port in docker-compose.yml
ports:
  - "8443:443"  # Map to different host port
```

### Performance Issues

```bash
# Check resource usage
docker stats

# Increase limits in docker-compose.yml
deploy:
  resources:
    limits:
      cpus: '4.0'
      memory: 2G
```

## Backup & Recovery

### Backup

```bash
# Backup configuration
tar -czf singbox-backup-$(date +%Y%m%d).tar.gz \
  config-examples/ certs/

# Backup data volumes
docker run --rm -v singbox-deployment_trojan-data:/data \
  -v $PWD:/backup alpine \
  tar -czf /backup/trojan-data-backup.tar.gz -C /data .
```

### Recovery

```bash
# Restore configuration
tar -xzf singbox-backup-20251127.tar.gz

# Restore data
docker run --rm -v singbox-deployment_trojan-data:/data \
  -v $PWD:/backup alpine \
  tar -xzf /backup/trojan-data-backup.tar.gz -C /data

# Restart services
docker-compose up -d
```

## Production Checklist

- [ ] Changed all default passwords
- [ ] Valid TLS certificates installed
- [ ] Firewall configured
- [ ] Rate limiting configured
- [ ] Resource limits set appropriately
- [ ] Logging configured
- [ ] Monitoring enabled (Prometheus/Grafana)
- [ ] Backup scheduled
- [ ] Auto-update configured

## Support

For issues, see:
- [Deployment Guide](../../docs/DEPLOYMENT_GUIDE.md)
- [Troubleshooting](../../docs/TROUBLESHOOTING.md)
- [GitHub Issues](https://github.com/Freedom18946/singbox-rust/issues)
