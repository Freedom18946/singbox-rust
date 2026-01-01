# Production Deployment Guide

**Version**: v1.0.0 Phase 1  
**Protocols**: Trojan, Shadowsocks  
**Status**: Production Ready  
**Last Updated**: 2026-01-01

---

## Prerequisites

### System Requirements

**Minimum**:
- CPU: 1 vCPU (2+ recommended)
- RAM: 512 MB (1 GB+ recommended)
- Disk: 100 MB
- OS: Linux (x86_64, aarch64)

**Recommended Production**:
- CPU: 4 vCPU
- RAM: 4 GB
- Disk: 10 GB (for logs)
- OS: Ubuntu 22.04 LTS, Debian 12, Alpine Linux

### Network Requirements

- Inbound ports: Configurable (default: 443 for Trojan, 8388 for Shadowsocks)
- Outbound: Internet access required
- Firewall: Allow configured ports

---

## Quick Start

### 1. Install Binary

```bash
# Download latest release
wget https://github.com/Freedom18946/singbox-rust/releases/download/v1.0.0/singbox-rust-linux-x86_64.tar.gz

# Extract
tar -xzf singbox-rust-linux-x86_64.tar.gz
cd singbox-rust

# Make executable
chmod +x singbox-rust

# Verify installation
./singbox-rust --version
```

### 2. Create Configuration

Create `config.json`:

```json
{
  "log": {
    "level": "info",
    "output": "stdout"
  },
  "inbounds": [
    {
      "type": "trojan",
      "tag": "trojan-in",
      "listen": "0.0.0.0",
      "listen_port": 443,
      "password": "CHANGEME_SECURE_PASSWORD",
      "tls": {
        "enabled": true,
        "cert_path": "/path/to/cert.pem",
        "key_path": "/path/to/key.pem"
      }
    }
  ],
  "outbounds": [
    {
      "type": "direct",
      "tag": "direct"
    }
  ],
  "route": {
    "rules": [
      {
        "inbound": ["trojan-in"],
        "outbound": "direct"
      }
    ]
  }
}
```

### 3. Run

```bash
# Run in foreground
./singbox-rust run -c config.json

# Or as systemd service (see below)
sudo systemctl start singbox-rust
```

---

## Docker Deployment

### Using Docker Compose

Create `docker-compose.yml`:

```yaml
version: '3.8'

services:
  singbox-rust:
    image: ghcr.io/freedom18946/singbox-rust:v1.0.0
    container_name: singbox-rust
    restart: unless-stopped
    
    ports:
      - "443:443"      # Trojan
      - "8388:8388"    # Shadowsocks
    
    volumes:
      - ./config.json:/etc/singbox-rust/config.json:ro
      - ./certs:/etc/singbox-rust/certs:ro
      - ./logs:/var/log/singbox-rust
    
    environment:
      - SB_INBOUND_RATE_LIMIT_PER_IP=100
      - SB_INBOUND_RATE_LIMIT_WINDOW_SEC=10
      - SB_INBOUND_RATE_LIMIT_QPS=1000
    
    security_opt:
      - no-new-privileges:true
    
    cap_drop:
      - ALL
    cap_add:
      - NET_BIND_SERVICE
    
    healthcheck:
      test: ["CMD", "wget", "-q", "--spider", "http://localhost:9090/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 10s
```

Run with:

```bash
docker-compose up -d
```

### Standalone Docker

```bash
docker run -d \
  --name singbox-rust \
  --restart unless-stopped \
  -p 443:443 \
  -p 8388:8388 \
  -v $(pwd)/config.json:/etc/singbox-rust/config.json:ro \
  -v $(pwd)/certs:/etc/singbox-rust/certs:ro \
  -e SB_INBOUND_RATE_LIMIT_PER_IP=100 \
  ghcr.io/freedom18946/singbox-rust:v1.0.0
```

---

## Systemd Service

Create `/etc/systemd/system/singbox-rust.service`:

```ini
[Unit]
Description=SingBox Rust Proxy Server
After=network.target
Wants=network-online.target

[Service]
Type=simple
User=singbox
Group=singbox
ExecStart=/usr/local/bin/singbox-rust run -c /etc/singbox-rust/config.json
Restart=on-failure
RestartSec=5s

# Security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/log/singbox-rust
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true

# Resource limits
LimitNOFILE=1000000
LimitNPROC=512

# Environment
Environment="SB_INBOUND_RATE_LIMIT_PER_IP=100"
Environment="SB_INBOUND_RATE_LIMIT_WINDOW_SEC=10"

[Install]
WantedBy=multi-user.target
```

Setup:

```bash
# Create user
sudo useradd -r -M -s /sbin/nologin singbox

# Install binary
sudo cp singbox-rust /usr/local/bin/
sudo chmod +x /usr/local/bin/singbox-rust

# Create directories
sudo mkdir -p /etc/singbox-rust /var/log/singbox-rust
sudo chown singbox:singbox /var/log/singbox-rust

# Copy configuration
sudo cp config.json /etc/singbox-rust/
sudo chmod 600 /etc/singbox-rust/config.json

# Enable and start
sudo systemctl daemon-reload
sudo systemctl enable singbox-rust
sudo systemctl start singbox-rust

# Check status
sudo systemctl status singbox-rust
sudo journalctl -u singbox-rust -f
```

---

## Configuration Reference

### Trojan Inbound

```json
{
  "type": "trojan",
  "tag": "trojan-in",
  "listen": "0.0.0.0",
  "listen_port": 443,
  "password": "your-secure-password-here",
  "tls": {
    "enabled": true,
    "cert_path": "/path/to/fullchain.pem",
    "key_path": "/path/to/privkey.pem",
    "alpn": ["h2", "http/1.1"]
  }
}
```

### Shadowsocks Inbound

```json
{
  "type": "shadowsocks",
  "tag": "ss-in",
  "listen": "0.0.0.0",
  "listen_port": 8388,
  "method": "aes-256-gcm",
  "password": "your-secure-password-here"
}
```

### Rate Limiting (Environment Variables)

```bash
# Per-IP connection limit
export SB_INBOUND_RATE_LIMIT_PER_IP=100

# Time window (seconds)
export SB_INBOUND_RATE_LIMIT_WINDOW_SEC=10

# QPS limit (optional)
export SB_INBOUND_RATE_LIMIT_QPS=1000
```

---

## TLS Certificate Setup

### Using Let's Encrypt (Recommended)

```bash
# Install certbot
sudo apt-get install certbot

# Obtain certificate
sudo certbot certonly --standalone -d your-domain.com

# Certificates will be in:
# /etc/letsencrypt/live/your-domain.com/fullchain.pem
# /etc/letsencrypt/live/your-domain.com/privkey.pem

# Auto-renewal
sudo certbot renew --dry-run
```

Update config.json:

```json
{
  "tls": {
    "enabled": true,
    "cert_path": "/etc/letsencrypt/live/your-domain.com/fullchain.pem",
    "key_path": "/etc/letsencrypt/live/your-domain.com/privkey.pem"
  }
}
```

### Using Self-Signed (Testing Only)

```bash
# Generate certificate
openssl req -x509 -newkey rsa:4096 -nodes \
  -keyout key.pem -out cert.pem -days 365 \
  -subj "/CN=localhost"
```

⚠️ **Warning**: Self-signed certificates are for testing only. Use proper CA-signed certificates in production.

---

## Monitoring

### Health Check Endpoint

```bash
# Check health
curl http://localhost:9090/health

# Expected response
{"status":"ok","uptime":3600}
```

### Prometheus Metrics

```bash
# Metrics endpoint
curl http://localhost:9090/metrics
```

Example metrics:
```
# Active connections
singbox_active_connections{protocol="trojan"} 42
singbox_active_connections{protocol="shadowsocks"} 18

# Rate limiting
singbox_rate_limited_total{protocol="trojan",reason="connection_limit"} 15
singbox_rate_limited_total{protocol="trojan",reason="auth_failure_ban"} 3

# Traffic
singbox_traffic_bytes{protocol="trojan",direction="tx"} 1048576000
singbox_traffic_bytes{protocol="trojan",direction="rx"} 2097152000
```

### Log Monitoring

```bash
# Tail logs
tail -f /var/log/singbox-rust/singbox.log

# Search for errors
grep ERROR /var/log/singbox-rust/singbox.log

# Connection stats
grep "connection accepted" /var/log/singbox-rust/singbox.log | wc -l
```

---

## Production Best Practices

### 1. Security

- ✅ **Use strong passwords** (≥20 characters, random)
- ✅ **Enable TLS 1.2+** (automatic with rustls)
- ✅ **Configure rate limiting** (prevent DoS)
- ✅ **Regular certificate renewal** (Let's Encrypt auto-renew)
- ✅ **Firewall rules** (allow only necessary ports)
- ✅ **Run as non-root user** (singbox user)

### 2. Performance

- ✅ **Increase file descriptor limits** (`ulimit -n 1000000`)
- ✅ **Use appropriate cipher** (ChaCha20-Poly1305 for mobile)
- ✅ **Enable connection pooling** (automatic)
- ✅ **Monitor resource usage** (Prometheus + Grafana)

### 3. Reliability

- ✅ **Setup systemd service** (auto-restart on failure)
- ✅ **Configure health checks** (Docker/K8s)
- ✅ **Log rotation** (logrotate)
- ✅ **Backup configuration** (version control)

### 4. Monitoring

- ✅ **Enable metrics endpoint**
- ✅ **Setup Prometheus scraping**
- ✅ **Create Grafana dashboards**
- ✅ **Configure alerts** (connection drops, high error rate)

---

## Troubleshooting

### Port Already in Use

```bash
# Check what's using the port
sudo lsof -i :443

# Kill process or change port in config
```

### TLS Certificate Errors

```bash
# Verify certificate
openssl x509 -in /path/to/cert.pem -text -noout

# Check expiration
openssl x509 -in /path/to/cert.pem -noout -enddate

# Test TLS handshake
openssl s_client -connect localhost:443 -servername your-domain.com
```

### High Memory Usage

```bash
# Check connections
netstat -an | grep ESTABLISHED | wc -l

# Adjust rate limiting
export SB_INBOUND_RATE_LIMIT_PER_IP=50

# Restart service
sudo systemctl restart singbox-rust
```

### Rate Limiting Too Aggressive

```bash
# Increase limits
export SB_INBOUND_RATE_LIMIT_PER_IP=200
export SB_INBOUND_RATE_LIMIT_WINDOW_SEC=60

# Or disable temporarily
unset SB_INBOUND_RATE_LIMIT_PER_IP
unset SB_INBOUND_RATE_LIMIT_WINDOW_SEC
```

---

## Kubernetes Deployment

See `k8s/` directory for:
- Deployment manifests
- Service configuration
- Ingress setup
- ConfigMap templates
- Secret management

Quick deploy:

```bash
kubectl apply -f k8s/namespace.yaml
kubectl apply -f k8s/configmap.yaml
kubectl apply -f k8s/deployment.yaml
kubectl apply -f k8s/service.yaml
```

---

## Upgrade Guide

### Rolling Upgrade (Zero Downtime)

1. Download new version
2. Test with new config
3. Graceful restart

```bash
# Docker
docker-compose pull
docker-compose up -d

# Systemd
sudo systemctl reload singbox-rust

# Kubernetes
kubectl rollout restart deployment/singbox-rust
```

### Configuration Migration

Check CHANGELOG.md for breaking changes between versions.

---

## Support

- **Documentation**: https://singbox-rust.dev/docs
- **Issues**: https://github.com/Freedom18946/singbox-rust/issues
- **Discussions**: https://github.com/Freedom18946/singbox-rust/discussions

---

## License

See LICENSE file in repository.
