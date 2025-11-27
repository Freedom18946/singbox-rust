# Production Deployment Guide - singbox-rust

**Version**: 1.0.0  
**Target Protocols**: Trojan, Shadowsocks (Phase 1)  
**Last Updated**: 2025-11-27

---

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Docker Deployment](#docker-deployment)
3. [Kubernetes Deployment](#kubernetes-deployment)
4. [systemd Deployment](#systemd-deployment)
5. [Configuration](#configuration)
6. [Monitoring & Observability](#monitoring--observability)
7. [Security Best Practices](#security-best-practices)
8. [Troubleshooting](#troubleshooting)

---

## Prerequisites

### System Requirements

**Minimum**:
- CPU: 1 core
- RAM: 512 MB
- Storage: 100 MB
- Network: Stable internet connection

**Recommended (Production)**:
- CPU: 2+ cores
- RAM: 2 GB
- Storage: 1 GB
- Network: Low-latency connection

### Dependencies

- **Docker**: 20.10+ (for container deployment)
- **Kubernetes**: 1.24+ (for K8s deployment)
- **systemd**: 237+ (for systemd deployment)

---

## Docker Deployment

### Quick Start

```bash
# 1. Pull image (once published)
docker pull ghcr.io/freedom18946/singbox-rust:v1.0.0

# 2. Create config file
mkdir -p /etc/singbox
cat > /etc/singbox/config.json <<EOF
{
  "log": {"level": "info"},
  "inbounds": [{
    "type": "shadowsocks",
    "listen": "0.0.0.0",
    "port": 1080,
    "method": "chacha20-poly1305",
    "password": "your-secure-password"
  }],
  "outbounds": [{"type": "direct"}]
}
EOF

# 3. Run container
docker run -d \
  --name singbox-rust \
  --restart unless-stopped \
  -v /etc/singbox:/etc/singbox:ro \
  -p 1080:1080 \
  -e SB_INBOUND_RATE_LIMIT_PER_IP=100 \
  -e SB_INBOUND_RATE_LIMIT_WINDOW_SEC=10 \
  ghcr.io/freedom18946/singbox-rust:v1.0.0
```

### Production Docker Deployment

```bash
# 1. Create dedicated network
docker network create singbox-net

# 2. Run with production settings
docker run -d \
  --name singbox-rust \
  --restart unless-stopped \
  --network singbox-net \
  --log-driver json-file \
  --log-opt max-size=10m \
  --log-opt max-file=3 \
  -v /etc/singbox:/etc/singbox:ro \
  -v /var/lib/singbox:/var/lib/singbox \
  -p 1080:1080 \
  -p 8080:8080 \
  -p 443:443 \
  -e SB_LOG_LEVEL=info \
  -e SB_INBOUND_RATE_LIMIT_PER_IP=100 \
  -e SB_INBOUND_RATE_LIMIT_WINDOW_SEC=10 \
  -e SB_INBOUND_RATE_LIMIT_QPS=1000 \
  --memory=512m \
  --cpus=1.0 \
  --health-cmd="singbox-rust version" \
  --health-interval=30s \
  --health-timeout=3s \
  --health-retries=3 \
  ghcr.io/freedom18946/singbox-rust:v1.0.0
```

### Docker Compose Example

```yaml
version: '3.8'

services:
  singbox-rust:
    image: ghcr.io/freedom18946/singbox-rust:v1.0.0
    container_name: singbox-rust
    restart: unless-stopped
    
    ports:
      - "1080:1080"  # Shadowsocks
      - "443:443"    # Trojan
    
    volumes:
      - ./config:/etc/singbox:ro
      - ./data:/var/lib/singbox
    
    environment:
      SB_LOG_LEVEL: info
      SB_INBOUND_RATE_LIMIT_PER_IP: 100
      SB_INBOUND_RATE_LIMIT_WINDOW_SEC: 10
    
    deploy:
      resources:
        limits:
          cpus: '1.0'
          memory: 512M
        reservations:
          cpus: '0.5'
          memory: 256M
    
    healthcheck:
      test: ["CMD", "singbox-rust", "version"]
      interval: 30s
      timeout: 3s
      retries: 3
      start_period: 5s
    
    logging:
      driver: json-file
      options:
        max-size: "10m"
        max-file: "3"

networks:
  default:
    driver: bridge
```

---

## Kubernetes Deployment

### Prerequisites

```bash
# Create namespace
kubectl create namespace singbox-system

# Create secret for sensitive config
kubectl create secret generic singbox-config \
  --from-file=config.json=/path/to/config.json \
  -n singbox-system
```

### Deploy with kubectl

```bash
# 1. Apply deployment
kubectl apply -f deployments/kubernetes/deployment.yaml

# 2. Verify deployment
kubectl get pods -n singbox-system
kubectl get svc -n singbox-system

# 3. Check logs
kubectl logs -f deployment/singbox-rust -n singbox-system

# 4. Check health
kubectl describe pod -l app=singbox-rust -n singbox-system
```

### Helm Chart (Future)

```bash
# Install with Helm (once chart is published)
helm repo add singbox https://freedom18946.github.io/singbox-rust-charts
helm install singbox-rust singbox/singbox-rust \
  --namespace singbox-system \
  --create-namespace \
  --set replicaCount=3 \
  --set resources.limits.memory=512Mi \
  --set config.rateLimit.perIP=100
```

### Scaling

```bash
# Horizontal scaling
kubectl scale deployment singbox-rust --replicas=5 -n singbox-system

# Autoscaling
kubectl autoscale deployment singbox-rust \
  --cpu-percent=70 \
  --min=3 \
  --max=10 \
  -n singbox-system
```

---

## systemd Deployment

### Installation

```bash
# 1. Build binary
cargo build --release --package app \
  --features "router,adapters,observe"

# 2. Install binary
sudo cp target/release/run /usr/local/bin/singbox-rust
sudo chmod +x /usr/local/bin/singbox-rust

# 3. Create user
sudo useradd -r -s /bin/false -M singbox

# 4. Create directories
sudo mkdir -p /etc/singbox
sudo mkdir -p /var/lib/singbox
sudo mkdir -p /var/log/singbox
sudo chown -R singbox:singbox /var/lib/singbox /var/log/singbox

# 5. Create config
sudo vim /etc/singbox/config.json

# 6. Install service file
sudo cp deployments/systemd/singbox-rust.service /etc/systemd/system/
sudo systemctl daemon-reload
```

### Service Management

```bash
# Start service
sudo systemctl start singbox-rust

# Enable auto-start
sudo systemctl enable singbox-rust

# Check status
sudo systemctl status singbox-rust

# View logs
sudo journalctl -u singbox-rust -f

# Restart
sudo systemctl restart singbox-rust

# Reload config (SIGHUP)
sudo systemctl reload singbox-rust

# Stop
sudo systemctl stop singbox-rust
```

---

## Configuration

### Trojan Configuration Example

```json
{
  "log": {
    "level": "info",
    "timestamp": true
  },
  "inbounds": [
    {
      "type": "trojan",
      "tag": "trojan-in",
      "listen": "0.0.0.0",
      "port": 443,
      "password": "your-secure-password",
      "tls": {
        "enabled": true,
        "cert_path": "/etc/singbox/cert.pem",
        "key_path": "/etc/singbox/key.pem",
        "sni": "example.com",
        "alpn": ["h2", "http/1.1"]
      }
    }
  ],
  "outbounds": [
    {
      "type": "direct",
      "tag": "direct"
    }
  ]
}
```

### Shadowsocks Configuration Example

```json
{
  "log": {
    "level": "info"
  },
  "inbounds": [
    {
      "type": "shadowsocks",
      "tag": "ss-in",
      "listen": "0.0.0.0",
      "port": 1080,
      "method": "chacha20-poly1305",
      "password": "your-secure-password"
    }
  ],
  "outbounds": [
    {
      "type": "direct",
      "tag": "direct"
    }
  ]
}
```

### Rate Limiting Configuration

**Environment Variables**:

```bash
# TCP Rate Limiting
export SB_INBOUND_RATE_LIMIT_PER_IP=100        # Max connections per IP
export SB_INBOUND_RATE_LIMIT_WINDOW_SEC=10     # Time window
export SB_INBOUND_RATE_LIMIT_QPS=1000          # Queries per second

# Auth Failure Protection
export SB_INBOUND_AUTH_FAILURE_MAX=10          # Max auth failures
export SB_INBOUND_AUTH_FAILURE_WINDOW_SEC=60   # Ban window

# UDP Rate Limiting
export SB_UDP_OUTBOUND_BPS_MAX=10485760        # 10 MB/s
export SB_UDP_OUTBOUND_PPS_MAX=10000           # 10k packets/s
```

---

## Monitoring & Observability

### Prometheus Metrics

**Endpoint**: `http://localhost:9090/metrics`

**Key Metrics**:
```
# Rate limiting
rate_limited_total{protocol="trojan",reason="connection_limit"}
rate_limited_total{protocol="shadowsocks",reason="qps_limit"}

# Connections
active_connections{protocol="trojan"}
connection_errors_total{protocol="shadowsocks"}

# Traffic
bytes_sent_total{protocol="trojan"}
bytes_received_total{protocol="shadowsocks"}
```

### Logging

**Log Levels**:
- `error`: Critical errors only
- `warn`: Warnings + errors
- `info`: General information (recommended)
- `debug`: Detailed debugging
- `trace`: Very verbose (development only)

**Structured Logging** (JSON):
```bash
export SB_LOG_FORMAT=json
```

---

## Security Best Practices

### 1. TLS Configuration

✅ **DO**:
- Use strong passwords (≥16 characters, random)
- Enable TLS 1.3 where possible
- Use valid certificates (Let's Encrypt)
- Configure ALPN for Trojan

❌ **DON'T**:
- Use default/weak passwords
- Disable certificate verification in production
- Expose admin API publicly

### 2. Network Security

```bash
# Firewall rules (iptables example)
sudo iptables -A INPUT -p tcp --dport 443 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 1080 -j DROP  # Block external SS
```

### 3. Rate Limiting

**Recommended Settings**:
```bash
# Conservative (public server)
SB_INBOUND_RATE_LIMIT_PER_IP=50
SB_INBOUND_RATE_LIMIT_WINDOW_SEC=10

# Moderate (semi-public)
SB_INBOUND_RATE_LIMIT_PER_IP=100
SB_INBOUND_RATE_LIMIT_WINDOW_SEC=10

# Permissive (private server)
SB_INBOUND_RATE_LIMIT_PER_IP=500
SB_INBOUND_RATE_LIMIT_WINDOW_SEC=60
```

### 4. File Permissions

```bash
# Config files
chmod 600 /etc/singbox/config.json
chmod 600 /etc/singbox/key.pem
chown singbox:singbox /etc/singbox/*

# Binary
chmod 755 /usr/local/bin/singbox-rust
chown root:root /usr/local/bin/singbox-rust
```

---

## Troubleshooting

See [TROUBLESHOOTING.md](./TROUBLESHOOTING.md) for detailed troubleshooting guide.

**Quick Checks**:

```bash
# Check if running
systemctl is-active singbox-rust  # systemd
docker ps | grep singbox-rust     # Docker
kubectl get pods -l app=singbox-rust  # K8s

# Check logs
journalctl -u singbox-rust -n 50   # systemd
docker logs singbox-rust --tail 50  # Docker
kubectl logs -l app=singbox-rust --tail=50  # K8s

# Test connectivity
curl -v --socks5 localhost:1080 https://google.com
```

---

## Maintenance

### Backup

```bash
# Backup config
tar -czf singbox-backup-$(date +%Y%m%d).tar.gz \
  /etc/singbox \
  /var/lib/singbox

# Restore
tar -xzf singbox-backup-20251127.tar.gz -C /
```

### Updates

```bash
# Docker
docker pull ghcr.io/freedom18946/singbox-rust:latest
docker stop singbox-rust
docker rm singbox-rust
# Re-run docker run command

# systemd
# Build new binary and replace
sudo systemctl restart singbox-rust

# Kubernetes
kubectl set image deployment/singbox-rust \
  singbox-rust=ghcr.io/freedom18946/singbox-rust:v1.1.0
```

---

## Support

- **Documentation**: [GitHub Wiki](https://github.com/Freedom18946/singbox-rust/wiki)
- **Issues**: [GitHub Issues](https://github.com/Freedom18946/singbox-rust/issues)
- **Security**: security@example.com

---

**Document Version**: 1.0.0  
**Last Updated**: 2025-11-27
