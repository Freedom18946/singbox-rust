# Troubleshooting Runbook - singbox-rust

**Version**: 1.0.0  
**Protocols**: Trojan, Shadowsocks (Phase 1)  
**Last Updated**: 2025-11-27

---

## Table of Contents

1. [Common Issues](#common-issues)
2. [Connection Problems](#connection-problems)
3. [Performance Issues](#performance-issues)
4. [Rate Limiting Issues](#rate-limiting-issues)
5. [TLS/Certificate Errors](#tlscertificate-errors)
6. [Resource Exhaustion](#resource-exhaustion)
7. [Logging & Debugging](#logging--debugging)
8. [Emergency Procedures](#emergency-procedures)

---

## Common Issues

### Service Won't Start

**Symptom**: `systemctl start singbox-rust` fails

**Diagnosis**:
```bash
# Check status
sudo systemctl status singbox-rust

# View recent logs
sudo journalctl -u singbox-rust -n 50 --no-pager

# Check config syntax
singbox-rust check --config /etc/singbox/config.json
```

**Common Causes**:

1. **Invalid Configuration**
   ```bash
   # Validate JSON syntax
   jq . /etc/singbox/config.json
   
   # Fix: Correct JSON errors
   ```

2. **Port Already in Use**
   ```bash
   # Check what's using the port
   sudo lsof -i :1080
   sudo netstat -tulpn | grep 1080
   
   # Fix: Change port or stop conflicting service
   ```

3. **Permission Denied**
   ```bash
   # Check file permissions
   ls -la /etc/singbox/
   
   # Fix permissions
   sudo chown -R singbox:singbox /etc/singbox
   sudo chmod 600 /etc/singbox/config.json
   ```

4. **Missing Certificate Files**
   ```bash
   # Check if cert files exist
   ls -la /etc/singbox/cert.pem /etc/singbox/key.pem
   
   # Fix: Generate or copy certificates
   ```

---

## Connection Problems

### Cannot Connect to Server

**Symptom**: Clients cannot establish connection

**Diagnosis Steps**:

```bash
# 1. Check if service is running
sudo systemctl is-active singbox-rust  # systemd
docker ps | grep singbox-rust          # Docker
kubectl get pods -l app=singbox-rust   # K8s

# 2. Check if port is listening
sudo netstat -tulpn | grep singbox-rust
sudo lsof -i -P -n | grep singbox-rust

# 3. Test local connectivity
curl -v --socks5 localhost:1080 https://google.com  # Shadowsocks
openssl s_client -connect localhost:443             # Trojan TLS

# 4. Check firewall
sudo iptables -L -n -v | grep <PORT>
sudo firewall-cmd --list-all  # CentOS/RHEL
```

**Solutions**:

1. **Firewall Blocking**
   ```bash
   # Allow port in firewall
   sudo iptables -A INPUT -p tcp --dport 443 -j ACCEPT
   sudo firewall-cmd --add-port=443/tcp --permanent  # CentOS/RHEL
   sudo ufw allow 443/tcp  # Ubuntu
   ```

2. **Wrong Listen Address**
   ```json
   // Change in config.json
   {
     "inbounds": [{
       "listen": "0.0.0.0",  // Not "127.0.0.1"
       "port": 1080
     }]
   }
   ```

3. **Rate Limiting**
   ```bash
   # Check if client IP is rate-limited
   sudo journalctl -u singbox-rust | grep "rate.limit"
   
   # Temporarily disable rate limiting to test
   export SB_INBOUND_RATE_LIMIT_PER_IP=10000
   sudo systemctl restart singbox-rust
   ```

### Connection Drops / Unstable

**Symptom**: Connections frequently disconnect

**Diagnosis**:
```bash
# Monitor active connections
watch -n 1 'netstat -an | grep :1080 | wc -l'

# Check for errors in logs
sudo journalctl -u singbox-rust -f | grep -i "error\|timeout\|close"

# Check system resources
top
free -h
df -h
```

**Common Causes**:

1. **Resource Exhaustion**
   - CPU at 100% → Scale up or optimize
   - Memory full → Increase limits or reduce connections
   - File descriptors exhausted → Increase ulimit

2. **Network Issues**
   ```bash
   # Check packet loss
   ping -c 100 <server-ip>
   
   # Check network interface errors
   ip -s link show
   ```

3. **Timeout Too Low**
   ```json
   {
     "inbounds": [{
       "connect_timeout_sec": 30  // Increase from default
     }]
   }
   ```

---

## Performance Issues

### Slow Throughput

**Symptom**: Transfer speeds below expected

**Diagnosis**:
```bash
# 1. Test baseline network speed
iperf3 -s  # On server
iperf3 -c <server-ip>  # On client

# 2. Check CPU usage
top -bn1 | grep singbox-rust

# 3. Profile with perf (Linux)
sudo perf record -g -p $(pgrep singbox-rust)
sudo perf report

# 4. Check encryption overhead
# Compare speeds with different ciphers
```

**Solutions**:

1. **Use Faster Cipher**
   ```json
   {
     "inbounds": [{
       "method": "chacha20-poly1305"  // ~1.5x faster than AES-256-GCM
     }]
   }
   ```

2. **Increase Worker Threads**
   ```bash
   # Set environment variable
   export TOKIO_WORKER_THREADS=4
   ```

3. **Optimize Kernel Parameters**
   ```bash
   # Add to /etc/sysctl.conf
   net.core.rmem_max = 134217728
   net.core.wmem_max = 134217728
   net.ipv4.tcp_rmem = 4096 87380 67108864
   net.ipv4.tcp_wmem = 4096 65536 67108864
   
   sudo sysctl -p
   ```

### High CPU Usage

**Symptom**: CPU constantly above 80%

**Diagnosis**:
```bash
# Check CPU usage per thread
top -H -p $(pgrep singbox-rust)

# Profile CPU hotspots
sudo perf top -p $(pgrep singbox-rust)
```

**Solutions**:

1. **Scale Horizontally**
   ```bash
   # Kubernetes
   kubectl scale deployment singbox-rust --replicas=3
   
   # Docker - run multiple instances with load balancer
   ```

2. **Reduce Logging**
   ```bash
   export SB_LOG_LEVEL=warn  # From info/debug
   ```

3. **Optimize Rate Limiting**
   ```bash
   # If tracking too many IPs, reduce window
   export SB_INBOUND_RATE_LIMIT_WINDOW_SEC=5  # From 60
   ```

---

## Rate Limiting Issues

### Legitimate Users Blocked

**Symptom**: Valid clients get rate-limited

**Diagnosis**:
```bash
# Check rate limiting metrics
curl localhost:9090/metrics | grep rate_limited_total

# View rate limiting logs
sudo journalctl -u singbox-rust | grep "rate.limit" | tail -50
```

**Solutions**:

1. **Increase Limits**
   ```bash
   export SB_INBOUND_RATE_LIMIT_PER_IP=200  # From 100
   export SB_INBOUND_RATE_LIMIT_WINDOW_SEC=30  # From 10
   sudo systemctl restart singbox-rust
   ```

2. **Whitelist Specific IPs** (Future Feature)
   ```json
   {
     "rate_limiting": {
       "whitelist": ["192.168.1.0/24"]
     }
   }
   ```

3. **Disable Temporarily**
   ```bash
   unset SB_INBOUND_RATE_LIMIT_PER_IP
   sudo systemctl restart singbox-rust
   ```

### Rate Limiting Not Working

**Symptom**: No connections being rate-limited during attack

**Diagnosis**:
```bash
# Check if env vars are set
env | grep SB_INBOUND

# Check metrics
curl localhost:9090/metrics | grep rate_limited_total

# Verify config
sudo journalctl -u singbox-rust | grep -i "rate.limit.config"
```

**Solution**:
```bash
# Ensure env vars are set
export SB_INBOUND_RATE_LIMIT_PER_IP=100
export SB_INBOUND_RATE_LIMIT_WINDOW_SEC=10

# Restart service
sudo systemctl restart singbox-rust

# Verify it's working
curl localhost:9090/metrics | grep rate_limited_total
```

---

## TLS/Certificate Errors

### Certificate Verification Failed

**Symptom**: Clients reject server certificate

**Diagnosis**:
```bash
# Test certificate
openssl s_client -connect localhost:443 -servername example.com

# Check certificate details
openssl x509 -in /etc/singbox/cert.pem -text -noout

# Check certificate expiry
openssl x509 -in /etc/singbox/cert.pem -noout -dates
```

**Common Issues**:

1. **Expired Certificate**
   ```bash
   # Renew with Let's Encrypt
   sudo certbot renew
   sudo systemctl reload singbox-rust
   ```

2. **Wrong SNI**
   ```json
   {
     "inbounds": [{
       "tls": {
         "sni": "correct-domain.com"  // Must match certificate
       }
     }]
   }
   ```

3. **Self-Signed Certificate**
   ```bash
   # Client must skip verification (NOT recommended for production)
   # OR: Add CA cert to client's trust store
   ```

### TLS Handshake Failures

**Symptom**: "TLS handshake failed" errors

**Diagnosis**:
```bash
# Check TLS versions
openssl s_client -connect localhost:443 -tls1_2
openssl s_client -connect localhost:443 -tls1_3

# Enable debug logging
export SB_LOG_LEVEL=debug
sudo systemctl restart singbox-rust
```

**Solutions**:

1. **Cipher Mismatch**
   ```json
   {
     "tls": {
       "cipher_suites": [
         "TLS_AES_256_GCM_SHA384",
         "TLS_CHACHA20_POLY1305_SHA256"
       ]
     }
   }
   ```

2. **ALPN Mismatch**
   ```json
   {
     "tls": {
       "alpn": ["h2", "http/1.1"]  // Ensure client supports these
     }
   }
   ```

---

## Resource Exhaustion

### Out of Memory (OOM)

**Symptom**: Process killed by OOM killer

**Diagnosis**:
```bash
# Check OOM killer logs
sudo dmesg | grep -i "out of memory"
sudo journalctl -k | grep -i "killed process"

# Monitor memory usage
watch -n 1 'free -h'
ps aux | grep singbox-rust
```

**Solutions**:

1. **Increase Memory Limit**
   ```bash
   # Docker
   docker update --memory=1g singbox-rust
   
   # systemd (add to service file)
   MemoryLimit=1G
   
   # Kubernetes (update deployment)
   resources:
     limits:
       memory: 1Gi
   ```

2. **Reduce Connection Limit**
   ```bash
   export SB_INBOUND_RATE_LIMIT_PER_IP=50  # Reduce max connections
   ```

3. **Memory Leak Investigation**
   ```bash
   # Long-running memory profile
   valgrind --leak-check=full --log-file=valgrind.log \
     singbox-rust run --config /etc/singbox/config.json
   ```

### File Descriptor Exhaustion

**Symptom**: "Too many open files" error

**Diagnosis**:
```bash
# Check current limits
ulimit -n

# Check usage
lsof -p $(pgrep singbox-rust) | wc -l

# Check system limit
cat /proc/sys/fs/file-max
```

**Solutions**:

1. **Increase Limits**
   ```bash
   # Temporary
   ulimit -n 65536
   
   # Permanent - add to /etc/security/limits.conf
   singbox soft nofile 65536
   singbox hard nofile 65536
   
   # systemd - in service file
   LimitNOFILE=1048576
   ```

2. **Check for Leaks**
   ```bash
   # Monitor FD count over time
   watch -n 5 'lsof -p $(pgrep singbox-rust) | wc -l'
   ```

---

## Logging & Debugging

### Enable Debug Logging

```bash
# Set log level
export SB_LOG_LEVEL=debug  # or trace for very verbose

# Enable structured JSON logging
export SB_LOG_FORMAT=json

# Restart service
sudo systemctl restart singbox-rust

# View logs
sudo journalctl -u singbox-rust -f
```

### Log Analysis

```bash
# Count errors in last hour
sudo journalctl -u singbox-rust --since "1 hour ago" | grep -c ERROR

# Find slow connections
sudo journalctl -u singbox-rust | grep "latency" | sort -k8 -n

# Find rate-limited IPs
sudo journalctl -u singbox-rust | grep "rate_limit" | \
  awk '{print $NF}' | sort | uniq -c | sort -rn
```

---

## Emergency Procedures

### Service Down - Quick Recovery

```bash
# 1. Emergency restart
sudo systemctl restart singbox-rust

# 2. If that fails, force kill and restart
sudo pkill -9 singbox-rust
sudo systemctl start singbox-rust

# 3. Failover (if available)
# Switch DNS to backup server
# Or manually route traffic
```

### Under Attack

```bash
# 1. Enable aggressive rate limiting
export SB_INBOUND_RATE_LIMIT_PER_IP=10
export SB_INBOUND_RATE_LIMIT_WINDOW_SEC=60
sudo systemctl restart singbox-rust

# 2. Block attacking IPs (if identified)
sudo iptables -A INPUT -s <ATTACKER_IP> -j DROP

# 3. Monitor
watch -n 1 'netstat -an | grep :1080 | wc -l'
curl localhost:9090/metrics | grep rate_limited_total
```

### Data Recovery

```bash
# Restore from backup
sudo systemctl stop singbox-rust
sudo tar -xzf /backups/singbox-backup-latest.tar.gz -C /
sudo systemctl start singbox-rust
```

---

## Contact & Escalation

**For Critical Issues**:
1. Check GitHub discussions: https://github.com/Freedom18946/singbox-rust/discussions
2. File bug report: https://github.com/Freedom18946/singbox-rust/issues
3. Security issues: security@example.com

**Log Collection for Bug Reports**:
```bash
# Collect diagnostic info
tar -czf singbox-debug-$(date +%Y%m%d-%H%M%S).tar.gz \
  <(systemctl status singbox-rust) \
  <(journalctl -u singbox-rust -n 500) \
  /etc/singbox/config.json \
  <(curl -s localhost:9090/metrics)
```

---

**Document Version**: 1.0.0  
**Last Updated**: 2025-11-27
