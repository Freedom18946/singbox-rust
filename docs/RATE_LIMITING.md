# Rate Limiting Configuration Guide

## Overview

singbox-rust implements comprehensive rate limiting across TCP and UDP protocols with per-IP connection limits, authentication failure tracking, and QPS (queries per second) controls.

## TCP Rate Limiting

### Environment Variables

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `SB_INBOUND_RATE_LIMIT_PER_IP` | integer | 100 | Maximum concurrent connections allowed per IP address |
| `SB_INBOUND_RATE_LIMIT_WINDOW_SEC` | integer | 10 | Time window in seconds for tracking connections |
| `SB_INBOUND_RATE_LIMIT_QPS` | integer | (none) | Optional queries-per-second limit per IP (token bucket) |

### Configuration Examples

**Basic DoS Protection:**
```bash
export SB_INBOUND_RATE_LIMIT_PER_IP=100
export SB_INBOUND_RATE_LIMIT_WINDOW_SEC=10
```

**Strict Rate Limiting:**
```bash
export SB_INBOUND_RATE_LIMIT_PER_IP=20
export SB_INBOUND_RATE_LIMIT_WINDOW_SEC=5
export SB_INBOUND_RATE_LIMIT_QPS=50
```

**High-Traffic Production:**
```bash
export SB_INBOUND_RATE_LIMIT_PER_IP=500
export SB_INBOUND_RATE_LIMIT_WINDOW_SEC=60
export SB_INBOUND_RATE_LIMIT_QPS=1000
```

## UDP Rate Limiting

### Environment Variables

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `SB_UDP_OUTBOUND_BPS_MAX` | integer | 0 (disabled) | Maximum bytes per second for UDP outbound traffic |
| `SB_UDP_OUTBOUND_PPS_MAX` | integer | 0 (disabled) | Maximum packets per second for UDP outbound traffic |

### Configuration Examples

**Bandwidth Limit (10 MB/s):**
```bash
export SB_UDP_OUTBOUND_BPS_MAX=10485760
```

**Packet Rate Limit (10k packets/sec):**
```bash
export SB_UDP_OUTBOUND_PPS_MAX=10000
```

**Combined Limits:**
```bash
export SB_UDP_OUTBOUND_BPS_MAX=52428800  # 50 MB/s
export SB_UDP_OUTBOUND_PPS_MAX=50000     # 50k packets/sec
```

## Admin API Rate Limiting

### Environment Variables

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `SB_ADMIN_RATE_LIMIT_ENABLED` | boolean | 0 | Enable rate limiting for admin API endpoints (set to "1") |
| `SB_ADMIN_RATE_LIMIT_MAX` | integer | 60 | Maximum requests per window |
| `SB_ADMIN_RATE_LIMIT_WINDOW_SEC` | integer | 60 | Time window in seconds |
| `SB_ADMIN_RATE_LIMIT_STRATEGY` | string | path | Strategy: "path", "endpoint", or "global" |
| `SB_ADMIN_RATE_LIMIT_BURST` | integer | (max) | Burst capacity for token bucket |

### Configuration Examples

**Enable Admin API Rate Limiting:**
```bash
export SB_ADMIN_RATE_LIMIT_ENABLED=1
export SB_ADMIN_RATE_LIMIT_MAX=100
export SB_ADMIN_RATE_LIMIT_WINDOW_SEC=60
export SB_ADMIN_RATE_LIMIT_STRATEGY=endpoint
```

## Authentication Failure Tracking

The TCP rate limiter automatically tracks authentication failures with hardcoded defaults:
- **Max auth failures**: 10 failures per IP
- **Failure window**: 60 seconds
- **Action**: Temporary IP ban after exceeding limit

This is built into `TcpRateLimiter` and does not require configuration.

## Metrics

Rate limiting events are instrumented via Prometheus metrics:

```
# TCP Rate Limiting
sb_subs_rate_limited_total         # Total rate-limited requests (admin API)
RATE_LIMITED_TOTAL{protocol, reason}  # Per-protocol rate limiting events

# Example queries
rate_limited_total{protocol="trojan", reason="connection_limit"}
rate_limited_total{protocol="shadowsocks", reason="connection_limit"}
```

## Verification

### Test Unit Tests
```bash
cargo test tcp_rate_limit --package sb-core --lib
```

**Expected output:**
```
test result: ok. 5 passed; 0 failed; 0 ignored
```

### Test Integration
```bash
cargo test --test rate_limit_integration_test --features net_e2e
```

### Monitor Metrics
```bash
curl http://localhost:9090/metrics | grep -i rate_limit
```

## Threat Model Mappings

### Low Security (Public Proxies)
- High connection limits to support many users
- Moderate QPS to prevent individual abuse

```bash
SB_INBOUND_RATE_LIMIT_PER_IP=1000
SB_INBOUND_RATE_LIMIT_WINDOW_SEC=60
SB_INBOUND_RATE_LIMIT_QPS=5000
```

### Medium Security (Private VPN)
- Balanced limits for known user base

```bash
SB_INBOUND_RATE_LIMIT_PER_IP=100
SB_INBOUND_RATE_LIMIT_WINDOW_SEC=10
SB_INBOUND_RATE_LIMIT_QPS=500
```

### High Security (Enterprise)
- Strict limits with monitoring

```bash
SB_INBOUND_RATE_LIMIT_PER_IP=20
SB_INBOUND_RATE_LIMIT_WINDOW_SEC=5
SB_INBOUND_RATE_LIMIT_QPS=100
SB_ADMIN_RATE_LIMIT_ENABLED=1
```

## Troubleshooting

**Issue**: Legitimate users getting rate limited

**Solution**: Increase `SB_INBOUND_RATE_LIMIT_PER_IP` or `WINDOW_SEC`

**Issue**: High memory usage

**Solution**: Rate limiter uses LRU cache (max 10,000 IPs tracked). Memory usage should plateau around ~50MB. If higher, investigate IP churn rate.

**Issue**: Rate limiting not working

**Solution**: Verify environment variables are set before server startup:
```bash
env | grep SB_INBOUND_RATE_LIMIT
```

## References

- Implementation: [`tcp_rate_limit.rs`](../crates/sb-core/src/net/tcp_rate_limit.rs)
- UDP Limiter: [`rate_limit.rs`](../crates/sb-core/src/net/rate_limit.rs)
- Admin Middleware: [`middleware/rate_limit.rs`](../app/src/admin_debug/middleware/rate_limit.rs)
- Integration Tests: [`rate_limit_integration_test.rs`](../app/tests/rate_limit_integration_test.rs)
