# API Reference

Complete API documentation for singbox-rust.

---

## Available APIs

singbox-rust provides multiple API interfaces:

### [Admin HTTP API](admin-api/)

HTTP API for runtime management and diagnostics.

- **Purpose**: Control and monitor running instance
- **Protocol**: HTTP/HTTPS
- **Default**: `http://127.0.0.1:18088`
- **Authentication**: Optional bearer token, HMAC, or mTLS
- **Use Cases**: Health checks, config fetch/update, metrics, routing tools

**Quick start**:

```bash
# Enable admin API
export SB_ADMIN_ENABLE=1
singbox-rust run -c config.yaml

# Check health
curl http://127.0.0.1:18088/__health
```

See [Admin API Documentation](admin-api/overview.md).

### [V2Ray Stats gRPC API](v2ray-stats/)

gRPC API compatible with V2Ray StatsService.

- **Purpose**: Query traffic statistics
- **Protocol**: gRPC
- **Compatibility**: V2Ray clients and tools
- **Use Cases**: Traffic monitoring, integration with V2Ray ecosystem

See [V2Ray Stats API](v2ray-stats/overview.md).

### [Internal APIs](internal/) (Developers)

Internal Rust APIs for protocol and router implementation.

- **Purpose**: Protocol adapter development
- **Audience**: Contributors and plugin developers
- **Documentation**: API docs and trait definitions

See [Internal API Reference](internal/).

---

## Quick Links

### Common Tasks

**Enable Admin API**:

```bash
SB_ADMIN_ENABLE=1 SB_ADMIN_LISTEN=127.0.0.1:18088 singbox-rust run -c config.yaml
```

**Check Service Health**:

```bash
curl http://127.0.0.1:18088/__health
```

**Get Prometheus Metrics**:

```bash
curl http://127.0.0.1:18088/__metrics
```

**Fetch Admin Debug Config**:

```bash
curl http://127.0.0.1:18088/__config
```

**Update Admin Debug Config**:

```bash
curl -X PUT http://127.0.0.1:18088/__config \
  -H "Content-Type: application/json" \
  -H "X-Role: admin" \
  -d '{"rps": 100}'
```

---

## Authentication

### Bearer Token Authentication

Set a token via environment variable:

```bash
export SB_ADMIN_TOKEN=your-secret-token
```

**Make authenticated request**:

```bash
curl http://127.0.0.1:18088/__health \
  -H "Authorization: Bearer your-secret-token"
```

See [Authentication Guide](admin-api/authentication.md).

### mTLS (Mutual TLS)

Use client certificates for authentication:

```yaml
admin:
  listen: 0.0.0.0:18088
  tls:
    enabled: true
    cert: /path/to/server.crt
    key: /path/to/server.key
    client_ca: /path/to/client-ca.crt # Require client cert
```

**Make request with client cert**:

```bash
curl https://0.0.0.0:18088/__health \
  --cert client.crt \
  --key client.key \
  --cacert server-ca.crt
```

### HMAC Signature

Sign requests with HMAC-SHA256:

```yaml
admin:
  listen: 127.0.0.1:18088
  hmac:
    enabled: true
    secret: ${HMAC_SECRET}
```

**Calculate signature**:

```python
import hmac
import hashlib
import time

secret = b"your-secret"
timestamp = str(int(time.time()))
path = "/__health"
message = (timestamp + path).encode()
signature = hmac.new(secret, message, hashlib.sha256).hexdigest()
auth_header = f"SB-HMAC admin:{timestamp}:{signature}"
```

**Make request**:

```bash
curl http://127.0.0.1:18088/__health \
  -H "Authorization: $auth_header"
```

---

## Response Format

All API responses follow a unified envelope format:

### Success Response

```json
{
  "ok": true,
  "data": {
    "key": "value"
  },
  "requestId": "req-1234567890-001"
}
```

### Error Response

```json
{
  "ok": false,
  "error": {
    "kind": "NotFound",
    "msg": "Outbound 'proxy-jp' not found",
    "ptr": "/outbound",
    "hint": "Check available outbounds in your configuration"
  },
  "requestId": "req-1234567890-002"
}
```

**Error kinds**:

- `NotFound` - Resource not found
- `Conflict` - Resource conflict (duplicate)
- `State` - Invalid state transition
- `Auth` - Authentication/authorization failure
- `RateLimit` - Rate limit exceeded
- `Io` - I/O error
- `Decode` - Parsing/decoding error
- `Timeout` - Operation timeout
- `Internal` - Internal server error

See [Response Contract](admin-api/overview.md#response-format).

---

## Rate Limiting

Configure rate limits to prevent abuse:

```yaml
admin:
  listen: 0.0.0.0:18088
  rate_limit:
    enabled: true
    qps: 100 # Queries per second
    burst: 200 # Burst capacity
```

**Rate limit headers**:

```http
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1234567890
```

**Rate limit exceeded response**:

```json
{
  "ok": false,
  "error": {
    "kind": "RateLimit",
    "msg": "Rate limit exceeded: 100 req/s",
    "hint": "Retry after 1 second"
  }
}
```

---

## CORS Configuration

Enable CORS for browser-based clients:

```yaml
admin:
  listen: 0.0.0.0:18088
  cors:
    enabled: true
    origins: ["https://dashboard.example.com"]
    methods: ["GET", "POST", "PUT", "DELETE"]
    headers: ["Content-Type", "Authorization"]
    max_age: 3600
```

---

## API Versioning

Current API version: **v1**

**Version header**:

```http
X-API-Version: v1
```

**Breaking changes** will result in a new major version (v2). Non-breaking additions may be made to v1.

---

## SDK and Libraries

### Official

- **Rust**: Built-in via `sb-admin-contract` crate
- **Go**: (Planned)
- **Python**: (Planned)

### Community

- Check [GitHub Discussions](https://github.com/your-repo/discussions) for community SDKs

### HTTP Client Examples

**curl**:

```bash
curl http://127.0.0.1:18088/__health
```

**Python**:

```python
import requests

response = requests.get("http://127.0.0.1:18088/__health")
print(response.json())
```

**JavaScript**:

```javascript
fetch("http://127.0.0.1:18088/__health")
  .then((r) => r.json())
  .then((data) => console.log(data));
```

---

## Related Documentation

- **[Admin API Overview](admin-api/overview.md)** - Complete HTTP API reference
- **[Authentication Guide](admin-api/authentication.md)** - Bearer token, mTLS, HMAC setup
- **[V2Ray Stats API](v2ray-stats/overview.md)** - gRPC stats service
- **[Internal APIs](internal/)** - Developer API reference
- **[Security Best Practices](../03-operations/security/hardening.md)** - Securing APIs

---

## Support

- **Documentation Issues**: [File a docs bug](https://github.com/your-repo/issues/new?labels=documentation)
- **API Questions**: [Ask in Discussions](https://github.com/your-repo/discussions)
- **Feature Requests**: [Request new API features](https://github.com/your-repo/issues/new?labels=enhancement)
