# Basic Configuration Guide

Learn the fundamentals of singbox-rust configuration files.

---

## Configuration File Format

singbox-rust supports **JSON** and **YAML** formats. We recommend YAML for human readability.

**Example: `config.yaml`**

```yaml
schema_version: 2 # Required: Config schema version

log:
  level: info # Optional: debug, info, warn, error

inbounds: # Required: Array of inbound listeners
  - type: socks
    tag: socks-in
    listen: 127.0.0.1
    port: 1080

outbounds: # Required: Array of outbound connectors
  - type: direct
    tag: direct-out

route: # Required: Routing configuration
  rules: []
  default: direct-out # Default outbound for unmatched traffic
```

---

## Core Sections

### 1. Schema Version

Always start with schema version:

```yaml
schema_version: 2
```

**Why**: Ensures forward compatibility. Version 2 is the current stable schema.

**Migration**: If you have a V1 (Go sing-box) config:

```bash
singbox-rust check -c old-config.json --migrate --write-normalized --out new-config.yaml
```

### 2. Logging

Control log output:

```yaml
log:
  level: info # debug | info | warn | error
  output: stdout # stdout | file path
  timestamp: true # Include timestamps
```

**Environment variable override**:

```bash
RUST_LOG=debug singbox-rust run -c config.yaml
```

### 3. Inbounds

Define local listeners that accept incoming connections:

```yaml
inbounds:
  # SOCKS5 proxy
  - type: socks
    tag: socks-in # Unique identifier
    listen: 127.0.0.1 # Listen address (0.0.0.0 for all interfaces)
    port: 1080 # Listen port

  # HTTP proxy
  - type: http
    tag: http-in
    listen: 127.0.0.1
    port: 8080

  # Mixed (SOCKS5 + HTTP on same port)
  - type: mixed
    tag: mixed-in
    listen: 127.0.0.1
    port: 7890
```

**Common inbound types**:

- `socks` - SOCKS5 proxy (most common)
- `http` - HTTP CONNECT proxy
- `mixed` - SOCKS5 + HTTP combined
- `tun` - System-wide transparent proxy
- `direct` - TCP/UDP forwarder
- `shadowsocks`, `vmess`, `vless`, `trojan` - Protocol servers

See [Inbound Configuration](../01-user-guide/configuration/inbounds.md) for all types.

### 4. Outbounds

Define how to connect to targets:

```yaml
outbounds:
  # Direct connection (no proxy)
  - type: direct
    tag: direct-out

  # Block connection
  - type: block
    tag: block-out

  # Upstream proxy
  - type: shadowsocks
    tag: ss-out
    server: proxy.example.com
    port: 8388
    method: aes-256-gcm
    password: your-password
```

**Common outbound types**:

- `direct` - Connect directly to target
- `block` - Block/reject connection
- `shadowsocks`, `vmess`, `vless`, `trojan` - Proxy protocols
- `selector` - Manual outbound selection
- `urltest` - Automatic selection based on health checks

See [Outbound Configuration](../01-user-guide/configuration/outbounds.md) for all types.

### 5. Routing

Control traffic flow based on rules:

```yaml
route:
  rules:
    # Block ads
    - domain_suffix: [doubleclick.net, googlesyndication.com]
      outbound: block-out

    # Direct connection for local domains
    - domain_suffix: [local]
      outbound: direct-out

    # Proxy international traffic
    - domain_suffix: [google.com, youtube.com]
      outbound: proxy-out

  # Default for unmatched traffic
  default: direct-out
```

**Rule matching fields**:

- `domain` - Exact domain match
- `domain_suffix` - Domain suffix (e.g., `.com`)
- `domain_keyword` - Domain contains keyword
- `ip_cidr` - IP CIDR block
- `port` - Port number
- `protocol` - `tcp` or `udp`
- `process_name` - Process name (requires permission)
- `inbound` - Source inbound tag

See [Routing Configuration](../01-user-guide/configuration/routing.md) for advanced rules.

### 6. DNS (Optional)

Configure DNS resolution:

```yaml
dns:
  servers:
    # Cloudflare DNS over HTTPS
    - address: https://1.1.1.1/dns-query
      tag: cloudflare

    # System DNS
    - address: system
      tag: system

  # Default DNS server
  default_server: cloudflare

  # FakeIP mode (for TUN)
  fakeip:
    enabled: true
    inet4_range: 198.18.0.0/15
    inet6_range: fc00::/18
```

See [DNS Configuration](../01-user-guide/configuration/dns.md) for details.

---

## Complete Example

Here's a typical client configuration:

```yaml
schema_version: 2

log:
  level: info

# Local SOCKS5 + HTTP proxy
inbounds:
  - type: mixed
    tag: mixed-in
    listen: 127.0.0.1
    port: 7890

# Outbound configurations
outbounds:
  # Direct connection
  - type: direct
    tag: direct

  # Block ads/tracking
  - type: block
    tag: block

  # Upstream Shadowsocks proxy
  - type: shadowsocks
    tag: proxy
    server: proxy.example.com
    port: 8388
    method: aes-256-gcm
    password: your-password

# Routing rules
route:
  rules:
    # Block ads
    - domain_suffix:
        - doubleclick.net
        - googlesyndication.com
        - googleadservices.com
      outbound: block

    # Direct for China domains
    - domain_suffix: [cn]
      outbound: direct

    # Proxy for international domains
    - domain_suffix:
        - google.com
        - youtube.com
        - twitter.com
      outbound: proxy

  # Default: direct connection
  default: direct
```

**Save as `config.yaml` and run**:

```bash
singbox-rust run -c config.yaml
```

**Test with curl**:

```bash
# Test via proxy
curl -x socks5h://127.0.0.1:7890 https://ifconfig.me

# Should show your proxy server's IP
```

---

## Configuration Validation

Always validate before running:

```bash
# Basic validation
singbox-rust check -c config.yaml

# Detailed JSON output
singbox-rust check -c config.yaml --format json

# Check specific outbound
singbox-rust check -c config.yaml --outbound proxy

# Test routing decision
singbox-rust route -c config.yaml --dest google.com:443 --explain
```

**Exit codes**:

- `0` - Valid configuration
- `1` - Warnings (still usable)
- `2` - Errors (cannot run)

See [CLI Exit Codes](../02-cli-reference/exit-codes.md).

---

## Common Patterns

### Pattern 1: Simple SOCKS5 Proxy

```yaml
schema_version: 2
inbounds:
  - type: socks
    tag: socks-in
    listen: 127.0.0.1
    port: 1080
outbounds:
  - type: direct
    tag: direct-out
route:
  default: direct-out
```

### Pattern 2: Proxy Everything

```yaml
schema_version: 2
inbounds:
  - type: mixed
    tag: mixed-in
    listen: 127.0.0.1
    port: 7890
outbounds:
  - type: shadowsocks
    tag: proxy
    server: proxy.example.com
    port: 8388
    method: aes-256-gcm
    password: your-password
route:
  default: proxy
```

### Pattern 3: Smart Routing (Direct + Proxy)

```yaml
schema_version: 2
inbounds:
  - type: socks
    tag: socks-in
    listen: 127.0.0.1
    port: 1080
outbounds:
  - type: direct
    tag: direct
  - type: shadowsocks
    tag: proxy
    server: proxy.example.com
    port: 8388
    method: aes-256-gcm
    password: your-password
route:
  rules:
    # Proxy international sites
    - domain_suffix: [google.com, youtube.com]
      outbound: proxy
  # Direct for everything else
  default: direct
```

---

## Environment Variables

Override configuration via environment:

```bash
# Enable debug logging
RUST_LOG=debug singbox-rust run -c config.yaml

# Print env snapshot at startup
SB_PRINT_ENV=1 singbox-rust run -c config.yaml

# DNS settings
SB_DNS_ENABLE=1 \
SB_DNS_MODE=doh \
singbox-rust run -c config.yaml

# Admin API
SB_ADMIN_ENABLE=1 \
SB_ADMIN_LISTEN=127.0.0.1:18088 \
singbox-rust run -c config.yaml
```

See [Environment Variables](../02-cli-reference/environment-variables.md) for all options.

---

## Configuration Tips

### 1. Use Tags Consistently

Always use descriptive tags:

```yaml
# Good
tag: proxy-us-01

# Bad
tag: out1
```

### 2. Test Incrementally

Start simple, add complexity gradually:

1. Start with direct outbound only
2. Add one proxy outbound
3. Add routing rules one by one
4. Test each addition

### 3. Keep Sensitive Data Secure

**Never commit passwords to git!**

Use environment variables:

```yaml
outbounds:
  - type: shadowsocks
    tag: proxy
    server: proxy.example.com
    port: 8388
    method: aes-256-gcm
    password: ${SS_PASSWORD} # From environment
```

Then:

```bash
export SS_PASSWORD=your-secret-password
singbox-rust run -c config.yaml
```

### 4. Use JSON Schema for Validation

Most editors support JSON Schema validation:

```json
{
  "$schema": "https://your-site/config-v2-schema.json",
  "schema_version": 2,
  ...
}
```

See [Reference Index](../07-reference/README.md) for schema references (detailed pages are planned).

---

## Next Steps

- **[Add Your First Proxy](first-proxy.md)** - Connect to an upstream proxy
- **[User Guide](../01-user-guide/)** - Deep dive into features
- **[Configuration Examples](../08-examples/)** - Ready-to-use configs
- **[Troubleshooting](../TROUBLESHOOTING.md)** - Common issues

---

**Related Documentation**:

- [Configuration Overview](../01-user-guide/configuration/overview.md)
- [Inbound Configuration](../01-user-guide/configuration/inbounds.md)
- [Outbound Configuration](../01-user-guide/configuration/outbounds.md)
- [Routing Configuration](../01-user-guide/configuration/routing.md)
- [DNS Configuration](../01-user-guide/configuration/dns.md)
