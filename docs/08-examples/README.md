# Configuration Examples

Ready-to-use configuration examples for common use cases.

---

## Quick Index

### Basic Examples

- **[SOCKS5 Proxy](basic/socks5-proxy.md)** - Simple SOCKS5 local proxy
- **[HTTP Proxy](basic/http-proxy.md)** - HTTP CONNECT proxy
- **[Mixed Proxy](basic/mixed-proxy.md)** - SOCKS5 + HTTP combined
- **[TUN Mode](basic/tun-mode.md)** - System-wide transparent proxy

### Advanced Examples

- **[REALITY Server](advanced/reality-server.md)** - Anti-censorship VLESS+REALITY
- **[Hysteria2 Client](advanced/hysteria2-client.md)** - High-performance QUIC proxy
- **[TUIC UDP over Stream](advanced/tuic-udp.md)** - TUIC UDP relay with QUIC streams
- **[Load Balancing](advanced/load-balancing.md)** - Multiple proxies with failover
- **[Smart Routing](advanced/smart-routing.md)** - Route by domain, IP, process

### Transport Examples

- **[V2Ray Transports](transport/)** - WebSocket, HTTP/2, gRPC configurations
- **[Multiplex](transport/multiplex.md)** - Connection multiplexing with yamux
- **[Fallback (WS↔H2)](transport/fallback.md)** - Enable automatic fallback between WebSocket and HTTP/2

### DNS Examples

- **[DNS Pool](dns/)** - Multiple DNS resolvers with race strategy
- **[FakeIP](dns/fakeip.md)** - Virtual IPs for routing optimization

---

## Basic Examples

### 1. Simple SOCKS5 Proxy

**Use case**: Local SOCKS5 proxy for development or testing

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

route:
  default: direct
```

**Usage**:

```bash
curl -x socks5h://127.0.0.1:1080 https://ifconfig.me
```

[Full Example →](basic/socks5-proxy.md)

### 2. Mixed Proxy (SOCKS5 + HTTP)

**Use case**: Single port for both SOCKS5 and HTTP clients

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
    password: ${SS_PASSWORD}

route:
  default: proxy
```

**Usage**:

```bash
# SOCKS5
curl -x socks5h://127.0.0.1:7890 https://google.com

# HTTP
curl -x http://127.0.0.1:7890 https://google.com
```

[Full Example →](basic/mixed-proxy.md)

### 3. TUN Mode (System-wide)

**Use case**: Route all system traffic through proxy

```yaml
schema_version: 2

inbounds:
  - type: tun
    tag: tun-in
    address: [172.19.0.1/30]
    mtu: 1500
    auto_route: true
    stack: system

outbounds:
  - type: shadowsocks
    tag: proxy
    server: proxy.example.com
    port: 8388
    method: aes-256-gcm
    password: ${SS_PASSWORD}

route:
  default: proxy
```

**Linux setup**:

```bash
# Grant capability
sudo setcap cap_net_admin+ep $(which singbox-rust)

# Run
singbox-rust run -c config.yaml
```

[Full Example →](basic/tun-mode.md)

---

## Advanced Examples

### 1. REALITY Server (Anti-Censorship)

**Use case**: Undetectable proxy server using REALITY

```yaml
schema_version: 2

inbounds:
  - type: vless
    tag: vless-reality
    listen: 0.0.0.0
    port: 443
    users:
      - uuid: 550e8400-e29b-41d4-a716-446655440000
        name: user1
    tls:
      enabled: true
      reality:
        enabled: true
        private_key: "your-64-char-hex-private-key"
        short_ids:
          - "0123456789abcdef"
          - "fedcba9876543210"
        fallback_server: "www.microsoft.com"
        fallback_port: 443
      sni: www.microsoft.com

outbounds:
  - type: direct
    tag: direct

route:
  default: direct
```

**Client config**:

```yaml
schema_version: 2

inbounds:
  - type: socks
    tag: socks-in
    listen: 127.0.0.1
    port: 1080

outbounds:
  - type: vless
    tag: reality-out
    server: your-server-ip
    port: 443
    uuid: 550e8400-e29b-41d4-a716-446655440000
    tls:
      enabled: true
      reality:
        enabled: true
        public_key: "your-64-char-hex-public-key"
        short_id: "0123456789abcdef"
      sni: www.microsoft.com

route:
  default: reality-out
```

[Full Example →](advanced/reality-server.md)

### 2. Load Balancing with Failover

**Use case**: Multiple proxies with automatic selection

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

  # Individual proxies
  - type: shadowsocks
    tag: proxy-us-1
    server: us1.example.com
    port: 8388
    method: aes-256-gcm
    password: password1

  - type: shadowsocks
    tag: proxy-us-2
    server: us2.example.com
    port: 8388
    method: aes-256-gcm
    password: password2

  - type: shadowsocks
    tag: proxy-jp
    server: jp.example.com
    port: 8388
    method: aes-256-gcm
    password: password3

  # Auto selector
  - type: urltest
    tag: auto-select
    outbounds: [proxy-us-1, proxy-us-2, proxy-jp]
    url: https://www.google.com/generate_204
    interval: 300s
    tolerance: 50ms

route:
  default: auto-select
```

**Manual selector alternative**:

```yaml
outbounds:
  - type: selector
    tag: manual-select
    outbounds: [proxy-us-1, proxy-us-2, proxy-jp]
    default: proxy-us-1
```

**Switch selection**:

Edit the selector `default` and reload the config (or restart the service).

[Full Example →](advanced/load-balancing.md)

### 3. Smart Routing (China Direct)

**Use case**: Route China traffic direct, others through proxy

```yaml
schema_version: 2

inbounds:
  - type: mixed
    tag: mixed-in
    listen: 127.0.0.1
    port: 7890

outbounds:
  - type: direct
    tag: direct
  - type: block
    tag: block
  - type: shadowsocks
    tag: proxy
    server: proxy.example.com
    port: 8388
    method: aes-256-gcm
    password: ${SS_PASSWORD}

route:
  rules:
    # Block ads
    - domain_suffix:
        - doubleclick.net
        - googlesyndication.com
        - googleadservices.com
      outbound: block

    # China direct
    - geoip: cn
      outbound: direct
    - geosite: cn
      outbound: direct
    - domain_suffix: [cn]
      outbound: direct

    # Private networks direct
    - ip_cidr:
        - 10.0.0.0/8
        - 172.16.0.0/12
        - 192.168.0.0/16
      outbound: direct

  # Everything else through proxy
  default: proxy
```

[Full Example →](advanced/smart-routing.md)

---

## Transport Examples

### VMess with TLS + WebSocket

```yaml
outbounds:
  - type: vmess
    tag: vmess-tls-ws
    server: vmess.example.com
    port: 443
    uuid: 550e8400-e29b-41d4-a716-446655440000

    tls:
      enabled: true
      sni: vmess.example.com
      alpn: [http/1.1]

    transport:
      type: ws
      path: /vmess
      headers:
        Host: vmess.example.com
```

### Trojan with HTTP/2 Transport

```yaml
outbounds:
  - type: trojan
    tag: trojan-h2
    server: trojan.example.com
    port: 443
    password: your-password

    tls:
      enabled: true
      sni: trojan.example.com
      alpn: [h2]

    transport:
      type: h2
      path: /trojan
```

### VLESS with gRPC

```yaml
outbounds:
  - type: vless
    tag: vless-grpc
    server: vless.example.com
    port: 443
    uuid: 550e8400-e29b-41d4-a716-446655440000

    tls:
      enabled: true
      sni: vless.example.com
      alpn: [h2]

    transport:
      type: grpc
      service_name: VlessService
```

[More Transport Examples →](transport/)

---

## DNS Examples

### DNS with FakeIP

```yaml
dns:
  servers:
    - address: https://1.1.1.1/dns-query
      tag: cloudflare

  fakeip:
    enabled: true
    inet4_range: 198.18.0.0/15
    inet6_range: fc00::/18
```

### DNS Pool with Race Strategy

```yaml
dns:
  servers:
    - address: system
      tag: system

    - address: udp://8.8.8.8:53
      tag: google

    - address: https://1.1.1.1/dns-query
      tag: cloudflare

    - address: tls://1.1.1.1:853
      tag: cloudflare-dot

    - address: quic://dns.adguard.com:853
      tag: adguard

  strategy: race # Query all, use fastest response
  default_server: cloudflare
```

[More DNS Examples →](dns/)

---

## Process-Based Routing

**Use case**: Route specific applications through proxy

```yaml
route:
  rules:
    # Browsers through proxy
    - process_name:
        - chrome
        - firefox
        - safari
        - msedge
      outbound: proxy

    # Development tools direct
    - process_name:
        - git
        - npm
        - cargo
        - go
      outbound: direct

    # Terminal direct
    - process_name:
        - Terminal
        - iTerm2
        - alacritty
      outbound: direct

  default: direct
```

**Note**: Requires appropriate permissions (macOS/Windows native APIs are 149x faster!)

---

## Example Files

All examples are available in the repository:

```
examples/
├── configs/
│   ├── basic-socks5.yaml
│   ├── mixed-proxy.yaml
│   ├── tun-mode.yaml
│   ├── reality-server.yaml
│   ├── reality-client.yaml
│   ├── load-balancing.yaml
│   └── smart-routing.yaml
├── dns_pool.md
└── v2ray_transport_config.json
```

**Run an example**:

```bash
# Validate
singbox-rust check -c examples/configs/basic-socks5.yaml

# Run
singbox-rust run -c examples/configs/basic-socks5.yaml
```

---

## Testing Your Configuration

### 1. Validate Syntax

```bash
singbox-rust check -c config.yaml
```

### 2. Test Routing

```bash
singbox-rust route -c config.yaml --dest google.com:443 --explain
```

### 3. Test Connection

```bash
# Start proxy
singbox-rust run -c config.yaml &

# Test connection
curl -x socks5h://127.0.0.1:1080 https://ifconfig.me

# Should show proxy server IP
```

### 4. Check Metrics

```bash
# If admin API enabled
curl http://127.0.0.1:18088/__metrics | grep sb_connections
```

---

## Environment Variables for Examples

Many examples use environment variables for secrets:

```bash
# Export secrets
export SS_PASSWORD=your-shadowsocks-password
export JWT_SECRET=your-jwt-secret

# Run config
singbox-rust run -c config.yaml
```

**Never commit passwords to version control!**

---

## Contributing Examples

Have a useful configuration? Share it!

1. Create example in `examples/configs/`
2. Add documentation in `docs/08-examples/`
3. Test thoroughly
4. Submit pull request

See [Contributing Guide](../04-development/contributing/getting-started.md).

---

## Related Documentation

- **[Getting Started](../00-getting-started/)** - Quick start guide
- **[User Guide](../01-user-guide/)** - Configuration reference
- **[Advanced Topics](../06-advanced-topics/)** - Deep dives
- **[Troubleshooting](../01-user-guide/troubleshooting.md)** - Common issues
