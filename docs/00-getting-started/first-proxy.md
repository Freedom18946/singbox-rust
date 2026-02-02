# Adding Your First Proxy

Connect singbox-rust to an upstream proxy server.

---

## Prerequisites

- singbox-rust installed ([Installation Guide](README.md#installation))
- Basic understanding of [configuration files](basic-configuration.md)
- An upstream proxy server (Shadowsocks, VMess, VLESS, Trojan, etc.)

---

## Quick Setup

### Step 1: Get Your Proxy Details

You'll need these from your proxy provider:

**For Shadowsocks**:

- Server address (e.g., `proxy.example.com`)
- Port (e.g., `8388`)
- Method/cipher (e.g., `aes-256-gcm`)
- Password

**For VMess/VLESS**:

- Server address
- Port
- UUID
- Encryption method
- Additional settings (alterID, transport, TLS, etc.)

**For Trojan**:

- Server address
- Port
- Password
- TLS settings (usually required)

### Step 2: Create Configuration

Choose your protocol and create `config.yaml`:

---

## Example 1: Shadowsocks

```yaml
schema_version: 2

log:
  level: info

# Local SOCKS5 listener
inbounds:
  - type: socks
    tag: socks-in
    listen: 127.0.0.1
    port: 1080

# Outbound definitions
outbounds:
  # Direct connection (fallback)
  - type: direct
    tag: direct

  # Shadowsocks proxy
  - type: shadowsocks
    tag: ss-proxy
    server: proxy.example.com
    port: 8388
    method: aes-256-gcm
    password: your-password-here

# Route everything through proxy
route:
  default: ss-proxy
```

**Supported Shadowsocks ciphers**:

- `aes-128-gcm`, `aes-256-gcm` (recommended)
- `chacha20-poly1305`
- `2022-blake3-aes-128-gcm`, `2022-blake3-aes-256-gcm` (Shadowsocks 2022)

---

## Example 2: VMess

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

  - type: vmess
    tag: vmess-proxy
    server: vmess.example.com
    port: 443
    uuid: 00000000-0000-0000-0000-000000000000 # Your UUID
    alter_id: 0 # Use 0 for AEAD
    security: auto # auto | aes-128-gcm | chacha20-poly1305

    # TLS (if server uses TLS)
    tls:
      enabled: true
      sni: vmess.example.com

    # WebSocket transport (if server uses WS)
    transport:
      type: ws
      path: /vmess
      headers:
        Host: vmess.example.com

route:
  default: vmess-proxy
```

**VMess security options**:

- `auto` - Auto-detect (recommended)
- `aes-128-gcm` - AES encryption
- `chacha20-poly1305` - ChaCha20 encryption
- `none` - No encryption (not recommended)

---

## Example 3: VLESS with REALITY

[REALITY](../01-user-guide/configuration/tls.md) is an anti-censorship TLS mode that disguises traffic as legitimate TLS connections.

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

  - type: vless
    tag: vless-reality
    server: reality.example.com
    port: 443
    uuid: 00000000-0000-0000-0000-000000000000

    # REALITY TLS settings
    tls:
      enabled: true
      reality:
        enabled: true
        public_key: "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
        short_id: "0123456789abcdef"
      sni: www.microsoft.com # Target SNI for camouflage

route:
  default: vless-reality
```

**Generate REALITY keypair**:

```bash
singbox-rust generate reality-keypair
```

See [TLS Configuration](../01-user-guide/configuration/tls.md) for REALITY details.

---

## Example 4: Trojan over TLS

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

  - type: trojan
    tag: trojan-proxy
    server: trojan.example.com
    port: 443
    password: your-trojan-password

    # TLS is required for Trojan
    tls:
      enabled: true
      sni: trojan.example.com
      # Skip cert verification (testing only!)
      # insecure: true

route:
  default: trojan-proxy
```

---

## Example 5: Hysteria v2

[Hysteria v2](../06-advanced-topics/README.md) is a high-performance QUIC-based protocol.

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

  - type: hysteria2
    tag: hy2-proxy
    server: hysteria.example.com
    port: 443
    password: your-hysteria-password

    # Bandwidth settings (required)
    up_mbps: 100
    down_mbps: 200

    # TLS (required)
    tls:
      enabled: true
      sni: hysteria.example.com

route:
  default: hy2-proxy
```

---

## Step 3: Validate Configuration

```bash
singbox-rust check -c config.yaml
```

**Expected output**:

```
✓ Configuration is valid
✓ Inbounds: 1 (socks-in)
✓ Outbounds: 2 (direct, ss-proxy)
✓ Routes: 1 rules, default: ss-proxy
```

---

## Step 4: Test the Connection

### Start the Proxy

```bash
singbox-rust run -c config.yaml
```

**Expected output**:

```
[INFO] Starting singbox-rust v0.2.0
[INFO] Listening on socks://127.0.0.1:1080
[INFO] Routing to ss-proxy (shadowsocks)
```

### Test with Curl

In another terminal:

```bash
# Test connection through proxy
curl -x socks5h://127.0.0.1:1080 https://ifconfig.me

# Should show your proxy server's IP, not your real IP
```

### Test Routing Decision

```bash
singbox-rust route -c config.yaml --dest google.com:443 --explain
```

---

## Adding Smart Routing

Route different domains to different outbounds:

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
    # Direct for local/China domains
    - domain_suffix: [cn, local, localhost]
      outbound: direct

    # Direct for China IPs (using geoip)
    - geoip: cn
      outbound: direct

    # Proxy for blocked domains
    - domain_suffix:
        - google.com
        - youtube.com
        - twitter.com
        - facebook.com
      outbound: proxy

  # Default: direct
  default: direct
```

See [Routing Configuration](../01-user-guide/configuration/routing.md) for advanced rules and [Transport Strategy](../TRANSPORT_STRATEGY.md) for transport behavior notes.

---

## Using Multiple Proxies

### Manual Selection (Selector)

```yaml
outbounds:
  - type: direct
    tag: direct

  - type: shadowsocks
    tag: proxy-us
    server: us.example.com
    port: 8388
    method: aes-256-gcm
    password: password1

  - type: shadowsocks
    tag: proxy-jp
    server: jp.example.com
    port: 8388
    method: aes-256-gcm
    password: password2

  # Manual selector
  - type: selector
    tag: proxy-select
    outbounds: [proxy-us, proxy-jp]
    default: proxy-us

route:
  default: proxy-select
```

**Switch proxy**:

Edit the selector `default` and reload the config (or restart the service).

### Automatic Selection (URLTest)

```yaml
outbounds:
  - type: shadowsocks
    tag: proxy-us
    server: us.example.com
    port: 8388
    method: aes-256-gcm
    password: password1

  - type: shadowsocks
    tag: proxy-jp
    server: jp.example.com
    port: 8388
    method: aes-256-gcm
    password: password2

  # Auto selector with health checks
  - type: urltest
    tag: auto-proxy
    outbounds: [proxy-us, proxy-jp]
    url: https://www.google.com/generate_204
    interval: 300s
    timeout_ms: 3000
    tolerance: 50ms

route:
  default: auto-proxy
```

Timing fields accept seconds/duration strings or `*_ms` values for millisecond precision. `members` is accepted as an alias for `outbounds` in selector/urltest configs.

See [Examples Index](../08-examples/README.md).

---

## Troubleshooting

### Connection Refused

**Symptoms**:

```
[ERROR] outbound_error: connection refused
```

**Solutions**:

1. Check server address and port
2. Verify firewall rules
3. Test with `telnet`:
   ```bash
   telnet proxy.example.com 8388
   ```

### Authentication Failed

**Symptoms**:

```
[ERROR] authentication failed
```

**Solutions**:

1. Verify password/UUID
2. Check encryption method matches server
3. Enable debug logging:
   ```bash
   RUST_LOG=debug singbox-rust run -c config.yaml
   ```

### TLS Handshake Failed

**Symptoms**:

```
[ERROR] TLS handshake failed: certificate verify failed
```

**Solutions**:

1. Verify SNI matches certificate
2. Check system time (TLS requires accurate clock)
3. For testing only, skip verification:
   ```yaml
   tls:
     enabled: true
     insecure: true # DO NOT USE IN PRODUCTION
   ```

### Slow Connection

**Solutions**:

1. Try different transport (WebSocket, HTTP/2, gRPC)
2. Enable multiplexing ([Advanced Topics](../06-advanced-topics/README.md))
3. Check bandwidth settings (Hysteria)
4. Test with:
   ```bash
   curl -x socks5h://127.0.0.1:1080 -w "%{time_total}\n" -o /dev/null https://google.com
   ```

See [Troubleshooting Guide](../TROUBLESHOOTING.md) for more.

---

## Next Steps

- **[Smart Routing](../TRANSPORT_STRATEGY.md)** - Route by domain, IP, process
- **[DNS Configuration](../01-user-guide/configuration/dns.md)** - FakeIP, DoH, DoT
- **[Examples Index](../08-examples/README.md)** - More configuration examples

---

**Related Documentation**:

- [User Guide](../01-user-guide/README.md)
- [TLS Configuration](../01-user-guide/configuration/tls.md)
- [Transport Defaults](../04-development/transport-defaults.md)
- [Operations Guide](../03-operations/README.md)
- [Examples Index](../08-examples/README.md)
