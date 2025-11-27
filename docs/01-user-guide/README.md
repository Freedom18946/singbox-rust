# User Guide

Complete guide to configuring and using singbox-rust.

---

## 📖 Documentation Sections

### Configuration

- **[Overview](configuration/overview.md)** - Configuration file structure and basics
- **[Inbounds](configuration/inbounds.md)** - Local listeners (SOCKS5, HTTP, TUN, etc.)
- **[Outbounds](configuration/outbounds.md)** - Upstream connections (proxies, direct, block)
- **[Routing](configuration/routing.md)** - Traffic routing rules
- **[DNS](configuration/dns.md)** - DNS resolution and FakeIP
- **[TLS](configuration/tls.md)** - TLS, REALITY, ECH configuration
- **[Schema Migration](configuration/schema-migration.md)** - V1 → V2 migration guide

### Protocols

- **[REALITY](protocols/reality.md)** - Anti-censorship TLS camouflage
- **[ECH](protocols/ech.md)** - Encrypted Client Hello for SNI privacy
- **[Hysteria](protocols/hysteria.md)** - High-performance QUIC proxy (v1/v2)
- **[TUIC](protocols/tuic.md)** - UDP-optimized QUIC protocol
- **[Shadowsocks](protocols/shadowsocks.md)** - Classic SOCKS5-based proxy
- **[Trojan](protocols/trojan.md)** - TLS-based protocol
- **[VMess](protocols/vmess.md)** - V2Ray's flexible protocol
- **[VLESS](protocols/vless.md)** - Lightweight V2Ray protocol

### Features

- **[Process Matching](features/process-matching.md)** - Route by application (149x faster on macOS)
- **[Multiplex](features/multiplex.md)** - Connection multiplexing with yamux
- **[UDP Relay](features/udp-relay.md)** - UDP support and NAT traversal
- **[Subscription](features/subscription.md)** - Remote subscription management
- **[Transports](features/transports.md)** - WebSocket, HTTP/2, gRPC, HTTPUpgrade

### Help

- **[Troubleshooting](troubleshooting.md)** - Common issues and solutions

---

## 🎯 Phase 1 Strategic Focus

**⚠️ Production-Ready Core Protocols for Initial Deployment**

This project's **Phase 1** release focuses exclusively on **Trojan** and **Shadowsocks** protocols for mature, production-ready deployment:

- ✅ 🎯 **Trojan** (inbound + outbound) - Full TLS-based protocol with fallback support
- ✅ 🎯 **Shadowsocks** (inbound + outbound) - All AEAD variants (AES-GCM, ChaCha20-Poly1305, AEAD-2022)

**All other protocols** are **📦 OPTIONAL/SECONDARY features** requiring manual feature enablement:
- VMess, VLESS, Hysteria (v1/v2), TUIC, AnyTLS, ShadowTLS
- HTTP, SOCKS, Naive, SSH, Tor
- Direct, Block, DNS, Mixed, TUN, Redirect, TProxy
- **DERP service** (🧪 experimental), WireGuard/Tailscale endpoints
- Advanced services (NTP, Resolved, SSMAPI)

**To enable optional protocols**:
```bash
# Example: Enable VMess outbound
cargo build --features "adapters,sb-adapters/adapter-vmess"

# Example: Enable DERP service
cargo build --features "service_derp"

# Example: Enable multiple optional protocols
cargo build --features "adapters,sb-adapters/adapter-vless,sb-adapters/adapter-hysteria2,service_derp"
```

---

## Protocol Support

### Inbound Protocols (17/17 Complete - 100%)

**🎯 Phase 1 Core (Production-Ready)**:
- **Shadowsocks**: AEAD ciphers with UDP relay (AES-GCM, ChaCha20-Poly1305, AEAD-2022)
- **Trojan**: TLS-based protocol with fallback

**📦 Optional (Feature-Gated)**:
- **SOCKS5**: Full support with UDP relay and authentication
- **HTTP/HTTPS**: HTTP proxy with CONNECT method
- **Mixed**: Combined SOCKS5 + HTTP on single port
- **Direct**: TCP/UDP forwarder with address override
- **TUN**: Virtual network interface (macOS/Linux/Windows)
- **Redirect**: Linux-only transparent proxy (iptables/nftables)
- **TProxy**: Linux-only transparent proxy with original destination
- **VMess**: V2Ray protocol with AEAD encryption
- **VLESS**: Lightweight V2Ray protocol with REALITY/ECH support
- **TUIC**: QUIC-based UDP-optimized protocol
- **Hysteria v1**: High-performance QUIC with custom congestion control
- **Hysteria v2**: Enhanced Hysteria with Salamander obfuscation
- **Naive**: Chromium-based HTTP/2 proxy
- **ShadowTLS**: TLS camouflage for Shadowsocks
- **AnyTLS**: TLS-based protocol with multi-user authentication and padding

### Outbound Protocols (19/19 Complete - 100%)

**🎯 Phase 1 Core (Production-Ready)**:
- **Shadowsocks**: Full cipher suite support (AES-GCM, ChaCha20-Poly1305, AEAD-2022)
- **Trojan**: Trojan client with TLS

**📦 Optional (Feature-Gated)**:
- **Direct**: Direct connection to target
- **Block**: Block connections
- **DNS**: DNS query outbound
- **SOCKS5**: SOCKS5 proxy client
- **HTTP/HTTPS**: HTTP proxy client
- **VMess**: V2Ray client with transport options
- **VLESS**: VLESS client with REALITY/ECH
- **TUIC**: QUIC-based client with UDP over stream
- **Hysteria v1**: High-performance QUIC client
- **Hysteria v2**: Enhanced Hysteria client
- **ShadowTLS**: TLS SNI/ALPN configuration
- **SSH**: SSH tunnel with key-based auth
- **Tor**: SOCKS5 proxy over Tor daemon
- **AnyTLS**: TLS-based client with session multiplexing
- **WireGuard**: System interface binding (production: use kernel WireGuard)
- **Selector**: Manual/auto outbound selection
- **URLTest**: Health-check based selection

### Advanced TLS Features

- **REALITY**: X25519-based TLS camouflage with fallback proxy
- **ECH (Encrypted Client Hello)**: HPKE-encrypted SNI for privacy
- **Standard TLS**: Full TLS 1.2/1.3 with ALPN, SNI, certificate verification
- **Certificate Management**: Custom CA, client certificates, skip verification

---

## Quick Links

### I Want To...

**Set up a basic proxy**
→ [Getting Started](../00-getting-started/) → [Basic Configuration](../00-getting-started/basic-configuration.md)

**Add an upstream proxy server**
→ [Your First Proxy](../00-getting-started/first-proxy.md)

**Route traffic by domain/IP**
→ [Routing Configuration](configuration/routing.md)

**Use TUN mode (system-wide proxy)**
→ [TUN Example](../08-examples/basic/tun-mode.md)

**Block ads and tracking**
→ [Routing with Rules](configuration/routing.md#blocking-traffic)

**Set up REALITY for anti-censorship**
→ [REALITY Protocol Guide](protocols/reality.md)

**Configure DNS with FakeIP**
→ [DNS Configuration](configuration/dns.md#fakeip)

**Use multiple proxies with load balancing**
→ [Load Balancing Example](../08-examples/advanced/load-balancing.md)

**Route by application/process**
→ [Process Matching](features/process-matching.md)

**Optimize performance**
→ [Performance Guide](../03-operations/performance/optimization-guide.md)

---

## Configuration Workflow

```
1. Create config file (YAML/JSON)
   ↓
2. Validate config
   $ singbox-rust check -c config.yaml
   ↓
3. Test routing decisions
   $ singbox-rust route -c config.yaml --dest example.com:443 --explain
   ↓
4. Run proxy
   $ singbox-rust run -c config.yaml
   ↓
5. Monitor metrics (optional)
   $ curl http://127.0.0.1:18088/metrics
```

---

## Configuration Structure

A typical singbox-rust configuration has these sections:

```yaml
schema_version: 2 # Required: config version

log: # Optional: logging settings
  level: info

inbounds: # Required: local listeners
  - type: socks
    tag: socks-in
    listen: 127.0.0.1
    port: 1080

outbounds: # Required: upstream connections
  - type: direct
    tag: direct
  - type: shadowsocks
    tag: proxy
    # ... proxy settings ...

route: # Required: routing rules
  rules:
    - domain_suffix: [google.com]
      outbound: proxy
  default: direct

dns: # Optional: DNS configuration
  servers:
    - address: https://1.1.1.1/dns-query
```

See [Configuration Overview](configuration/overview.md) for details.

---

## Supported Protocols

### Inbound Protocols (12/12 Complete)

| Protocol           | Description                   | Example Config                                  |
| ------------------ | ----------------------------- | ----------------------------------------------- |
| **SOCKS5**         | SOCKS5 proxy with UDP relay   | [Example](../08-examples/basic/socks5-proxy.md) |
| **HTTP**           | HTTP CONNECT proxy            | [Example](../08-examples/basic/http-proxy.md)   |
| **Mixed**          | SOCKS5 + HTTP combined        | [Example](../08-examples/basic/mixed-proxy.md)  |
| **TUN**            | System-wide transparent proxy | [Example](../08-examples/basic/tun-mode.md)     |
| **Direct**         | TCP/UDP forwarder             | [Config](configuration/inbounds.md#direct)      |
| **Shadowsocks**    | SS server with AEAD ciphers   | [Config](configuration/inbounds.md#shadowsocks) |
| **VMess**          | V2Ray protocol server         | [Config](configuration/inbounds.md#vmess)       |
| **VLESS**          | Lightweight V2Ray server      | [Config](configuration/inbounds.md#vless)       |
| **Trojan**         | TLS-based server              | [Config](configuration/inbounds.md#trojan)      |
| **TUIC**           | QUIC-based server             | [Protocol Guide](protocols/tuic.md)             |
| **Hysteria v1/v2** | High-performance QUIC         | [Protocol Guide](protocols/hysteria.md)         |
| **Naive**          | Chromium-based HTTP/2         | [Config](configuration/inbounds.md#naive)       |

### Outbound Protocols (15/15 Complete)

| Protocol           | Description                       | Example Config                                                |
| ------------------ | --------------------------------- | ------------------------------------------------------------- |
| **Direct**         | Direct connection                 | [Config](configuration/outbounds.md#direct)                   |
| **Block**          | Block/reject connections          | [Config](configuration/outbounds.md#block)                    |
| **DNS**            | DNS query outbound                | [Config](configuration/outbounds.md#dns)                      |
| **HTTP**           | HTTP proxy client                 | [Example](../00-getting-started/first-proxy.md#http)          |
| **SOCKS5**         | SOCKS5 proxy client               | [Config](configuration/outbounds.md#socks5)                   |
| **Shadowsocks**    | SS client with all ciphers        | [Example](../00-getting-started/first-proxy.md#shadowsocks)   |
| **VMess**          | V2Ray protocol client             | [Example](../00-getting-started/first-proxy.md#vmess)         |
| **VLESS**          | VLESS client with REALITY         | [Example](../00-getting-started/first-proxy.md#vless)         |
| **Trojan**         | Trojan client                     | [Example](../00-getting-started/first-proxy.md#trojan)        |
| **TUIC**           | TUIC client                       | [Protocol Guide](protocols/tuic.md)                           |
| **Hysteria v1/v2** | Hysteria client                   | [Example](../00-getting-started/first-proxy.md#hysteria-v2)   |
| **SSH**            | SSH tunnel                        | [Config](configuration/outbounds.md#ssh)                      |
| **ShadowTLS**      | TLS camouflage                    | [Config](configuration/outbounds.md#shadowtls)                |
| **Selector**       | Manual outbound selection         | [Example](../08-examples/advanced/load-balancing.md#selector) |
| **URLTest**        | Auto selection with health checks | [Example](../08-examples/advanced/load-balancing.md#urltest)  |

---

## Key Features

### Smart Routing

Route traffic based on:

- **Domain**: Exact match, suffix, keyword, regex
- **IP/CIDR**: IPv4/IPv6 address ranges
- **Port**: Destination port numbers
- **Protocol**: TCP or UDP
- **Process**: Application name or path (requires permission)
- **Sniffing**: Auto-detected protocol (TLS SNI, HTTP Host, QUIC ALPN)
- **Inbound**: Source inbound tag
- **GeoIP/GeoSite**: Geographic and domain categorization

See [Routing Configuration](configuration/routing.md).

### DNS Resolution

Multiple DNS modes:

- **System**: Use system DNS resolver
- **Direct**: Traditional DNS queries (UDP/TCP port 53)
- **DNS over HTTPS (DoH)**: Encrypted DNS via HTTPS
- **DNS over TLS (DoT)**: Encrypted DNS via TLS
- **DNS over QUIC (DoQ)**: Encrypted DNS via QUIC
- **FakeIP**: Virtual IPs for routing optimization

See [DNS Configuration](configuration/dns.md).

### TLS & Anti-Censorship

Advanced TLS features:

- **Standard TLS 1.2/1.3**: Production-ready with rustls
- **REALITY**: Anti-censorship TLS camouflage
- **ECH**: Encrypted Client Hello for SNI privacy
- **ALPN**: Protocol negotiation (HTTP/2, HTTP/1.1)
- **Custom CA**: Self-signed certificate support

See [TLS Configuration](configuration/tls.md).
See DNS configuration: [DNS Configuration](configuration/dns.md).

### Transport Layers

Flexible transport options:

- **TCP/UDP**: Standard transports
- **WebSocket**: WS and WSS with custom paths
- **HTTP/2**: H2 and H2C transport
- **HTTPUpgrade**: HTTP upgrade to TCP stream
- **gRPC**: gRPC tunnel transport
- **QUIC**: HTTP/3 and custom QUIC protocols
- **Multiplex**: yamux stream multiplexing

See [Transport Features](features/transports.md).

---

## Common Use Cases

### 1. Personal VPN Replacement

```yaml
inbounds:
  - type: tun
    tag: tun-in
    address: [172.19.0.1/30]
    mtu: 1500
    auto_route: true

outbounds:
  - type: shadowsocks
    tag: proxy
    # ... your SS server ...

route:
  default: proxy
```

See [TUN Mode Example](../08-examples/basic/tun-mode.md).

### 2. Development Proxy

```yaml
inbounds:
  - type: mixed
    tag: mixed-in
    listen: 127.0.0.1
    port: 7890

outbounds:
  - type: direct
    tag: direct

route:
  default: direct
```

### 3. Smart Routing (China Direct, Others Proxy)

```yaml
route:
  rules:
    - geoip: cn
      outbound: direct
    - geosite: cn
      outbound: direct
    - domain_suffix: [cn]
      outbound: direct
  default: proxy
```

### 4. Ad Blocking

```yaml
route:
  rules:
    - domain_suffix:
        - doubleclick.net
        - googlesyndication.com
        - googleadservices.com
      outbound: block
```

### 5. Load Balancing

```yaml
outbounds:
  - type: urltest
    tag: auto-select
    outbounds: [proxy-us, proxy-jp, proxy-sg]
    url: https://www.google.com/generate_204
    interval: 300s
```

See [Load Balancing Example](../08-examples/advanced/load-balancing.md).

---

## Environment Variables

Override configuration via environment:

| Variable          | Description        | Example             |
| ----------------- | ------------------ | ------------------- |
| `RUST_LOG`        | Log level          | `RUST_LOG=debug`    |
| `SB_PRINT_ENV`    | Print env snapshot | `SB_PRINT_ENV=1`    |
| `SB_DNS_ENABLE`   | Enable DNS         | `SB_DNS_ENABLE=1`   |
| `SB_DNS_MODE`     | DNS mode           | `SB_DNS_MODE=doh`   |
| `SB_ADMIN_ENABLE` | Enable admin API   | `SB_ADMIN_ENABLE=1` |

See [Environment Variables](../02-cli-reference/environment-variables.md) for all options.

---

## Getting Help

### Documentation

- **[Getting Started](../00-getting-started/)** - Quick start guide
- **[Troubleshooting](troubleshooting.md)** - Common issues and fixes
- **[CLI Reference](../02-cli-reference/)** - Command-line tools
- **[Examples](../08-examples/)** - Ready-to-use configs

### Community

- **GitHub Issues**: [Report bugs](https://github.com/your-repo/issues)
- **Discussions**: [Ask questions](https://github.com/your-repo/discussions)
- **Examples**: [Share configurations](https://github.com/your-repo/discussions/categories/show-and-tell)

---

**Next Steps**:

- Read [Configuration Overview](configuration/overview.md) to understand config structure
- Try [Examples](../08-examples/) for ready-to-use configurations
- Learn about [Routing](configuration/routing.md) for advanced traffic control
- Explore [Protocols](protocols/) for protocol-specific guides
