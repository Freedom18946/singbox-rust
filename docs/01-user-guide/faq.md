# Frequently Asked Questions

---

## Migration

### How do I migrate from Go sing-box?

Use the built-in migration command:

```bash
singbox-rust check -c old-config.json --migrate --write-normalized --out config.v2.yaml
```

This automatically handles:
- Renaming `tag` to `name` on outbounds
- Merging `listen` + `listen_port` into `listen: "IP:PORT"`
- Moving root-level `rules` into `route.rules`
- Renaming `default_outbound` to `route.default`
- Renaming `server_port` to `port`
- Normalizing `socks5` type to `socks`
- Wrapping flat rule conditions in `when` objects
- Adding `schema_version: 2`

Always review the output before deploying. See [Schema Migration](configuration/schema-migration.md) for the complete field mapping.

### Can I use my Go sing-box config directly?

In many cases, yes. singbox-rust accepts Go-compatible aliases for common fields:
- `tag` works alongside `name`
- `outbound` works alongside `to` in route rules
- `outbounds` works alongside `members` in selector/urltest
- `listen_port` is accepted (merged with `listen`)
- `server_port` is accepted (mapped to `port`)
- Duration strings like `"3s"` are accepted in timing fields

However, running the migrator is recommended for a clean V2 config.

### What are the key config format differences?

| Aspect | Go sing-box | singbox-rust |
|---|---|---|
| Outbound identifier | `tag` | `name` (or `tag`) |
| Listen port | `listen` + `listen_port` | `listen: "IP:PORT"` |
| Outbound remote port | `server_port` | `port` |
| URLTest interval | `"60s"` (duration string) | `60` (seconds) or `60000` (ms) |
| SOCKS outbound type | `socks5` | `socks` |
| Route rule target | `outbound` | `outbound` or `to` |
| Schema version | (none) | `schema_version: 2` |
| WireGuard | In `outbounds` | In `endpoints` |

---

## Features

### What features are supported?

singbox-rust has 100% feature parity with Go sing-box 1.12.14 (209/209 features).

**Inbound types**: socks, http, mixed, tun, redirect, tproxy, direct, shadowsocks, vmess, vless, trojan, naive, shadowtls, anytls, hysteria, hysteria2, tuic, dns, ssh

**Outbound types**: direct, block, http, socks, shadowsocks, shadowtls, selector, urltest, hysteria, hysteria2, tuic, vless, vmess, trojan, ssh, dns, tor, anytls, wireguard, tailscale, shadowsocksr

**Transport**: WebSocket, gRPC, HTTP Upgrade, HTTP/2

**TLS**: Standard TLS 1.2/1.3 (rustls), REALITY, ECH (Encrypted Client Hello)

**DNS**: System, UDP, DoH, DoT, DoQ, DoH3, DHCP, Tailscale, systemd-resolved

**Routing**: Domain, domain suffix/keyword/regex, GeoIP, Geosite, IP CIDR, port, process, network, protocol, rule sets (SRS), logical rules, Clash mode, AdGuard-style rules

**API**: Clash API (with WebSocket), V2Ray API (gRPC stats)

**Extras**: NTP, FakeIP, cache file, traffic sniffing (HTTP/TLS/QUIC with multi-packet SNI), multiplex (yamux), UDP over TCP, uTLS fingerprinting

### What Rust-only features are available?

- **Tailscale outbound/endpoint**: Native Tailscale integration (feature-gated)
- **DERP relay service**: Built-in DERP server
- **SSM API service**: Shadowsocks Manager API
- **Provider hot-reload**: Subscription provider auto-update
- **Memory-safe protocol implementations**: All protocols rewritten in safe Rust

### What features are NOT supported?

- **V2Ray inbound routing** (deprecated in Go sing-box)
- **Some provider backends**: Provider endpoint stubs are not fully implemented (7 BHV-SV structural blocks)

---

## TUN Mode

### How do I configure TUN mode?

```yaml
inbounds:
  - type: tun
    tag: tun-in
    tun:
      mtu: 1500
      auto_route: true
      stack: system
      inet4_address: "172.19.0.1/30"
    sniff: true
    sniff_override_destination: true

outbounds:
  - type: direct
    name: direct

route:
  default: direct
  auto_detect_interface: true
```

### Does TUN require root/admin privileges?

Yes. TUN device creation requires elevated permissions on all platforms:
- **macOS**: Run with `sudo` or use a privileged helper
- **Linux**: Run as root or use `CAP_NET_ADMIN` capability
- **Windows**: Run as Administrator

### Which TUN stack should I use?

- **`system`** (default): Uses the OS kernel networking stack. Best performance on macOS and Linux.
- **`gvisor`**: Userspace TCP/IP stack. Better compatibility but higher CPU usage. Required on some restricted environments.
- **`mixed`**: System stack for TCP, gVisor for UDP. Good balance for most setups.

### Does TUN UDP work on all platforms?

- **macOS**: Full UDP support
- **Linux**: Requires additional kernel configuration; may drop packets without proper setup
- **Windows**: Limited; some packets may be dropped

---

## Clash API

### How do I enable Clash API?

```yaml
experimental:
  clash_api:
    external_controller: "127.0.0.1:9090"
    secret: optional-api-secret
    default_mode: rule
```

### Can I use Clash GUI dashboards?

Yes. singbox-rust is compatible with Clash dashboards like Yacd and Metacubexd:

```yaml
experimental:
  clash_api:
    external_controller: "127.0.0.1:9090"
    external_ui: /path/to/yacd-dist
    secret: my-secret
```

Then open `http://127.0.0.1:9090/ui/` in your browser.

### What Clash API endpoints are supported?

- `GET /proxies` - List all proxies
- `GET /proxies/:name` - Get proxy details
- `PUT /proxies/:name` - Switch selector proxy
- `GET /proxies/:name/delay` - Test proxy latency
- `GET /connections` - List active connections (WebSocket supported)
- `DELETE /connections` - Close all connections
- `DELETE /connections/:id` - Close specific connection
- `GET /rules` - List routing rules
- `GET /configs` - Get running config
- `PATCH /configs` - Update config (mode, log level)
- `PUT /configs` - Reload config
- `GET /logs` - Stream logs (WebSocket)
- `GET /traffic` - Stream traffic stats (WebSocket)
- `GET /memory` - Stream memory usage (WebSocket)
- `GET /providers/proxies` - List proxy providers

---

## Troubleshooting

### Why is my config rejected?

Run validation:

```bash
singbox-rust check -c config.yaml
```

Common issues:
1. Missing `schema_version: 2`
2. Duplicate `tag`/`name` across inbounds or outbounds
3. Route rule referencing a non-existent outbound tag
4. TLS `sni` not matching server certificate
5. Missing required fields (e.g., `uuid` for VMess/VLESS)

### How do I enable debug logging?

```bash
RUST_LOG=debug singbox-rust run -c config.yaml
```

For specific module logging:

```bash
RUST_LOG=sb_core=debug,sb_tls=trace singbox-rust run -c config.yaml
```

Or in config:

```yaml
log:
  level: debug
  timestamp: true
```

### Why are connections slow?

1. **DNS resolution**: Ensure DNS is configured and responsive. Use a nearby DNS server.
2. **TLS handshake**: First connections incur TLS overhead. Enable multiplex for connection reuse.
3. **Proxy server latency**: Use `urltest` to automatically pick the lowest-latency proxy.
4. **MTU issues**: With TUN mode, try reducing `mtu` (e.g., 1280).
5. **Routing rules**: Too many regex rules can slow matching. Prefer domain suffix rules or rule sets.

### How do I check proxy latency?

Using Clash API:

```bash
curl http://127.0.0.1:9090/proxies/proxy-name/delay?url=http://www.gstatic.com/generate_204&timeout=5000
```

Or use a URLTest outbound that continuously measures latency.

### Config hot-reload

Send SIGHUP to reload config without restarting:

```bash
kill -HUP $(pidof singbox-rust)
```

This triggers a full supervisor reload cycle.

---

## Performance

### What is the throughput?

On loopback benchmarks:
- **TCP relay**: 2.4 GiB/s (16KB buffer), 3.0 GiB/s (64KB buffer) for 1MB payload
- Real-world throughput depends on proxy protocol, encryption, and network conditions

### How do I optimize memory usage?

1. Use rule sets (SRS binary format) instead of inline rules for large domain lists
2. Enable `experimental.cache_file` to persist DNS/FakeIP cache across restarts
3. Avoid excessive concurrent connections (tune `max_connections` in multiplex)
4. Use `geoip`/`geosite` databases instead of inline IP CIDR/domain lists

---

## Platform Support

### Which platforms are supported?

- **macOS**: aarch64 (Apple Silicon), x86_64
- **Linux**: x86_64, aarch64, armv7
- **Windows**: x86_64, aarch64

### Cross-compilation

The release workflow produces binaries for all supported targets. For manual builds:

```bash
# Build for current platform
cargo build -p app --release --features parity

# Build with specific features
cargo build -p app --release --features "adapters,clash_api"
```

Feature flags:
- `adapters`: Enables SOCKS/HTTP/mixed inbounds
- `clash_api`: Enables Clash API server
- `parity`: Full feature set (adapters + clash_api + DNS + NTP + services)
- `router`: Minimal routing (no inbound adapters)
