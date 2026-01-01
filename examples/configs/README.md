# Configuration Examples / 配置示例

Complete configuration examples for all singbox-rust features, organized by category.

singbox-rust 的完整配置示例，按类别组织。

---

## 📁 Directory Structure

```
configs/
├── inbounds/       # Inbound protocol configurations
├── outbounds/      # Outbound proxy client configurations
├── routing/        # Routing rule examples
├── dns/            # DNS configuration examples
├── advanced/       # Complex production scenarios
└── security/       # TLS and security features
```

---

## 📥 Inbound Protocols

**Directory**: `inbounds/`

Server-side configurations for accepting connections:

| Protocol       | Status | Key Features         |
| -------------- | ------ | -------------------- |
| SOCKS5         | ✅     | Auth, UDP relay      |
| HTTP           | ✅     | CONNECT method       |
| Mixed          | ✅     | SOCKS5+HTTP combined |
| Shadowsocks    | ✅     | AEAD ciphers         |
| VMess          | ✅     | WebSocket transport  |
| VLESS          | ✅     | REALITY support      |
| Trojan         | ✅     | TLS with fallback    |
| TUN            | ✅     | Transparent proxy    |
| Hysteria v1/v2 | ✅     | QUIC-based           |
| TUIC           | ✅     | UDP optimization     |

See [inbounds/README.md](inbounds/README.md) for details.

---

## 📤 Outbound Protocols

**Directory**: `outbounds/`

Client-side configurations for connecting to upstream proxies:

| Protocol       | Status | Transport Options |
| -------------- | ------ | ----------------- |
| Shadowsocks    | ✅     | Standard          |
| VMess          | ✅     | WS, gRPC, H2      |
| VLESS          | ✅     | REALITY, ECH      |
| Trojan         | ✅     | TLS, gRPC         |
| Hysteria v1/v2 | ✅     | QUIC              |
| TUIC           | ✅     | QUIC              |
| SSH            | ✅     | SSH tunnel        |
| Selector       | ✅     | Manual selection  |
| URLTest        | ✅     | Auto failover     |

See [outbounds/README.md](outbounds/README.md) for details.

---

## 🛣️ Routing

**Directory**: `routing/`

Routing rule examples for traffic steering:

- **domain-based.json** - Domain/suffix matching
- **geoip-routing.json** - Geographic IP routing
- **process-based.json** - Per-application routing (macOS/Windows)
- **rules_demo.json** - Basic routing patterns

**Key Concepts**:

- Rule evaluation order
- Domain suffix matching
- CIDR-based routing
- GeoIP/GeoSite integration
- Process name matching (platform-specific)

See [routing/README.md](routing/README.md) for details.

---

## 🌐 DNS Configuration

**Directory**: `dns/`

DNS resolver configurations:

| File              | Protocol       | Provider           |
| ----------------- | -------------- | ------------------ |
| `doh-simple.yaml` | DNS-over-HTTPS | Cloudflare, Google |
| `dot-simple.yaml` | DNS-over-TLS   | Cloudflare, Quad9  |
| `doq-simple.yaml` | DNS-over-QUIC  | AdGuard, NextDNS   |
| `fakeip.json`     | FakeIP         | N/A (local)        |
| `v1_dns.yml`      | Mixed          | Legacy format      |
| `v2_dns.yml`      | Mixed          | V2 format          |

**Features**:

- Encrypted DNS (DoH/DoT/DoQ)
- FakeIP for low latency
- DNS routing rules
- Fallback strategies

See [dns/README.md](dns/README.md) for details.

---

## 🚀 Advanced Scenarios

**Directory**: `advanced/`

Production-ready complex configurations:

| File                     | Scenario         | Complexity |
| ------------------------ | ---------------- | ---------- |
| `full_stack.json`        | Complete setup   | ⭐⭐⭐     |
| `transparent-proxy.json` | Global TUN proxy | ⭐⭐⭐⭐   |
| `load-balancing.json`    | Multi-server LB  | ⭐⭐⭐     |
| `failover.json`          | Auto failover    | ⭐⭐⭐     |
| `chain-proxy.json`       | Proxy chaining   | ⭐⭐⭐     |
| `v2_proxy.yml`           | V2Ray compatible | ⭐⭐       |

See [advanced/README.md](advanced/README.md) for details.

---

## 🔐 Security & TLS

**Directory**: `security/`

Advanced TLS and security features:

| File                    | Technology             | Security Level |
| ----------------------- | ---------------------- | -------------- |
| `tls-standard.json`     | TLS 1.2/1.3            | 🔒🔒🔒         |
| `reality_vless.json`    | REALITY TLS            | 🔒🔒🔒🔒       |
| `reality-complete.json` | REALITY (full)         | 🔒🔒🔒🔒       |
| `ech_outbound.json`     | Encrypted Client Hello | 🔒🔒🔒🔒       |

**Technologies**:

- Standard TLS with ALPN and SNI
- REALITY: X25519-based TLS camouflage
- ECH: Encrypted Client Hello (HPKE)
- Certificate management
- Client authentication

See [security/README.md](security/README.md) for details.

---

## 🔧 Usage Guide

### Running Examples

```bash
# Basic usage
cargo run -p app -- run -c examples/configs/CATEGORY/FILE.json

# With logging
RUST_LOG=info cargo run -p app -- run -c examples/configs/CATEGORY/FILE.json

# Check validity
cargo run -p app -- check -c examples/configs/CATEGORY/FILE.json
```

### Feature Flags

Many examples require specific features:

```bash
# Shadowsocks
cargo run -p app --features 'sb-core/in_shadowsocks' -- run -c CONFIG

# VMess with transport
cargo run -p app --features 'sb-core/out_vmess,sb-core/v2ray_transport' -- run -c CONFIG

# TUN (requires root)
sudo cargo run -p app --features 'sb-core/in_tun' -- run -c CONFIG

# REALITY
cargo run -p app --features 'sb-core/reality' -- run -c CONFIG
```

### Environment Variables

```bash
# DNS configuration
SB_DNS_ENABLE=1 SB_DNS_MODE=doh cargo run -p app -- run -c CONFIG

# UDP NAT settings
SB_UDP_NAT_MAX=10000 cargo run -p app -- run -c CONFIG

# Debug printing
SB_PRINT_ENV=1 RUST_LOG=debug cargo run -p app -- run -c CONFIG
```

---

## 📖 Configuration Tips

### 1. Start Simple

Begin with basic examples from `inbounds/` or `outbounds/`, then add complexity.

### 2. Validate Configuration

Always validate before running:

```bash
cargo run -p app -- check -c CONFIG.json --format json
```

### 3. Test Routing

Explain routing decisions:

```bash
cargo run -p app -- route -c CONFIG.json \
  --dest example.com:443 --explain
```

### 4. Enable Logging

Use logging to understand behavior:

```bash
RUST_LOG=sb_core=debug,app=info cargo run -p app -- run -c CONFIG
```

---

## 🎓 Learning Path

### Beginner

1. Review `inbounds/socks5.json` or `inbounds/minimal_http.json`
2. Try `outbounds/shadowsocks.json`
3. Learn routing with `routing/domain-based.json`

### Intermediate

4. Configure DNS with `dns/doh-simple.yaml`
5. Explore `outbounds/selector.json` for manual switching
6. Try `outbounds/urltest.json` for auto failover

### Advanced

7. Study `advanced/transparent-proxy.json` for TUN setup
8. Review `security/reality-complete.json` for REALITY
9. Combine features in custom configurations

---

## 💡 Best Practices

### Security

1. **Never skip TLS verification** in production (`insecure: false`)
2. **Use strong passwords** for Shadowsocks/Trojan (20+ chars)
3. **Enable JWT auth** for admin API
4. **Prefer REALITY** over standard TLS for better camouflage

### Performance

1. **Use FakeIP** for lower DNS latency
2. **Enable URLTest** for automatic failover
3. **Tune UDP NAT** table size with `SB_UDP_NAT_MAX`
4. **Use native process matching** on macOS/Windows (20-150x faster)

### Maintenance

1. **Version control** your configurations
2. **Document customizations** with comments (use `"// comment": "text"` in JSON)
3. **Test after changes** with `check` and `route --explain`
4. **Monitor metrics** via Prometheus endpoint

---

## 🔗 Related Documentation

- [Architecture](../../docs/ARCHITECTURE.md)
- [Router Rules](../../docs/ROUTER_RULES.md)
- [Environment Variables](../../docs/ENV_VARS.md)
- [Admin API](../../docs/ADMIN_API_CONTRACT.md)

---

## 📊 Feature Matrix

| Feature            | Coverage     | Examples    |
| ------------------ | ------------ | ----------- |
| Inbound Protocols  | 12/12 (100%) | ✅ Complete |
| Outbound Protocols | 15/15 (100%) | ✅ Complete |
| Transport Layers   | All          | ✅ Complete |
| DNS Backends       | DoH/DoT/DoQ  | ✅ Complete |
| Routing Rules      | All types    | ✅ Complete |
| TLS Features       | All          | ✅ Complete |

---

**Last Updated**: 2026-01-01  
**Config Version**: v0.2.0+
