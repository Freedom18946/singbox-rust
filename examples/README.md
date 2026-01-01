# Examples / 示例配置

Welcome to the singbox-rust examples directory! This comprehensive collection provides configuration examples, code samples, and tutorials for all features of singbox-rust.

欢迎来到 singbox-rust 示例目录！这里提供了全面的配置示例、代码样例和教程，涵盖 singbox-rust 的所有功能。

---

## 📑 Table of Contents / 目录

- [Quick Start](#-quick-start--快速开始) - Get started in minutes
- [Configuration Examples](#-configuration-examples--配置示例) - Protocol-specific configs
- [DSL Rules](#-dsl-rules--dsl-规则) - Domain-specific routing language
- [Code Examples](#-code-examples--代码示例) - Rust integration examples
- [Schemas](#-schemas--模式定义) - JSON schemas for validation
- [Usage Guide](#-usage-guide--使用指南) - How to run examples

---

## 🚀 Quick Start / 快速开始

**New to singbox-rust? Start here!** / **初次使用？从这里开始！**

Located in: `quick-start/`

These minimal examples help you get up and running quickly:

| File                    | Description                   | Usage                |
| ----------------------- | ----------------------------- | -------------------- |
| `01-minimal.yaml`       | Minimal HTTP proxy            | Most basic setup     |
| `02-socks5-direct.yaml` | SOCKS5 with direct connection | Simple SOCKS5 proxy  |
| `03-http-proxy.yaml`    | HTTP proxy with routing       | Basic HTTP proxy     |
| `04-mixed-inbound.yaml` | Mixed SOCKS5+HTTP on one port | Versatile setup      |
| `05-basic-routing.yaml` | Basic routing rules demo      | Learn routing basics |

### Run Your First Example

```bash
# Run minimal HTTP proxy
cargo run -p app -- run -c examples/quick-start/01-minimal.yaml

# Test it
curl -x http://127.0.0.1:28090 https://example.com
```

---

## 📦 Configuration Examples / 配置示例

Located in: `configs/`

### Inbound Protocols / 入站协议

**Directory:** `configs/inbounds/`

Examples for all supported inbound protocols:

| Protocol        | File                | Features                  | Status      |
| --------------- | ------------------- | ------------------------- | ----------- |
| **SOCKS5**      | `socks5.json`       | Authentication, UDP relay | ✅ Complete |
| **HTTP**        | `minimal_http.json` | HTTP CONNECT proxy        | ✅ Complete |
| **Shadowsocks** | `shadowsocks.json`  | AEAD ciphers, UDP         | ✅ Complete |
| **VMess**       | `vmess.json`        | WebSocket transport       | ✅ Complete |
| **Trojan**      | `trojan.json`       | TLS with fallback         | ✅ Complete |
| **TUN**         | `tun.json`          | Transparent proxy         | ✅ Complete |

```bash
# Example: Run Shadowsocks server
cargo run -p app --features 'sb-core/in_shadowsocks' -- \
  run -c examples/configs/inbounds/shadowsocks.json
```

### Outbound Protocols / 出站协议

**Directory:** `configs/outbounds/`

Client configuration for connecting to upstream proxies:

| Protocol        | File                             | Features                         | Status      |
| --------------- | -------------------------------- | -------------------------------- | ----------- |
| **Shadowsocks** | `shadowsocks.json`               | Standard SS client               | ✅ Complete |
| **VMess**       | `vmess-ws-tls.json`              | WebSocket + TLS                  | ✅ Complete |
| **VLESS**       | `../security/reality_vless.json` | With REALITY TLS                 | ✅ Complete |
| **Trojan**      | `trojan-grpc.json`               | gRPC transport                   | ✅ Complete |
| **TUIC**        | `tuic_outbound.json`             | QUIC-based UDP                   | ✅ Complete |
| **Hysteria v1** | `hysteria_v1.json`               | High-performance QUIC            | ✅ Complete |
| **Hysteria v2** | `hysteria_v2.json`               | With Salamander obfuscation      | ✅ Complete |
| **SSH**         | `ssh_outbound.json`              | SSH tunnel                       | ✅ Complete |
| **Selector**    | `selector.json`                  | Manual proxy selection           | ✅ Complete |
| **URLTest**     | `urltest.json`                   | Auto failover with health checks | ✅ Complete |

```bash
# Example: Run VMess client with WebSocket + TLS
cargo run -p app --features 'sb-core/out_vmess,sb-core/v2ray_transport' -- \
  run -c examples/configs/outbounds/vmess-ws-tls.json
```

### Routing / 路由规则

**Directory:** `configs/routing/`

Advanced routing configurations:

| File                 | Description            | Use Case                |
| -------------------- | ---------------------- | ----------------------- |
| `rules_demo.json`    | Basic routing rules    | Learning routing        |
| `domain-based.json`  | Domain/suffix matching | Domain-specific routing |
| `geoip-routing.json` | GeoIP + GeoSite rules  | China/foreign split     |
| `process-based.json` | Process name matching  | Per-app routing         |

```bash
# Example: Run with GeoIP routing
cargo run -p app -- run -c examples/configs/routing/geoip-routing.json
```

### DNS Configuration / DNS 配置

**Directory:** `configs/dns/`

DNS examples for all supported protocols:

| File                       | Protocol       | Description       |
| -------------------------- | -------------- | ----------------- |
| `doh-simple.yaml`          | DNS-over-HTTPS | Cloudflare DoH    |
| `dot-simple.yaml`          | DNS-over-TLS   | Encrypted DNS     |
| `doq-simple.yaml`          | DNS-over-QUIC  | QUIC-based DNS    |
| `fakeip.json`              | FakeIP         | Low-latency DNS   |
| `v1_dns.yml`, `v2_dns.yml` | Various        | Complex DNS rules |

```bash
# Example: Run with DoH
cargo run -p app --features 'sb-core/dns_doh' -- \
  run -c examples/configs/dns/doh-simple.yaml
```

### Advanced Scenarios / 高级场景

**Directory:** `configs/advanced/`

Production-ready complex configurations:

| File                     | Scenario                    | Features               |
| ------------------------ | --------------------------- | ---------------------- |
| `full_stack.json`        | Complete setup              | All features combined  |
| `transparent-proxy.json` | Global proxy with TUN       | Automatic routing      |
| `load-balancing.json`    | Multi-server load balancing | Round-robin strategy   |
| `failover.json`          | Automatic failover          | Health-check based     |
| `chain-proxy.json`       | Proxy chaining              | Multi-hop routing      |
| `v2_proxy.yml`           | V2Ray-compatible            | Upstream compatibility |

```bash
# Example: Run full-stack configuration
cargo run -p app -- run -c examples/configs/advanced/full_stack.json
```

### Security & TLS / 安全与 TLS

**Directory:** `configs/security/`

Advanced TLS and security features:

| File                    | Technology   | Description             |
| ----------------------- | ------------ | ----------------------- |
| `tls-standard.json`     | Standard TLS | TLS 1.2/1.3 with ALPN   |
| `reality_vless.json`    | REALITY TLS  | X25519-based camouflage |
| `reality-complete.json` | REALITY TLS  | Complete REALITY setup  |
| `ech_outbound.json`     | ECH          | Encrypted Client Hello  |

```bash
# Example: Run REALITY TLS client
cargo run -p app --features 'sb-core/reality' -- \
  run -c examples/configs/security/reality-complete.json
```

---

## 📝 DSL Rules / DSL 规则

**Directory:** `dsl/`

Domain-Specific Language for routing rules:

| File                   | Description                 |
| ---------------------- | --------------------------- |
| `basic-routing.dsl`    | Basic DSL syntax examples   |
| `advanced-routing.dsl` | Advanced patterns with CIDR |
| `plus-syntax.txt`      | Extended DSL+ syntax guide  |
| `v1-examples.txt`      | Version 1 DSL examples      |
| `v2-examples.txt`      | Version 2 DSL examples      |
| `sample.txt`           | General DSL samples         |

### Example DSL Syntax

```
# Basic routing rules
exact:example.com=direct
suffix:.cn=direct
keyword:ads=reject
cidr:192.168.0.0/16=direct
default:proxy
```

See `dsl/README.md` for complete DSL documentation.

---

## 🔧 Code Examples / 代码示例

**Directory:** `code-examples/`

Rust code examples for integrating singbox-rust into your applications:

### Network Examples / 网络示例

`code-examples/network/`

- `tcp_connect.rs` - Direct TCP connection example
- `udp_echo.rs` - UDP echo server example
- `udp_blast.rs` - UDP stress testing

```bash
# Run TCP connect example
cargo run --example tcp_connect -- example.com 80
```

### DNS Examples / DNS 示例

`code-examples/dns/`

- `dns_lookup.rs` - DNS resolution example

```bash
# Run DNS lookup
cargo run --example dns_lookup
```

### Proxy Examples / 代理示例

`code-examples/proxy/`

- `http_inbound_demo.rs` - HTTP inbound implementation
- `socks5_udp_probe.rs` - SOCKS5 UDP relay testing

```bash
# Run HTTP inbound demo
RUST_LOG=info cargo run --example http_inbound_demo
```

### Testing Scenarios / 测试场景

`code-examples/testing/scenarios/`

- `loopback.smoke.json` - Loopback smoke test
- `vars.ci.json` - CI environment variables
- `vars.dev.json` - Development environment variables

---

## 📋 Schemas / 模式定义

**Directory:** `schemas/`

JSON schemas for configuration validation:

| File                 | Purpose                    |
| -------------------- | -------------------------- |
| `config.schema.json` | Main configuration schema  |
| `subs.schema.json`   | Subscription format schema |
| `schema.map.json`    | Schema mapping file        |

Use these for IDE autocompletion and validation.

---

## 📚 Usage Guide / 使用指南

### Basic Usage

```bash
# Run any configuration
cargo run -p app -- run -c examples/PATH/TO/CONFIG.json

# Check configuration validity
cargo run -p app -- check -c examples/PATH/TO/CONFIG.json

# Explain routing decision
cargo run -p app -- route -c examples/PATH/TO/CONFIG.json \
  --dest example.com:443 --explain
```

### With Feature Flags

Many examples require specific feature flags:

```bash
# Shadowsocks inbound
cargo run -p app --features 'sb-core/in_shadowsocks' -- run -c CONFIG

# VMess with V2Ray transport
cargo run -p app --features 'sb-core/out_vmess,sb-core/v2ray_transport' -- run -c CONFIG

# TUN device (requires root)
sudo cargo run -p app --features 'sb-core/in_tun' -- run -c CONFIG

# REALITY TLS
cargo run -p app --features 'sb-core/reality' -- run -c CONFIG

# DoQ (DNS-over-QUIC)
cargo run -p app --features 'sb-core/dns_doq' -- run -c CONFIG
```

### Environment Variables

Control runtime behavior with environment variables:

```bash
# Enable logging
RUST_LOG=info cargo run -p app -- run -c CONFIG

# DNS configuration
SB_DNS_ENABLE=1 SB_DNS_MODE=doh cargo run -p app -- run -c CONFIG

# UDP NAT settings
SB_UDP_NAT_MAX=10000 cargo run -p app -- run -c CONFIG

# Print environment snapshot
SB_PRINT_ENV=1 cargo run -p app -- run -c CONFIG
```

See [docs/ENV_VARS.md](../docs/ENV_VARS.md) for complete list.

---

## 🗂️ Miscellaneous / 杂项

**Directory:** `misc/`

Additional helper files and legacy examples:

- `chaos.profiles.json` - Chaos testing profiles
- `dns_pool_example.env` - DNS pool environment variables
- `targets.sample.txt` - Target list examples
- `tuic_example.json` - TUIC legacy example
- `subs.*.json` - Subscription examples

---

## 🧪 Rules & Templates / 规则与模板

**Directory:** `rules/`

Pre-made routing rule sets:

### Basic Rules

- `basic-router.rules` - Minimal rule set example

### Rule Snippets

`rules/snippets/`

- `block_ads.dsl` - Ad blocking rules

### Templates (Coming Soon)

`rules/templates/`

- Home network rules
- Office network rules
- Travel mode rules

---

## 💡 Tips & Best Practices

### Configuration Tips

1. **Start Simple**: Begin with `quick-start/01-minimal.yaml`
2. **Enable Logging**: Always use `RUST_LOG=info` during development
3. **Validate First**: Use `check` command before running
4. **Test Routing**: Use `route --explain` to debug routing decisions

### Performance Tips

1. **FakeIP**: Use FakeIP DNS for lower latency (see `configs/dns/fakeip.json`)
2. **URLTest**: Enable auto-failover for reliability (see `configs/outbounds/urltest.json`)
3. **Process Matching**: On macOS/Windows, native process matching is 20-150x faster

### Security Tips

1. **TLS Verification**: Never use `skip_cert_verify` in production
2. **Strong Passwords**: Use long random passwords for Shadowsocks/Trojan
3. **REALITY**: Prefer REALITY over standard TLS for better camouflage
4. **JWT Auth**: Enable JWT authentication for admin API (see [docs/ADMIN_API_CONTRACT.md](../docs/ADMIN_API_CONTRACT.md))

---

## 🔗 Related Documentation

- [Architecture](../docs/ARCHITECTURE.md) - System architecture overview
- [Router Rules](../docs/ROUTER_RULES.md) - Routing engine details
- [Environment Variables](../docs/ENV_VARS.md) - All environment variables
- [Cookbook](../docs/COOKBOOK.md) - Recipes and FAQ
- [Development](../docs/DEVELOPMENT.md) - Development guide

---

## 📞 Getting Help

- **Issues**: Found a bug? [Open an issue](../../issues)
- **Questions**: Check [docs/COOKBOOK.md](../docs/COOKBOOK.md) first
- **Contributing**: See [docs/DEVELOPMENT.md](../docs/DEVELOPMENT.md)

---

## 📜 License

All examples are provided under the same license as singbox-rust.

---

**Last Updated**: 2026-01-01  
**Examples Version**: v0.2.0+
