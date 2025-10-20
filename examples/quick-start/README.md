# Quick Start Examples / 快速入门示例

These minimal examples help you get started with singbox-rust in minutes.

这些最小化示例帮助您在几分钟内开始使用 singbox-rust。

---

## 📚 Examples

### 1. Minimal Configuration - `01-minimal.yaml`

**Description**: The absolute minimum configuration - HTTP inbound with direct outbound.

**最简单的配置** - HTTP 入站 + 直连出站。

```bash
# Run
cargo run -p app -- run -c examples/quick-start/01-minimal.yaml

# Test
curl -x http://127.0.0.1:28090 https://example.com
```

**Use Case**: Testing, learning basics, temporary proxy.

---

### 2. SOCKS5 Direct - `02-socks5-direct.yaml`

**Description**: SOCKS5 proxy with direct connection.

**SOCKS5 代理** + 直连。

```bash
# Run
cargo run -p app -- run -c examples/quick-start/02-socks5-direct.yaml

# Test
curl -x socks5://127.0.0.1:1080 https://example.com
```

**Use Case**: Basic SOCKS5 proxy for local testing.

---

### 3. HTTP Proxy - `03-http-proxy.yaml`

**Description**: HTTP proxy with basic routing rules.

**HTTP 代理** + 基础路由规则。

```bash
# Run
cargo run -p app -- run -c examples/quick-start/03-http-proxy.yaml

# Test
curl -x http://127.0.0.1:8080 https://example.com
```

**Features**:

- Direct connection for `.cn` domains
- Basic routing rules

---

### 4. Mixed Inbound - `04-mixed-inbound.yaml`

**Description**: Single port accepting both SOCKS5 and HTTP protocols.

**混合入站** - 单端口同时接受 SOCKS5 和 HTTP。

```bash
# Run
cargo run -p app -- run -c examples/quick-start/04-mixed-inbound.yaml

# Test SOCKS5
curl -x socks5://127.0.0.1:1080 https://example.com

# Test HTTP
curl -x http://127.0.0.1:1080 https://example.com
```

**Features**:

- Dual-protocol support on one port
- Ad/tracker blocking
- Private network routing

**Use Case**: Versatile local proxy.

---

### 5. Basic Routing - `05-basic-routing.yaml`

**Description**: Demonstrates core routing capabilities.

**基础路由** - 展示核心路由能力。

```bash
# Run
cargo run -p app -- run -c examples/quick-start/05-basic-routing.yaml

# Explain routing
cargo run -p app -- route \
  -c examples/quick-start/05-basic-routing.yaml \
  --dest ads.example.com:443 --explain
```

**Features**:

- Domain suffix matching
- CIDR-based routing
- Port-based rules
- Transport-specific rules

**Use Case**: Learning routing concepts.

---

## 🔧 Configuration Tips

### Enable Logging

```bash
RUST_LOG=info cargo run -p app -- run -c CONFIG.yaml
```

### Validate Configuration

```bash
cargo run -p app -- check -c CONFIG.yaml
```

### JSON Format Output

```bash
cargo run -p app -- check -c CONFIG.yaml --format json
```

---

## 🚀 Next Steps

Once you're comfortable with these examples:

1. **Explore Protocols**: Check `../configs/inbounds/` and `../configs/outbounds/`
2. **Advanced Routing**: See `../configs/routing/`
3. **DNS Configuration**: Review `../configs/dns/`
4. **Production Setups**: Study `../configs/advanced/`

---

## 📖 Related Documentation

- [Main Examples README](../README.md)
- [Routing Rules](../../docs/ROUTER_RULES.md)
- [Environment Variables](../../docs/ENV_VARS.md)
- [Cookbook](../../docs/COOKBOOK.md)

---

**Tip**: Always start with the smallest example that meets your needs, then add features incrementally!
