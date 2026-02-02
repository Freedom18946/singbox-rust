# User Guide

Complete guide to configuring and using singbox-rust.
Configuration accepts a small set of Go-compatible aliases; see the configuration overview for details.

---

## 📖 Documentation Sections

### Configuration

- **[Configuration Overview](configuration/overview.md)** - Schema and section layout
- **[Inbounds](configuration/inbounds.md)** - Listener configuration
- **[Outbounds](configuration/outbounds.md)** - Upstream configuration
- **[Routing](configuration/routing.md)** - Rule-based routing
- **[DNS Configuration](configuration/dns.md)** - DNS resolution and FakeIP
- **[TLS Configuration](configuration/tls.md)** - TLS, REALITY, ECH configuration
- **[Schema Migration](configuration/schema-migration.md)** - V1 → V2 migration
- **[Basic Configuration](../00-getting-started/basic-configuration.md)** - Minimal working config
- **[Your First Proxy](../00-getting-started/first-proxy.md)** - Single outbound setup

### Operations & CLI

- **[CLI Reference](../02-cli-reference/README.md)** - Command-line tools and flags
- **[Operations Overview](../03-operations/README.md)** - Deployment and runtime notes
- **[Troubleshooting](../TROUBLESHOOTING.md)** - Common issues and fixes

### Examples & Advanced

- **[Transport Planning Examples](../examples/README.md)** - Transport chain examples
- **[Advanced Topics](../06-advanced-topics/README.md)** - REALITY, ECH, routing patterns
- **[Reference](../07-reference/README.md)** - Schemas, error codes, glossary

### Protocols

- **[Protocol Index](protocols/README.md)** - All protocol notes
- **[Shadowsocks](protocols/shadowsocks.md)**
- **[Trojan](protocols/trojan.md)**
- **[VMess](protocols/vmess.md)**
- **[VLESS](protocols/vless.md)**
- **[Hysteria](protocols/hysteria.md)**
- **[TUIC](protocols/tuic.md)**

### Features

- **[Multiplex](features/multiplex.md)** - Connection multiplexing
- **[Transports](features/transports.md)** - WebSocket, HTTP/2, gRPC, HTTPUpgrade

### In-Progress Sections

These pages exist as initial stubs and will be expanded:

- Protocol guides (expand details and examples)
- Feature deep-dives (subscription and advanced routing)

---

## 🎯 Phase 1 Strategic Focus

**⚠️ Production-Ready Core Protocols for Initial Deployment**

This project's **Phase 1** release focuses exclusively on **Trojan** and **Shadowsocks** protocols for mature, production-ready deployment:

- ✅ **Trojan** (inbound + outbound) - TLS-based protocol with fallback
- ✅ **Shadowsocks** (inbound + outbound) - AEAD ciphers (AES-GCM, ChaCha20-Poly1305, AEAD-2022)

**All other protocols** are optional and feature-gated.

---

## Protocol Support (Summary)

### Inbound Protocols (18/18 Complete - 100% of Go protocols)

**Phase 1 Core**:
- Shadowsocks
- Trojan

**Optional (Feature-Gated)**:
- SOCKS5, HTTP, Mixed, Direct, DNS, TUN, Redirect, TProxy
- VMess, VLESS, TUIC, Hysteria v1/v2, Naive, ShadowTLS, AnyTLS

### Outbound Protocols (19/19 Complete - 100% of Go protocols)

**Phase 1 Core**:
- Shadowsocks
- Trojan

**Optional (Feature-Gated)**:
- Direct, Block, DNS, SOCKS5, HTTP/HTTPS, VMess, VLESS
- TUIC, Hysteria v1/v2, ShadowTLS, SSH, Tor, AnyTLS
- WireGuard, Selector, URLTest

---

## Quick Links

**Set up a basic proxy**
→ [Getting Started](../00-getting-started/README.md) → [Basic Configuration](../00-getting-started/basic-configuration.md)

**Add an upstream proxy server**
→ [Your First Proxy](../00-getting-started/first-proxy.md)

**Configure DNS**
→ [DNS Configuration](configuration/dns.md)

**Configure TLS**
→ [TLS Configuration](configuration/tls.md)

**Understand transport behavior**
→ [Transport Defaults](../04-development/transport-defaults.md) → [Transport Strategy](../TRANSPORT_STRATEGY.md)

**Troubleshoot common issues**
→ [Troubleshooting](../TROUBLESHOOTING.md)

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
   $ curl http://127.0.0.1:18088/__metrics
```

---

## Where to Go Next

- For advanced routing and transport behavior, see **[Advanced Topics](../06-advanced-topics/README.md)**.
- For deployment and runtime operations, see **[Operations](../03-operations/README.md)**.
- For testing and verification, see **[Testing Guide](../testing/TESTING_GUIDE.md)**.
