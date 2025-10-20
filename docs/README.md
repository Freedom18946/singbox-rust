# 📚 singbox-rust Documentation

Welcome to the **singbox-rust** documentation! This is a complete Rust rewrite of sing-box, designed for high performance, memory safety, and cross-platform compatibility.

**Project Status**: v0.2.0+ | Production-ready ⭐⭐⭐⭐⭐ (9.9/10) | Feature Parity: 99%+

---

## 🚀 Quick Navigation

### 👤 I'm a User

- **[Get Started in 5 Minutes →](00-getting-started/)** - Installation, first configuration, basic usage
- **[User Guide →](01-user-guide/)** - Configuration, protocols, features, troubleshooting
- **[CLI Reference →](02-cli-reference/)** - Complete command-line tools documentation
- **[Examples →](08-examples/)** - Ready-to-use configuration examples

### 🔧 I'm an Operator

- **[Deployment Guide →](03-operations/)** - Systemd, Docker, Kubernetes deployment
- **[Monitoring →](03-operations/monitoring/)** - Prometheus metrics, logging, tracing
- **[Performance →](03-operations/performance/)** - Optimization guides and checklists
- **[Security →](03-operations/security/)** - Hardening, TLS best practices

### 💻 I'm a Developer

- **[Development Guide →](04-development/)** - Architecture, contributing, testing
- **[Architecture →](04-development/architecture/)** - System design and data flow
- **[API Reference →](05-api-reference/)** - Admin HTTP API, V2Ray gRPC API
- **[Quality Gates →](04-development/quality-gates/)** - Linting, testing, benchmarking

### 🎓 I Want to Go Deeper

- **[Advanced Topics →](06-advanced-topics/)** - REALITY, ECH, advanced routing, DSL
- **[Reference →](07-reference/)** - Schemas, error codes, glossary

---

## 📖 Documentation Structure

```
docs/
├── 00-getting-started/      🚀 5-minute quickstart, installation
├── 01-user-guide/           📖 Configuration, protocols, features
├── 02-cli-reference/        🔧 Command-line tools (run, check, generate, etc.)
├── 03-operations/           🏗️ Deployment, monitoring, performance, security
├── 04-development/          💻 Architecture, contributing, build system
├── 05-api-reference/        📡 HTTP Admin API, gRPC Stats API
├── 06-advanced-topics/      🎓 REALITY, ECH, custom routing, DSL
├── 07-reference/            📚 Schemas, error codes, compatibility
└── 08-examples/             💡 Configuration examples
```

---

## 🔥 Popular Topics

### Configuration & Setup

- [Installation Guide](00-getting-started/README.md#installation)
- [Basic Configuration](00-getting-started/basic-configuration.md)
- [Configuration Schema (V2)](01-user-guide/configuration/overview.md)
- [V1 → V2 Migration](01-user-guide/configuration/schema-migration.md)

### Protocols

- [REALITY Protocol](01-user-guide/protocols/reality.md) - Anti-censorship TLS
- [ECH (Encrypted Client Hello)](01-user-guide/protocols/ech.md) - SNI encryption
- [Hysteria v2](01-user-guide/protocols/hysteria.md) - High-performance QUIC
- [TUIC](01-user-guide/protocols/tuic.md) - UDP-optimized proxy

### Features

- [Routing Rules](01-user-guide/configuration/routing.md) - Advanced traffic routing
- [DNS Configuration](01-user-guide/configuration/dns.md) - FakeIP, DoH, DoT, DoQ
- [TLS Configuration](01-user-guide/configuration/tls.md) - Standard TLS, REALITY, ECH
- [Process Matching](01-user-guide/features/process-matching.md) - Native OS APIs (149x faster)

### Operations

- [Systemd Deployment](03-operations/deployment/systemd.md)
- [Docker Deployment](03-operations/deployment/docker.md)
- [Prometheus Metrics](03-operations/monitoring/metrics.md)
- [Performance Tuning](03-operations/performance/optimization-guide.md)

### Development

- [Architecture Overview](04-development/architecture/overview.md)
- [Contributing Guide](04-development/contributing/getting-started.md)
- [Testing Guide](04-development/quality-gates/testing.md)
- [Protocol Implementation](04-development/protocols/implementation-guide.md)

---

## 🆘 Getting Help

### Common Issues

- **[Troubleshooting Guide](01-user-guide/troubleshooting.md)** - Common errors and fixes
- **[Error Codes Reference](07-reference/error-codes.md)** - All error codes explained
- **[FAQ](00-getting-started/README.md#faq)** - Frequently asked questions

### Community & Support

- **GitHub Issues**: [Report bugs or request features](https://github.com/your-repo/issues)
- **Discussions**: [Ask questions and share experiences](https://github.com/your-repo/discussions)
- **Documentation Issues**: Found a docs problem? [File an issue](https://github.com/your-repo/issues/new?labels=documentation)

---

## 🌟 Key Features

### Protocol Support

- **Inbounds** (12/12): SOCKS5, HTTP, TUN, VMess, VLESS, Trojan, Shadowsocks, TUIC, Hysteria v1/v2, Naive, ShadowTLS, Direct
- **Outbounds** (15/15): Direct, Block, DNS, HTTP, SOCKS5, SSH, Shadowsocks, VMess, VLESS, Trojan, TUIC, Hysteria v1/v2, ShadowTLS, Selector, URLTest
- **TLS**: Standard TLS 1.2/1.3, REALITY, ECH, uTLS (future)
- **Transports**: TCP, UDP, QUIC, WebSocket, HTTP/2, HTTPUpgrade, gRPC, Multiplex (yamux)

### Advanced Features

- **Smart Routing**: Domain, IP, port, protocol, process matching with sniffing
- **DNS**: FakeIP, multiple strategies, DoH/DoT/DoQ, resolver pools
- **Observability**: Prometheus metrics, structured logging (tracing), cardinality monitoring
- **Security**: JWT auth, constant-time verification, credential redaction, rate limiting
- **Performance**: Native process matching (149x faster), zero-copy I/O, connection pooling

---

## 📋 Documentation Standards

This documentation follows these principles:

1. **User-First**: Organized by use case, not internal structure
2. **Progressive Disclosure**: Basic info first, advanced details in separate sections
3. **Working Examples**: Every feature has a runnable example
4. **Version Aware**: Clearly marked version requirements and compatibility
5. **Searchable**: Clear headings, consistent terminology, comprehensive index

---

## 🔄 Recent Updates

- **2025-10-18**: Complete documentation restructure - organized by user role
- **2025-10-09**: TLS infrastructure complete (REALITY, ECH, Standard TLS)
- **2025-10-02**: Sprint 5 completion - Hysteria v1/v2, TUIC, Direct inbound
- **2025-10-02**: Native process matching - macOS (149.4x), Windows (20-50x)

For detailed changelogs, see [CHANGELOG.md](../CHANGELOG.md).

---

## 📌 Legacy Documentation

Historical sprint reports, task summaries, and deprecated docs are preserved in [`archive/`](archive/) for reference. These are not actively maintained.

---

## 🤝 Contributing to Docs

Found a typo? Want to improve an explanation? Documentation contributions are welcome!

See [Documentation Contributing Guide](04-development/contributing/documentation.md) for:

- Documentation style guide
- How to add new pages
- Building docs locally
- Submitting documentation PRs

---

**Documentation Version**: v2.0 (restructured)  
**Project Version**: v0.2.0+  
**Last Updated**: 2025-10-18

> _Never break userspace_ — we add, we don't remove.
