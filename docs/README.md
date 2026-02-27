# 📚 singbox-rust Documentation

Welcome to the **singbox-rust** documentation! This is a complete Rust rewrite of sing-box, designed for high performance, memory safety, and cross-platform compatibility.

**Project Status**: v0.2.0+ | Release-ready candidate | Feature Parity: 100% acceptance baseline (209/209 closed) vs sing-box 1.12.14

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
- **[Environment Toggles →](03-operations/env-toggles.md)** - Runtime flags and env overrides
- **[Transport Fallback →](03-operations/transport-fallback.md)** - Fallback behavior and guidance
- **[Data Pipeline →](03-operations/data-pipeline.md)** - Metrics and data flow overview

### 💻 I'm a Developer

- **[Development Guide →](04-development/)** - Architecture, contributing, and build system
- **[Architecture Overview →](04-development/architecture/overview.md)** - System design and data flow
- **[Contributing →](04-development/contributing/getting-started.md)** - Dev setup and workflow
- **[Quality Gates →](04-development/quality-gates/testing.md)** - Linting, testing, benchmarking
- **[API Reference →](05-api-reference/)** - Admin HTTP API, V2Ray gRPC API

### 🎓 I Want to Go Deeper

- **[Advanced Topics →](06-advanced-topics/)** - REALITY, ECH, advanced routing, DSL
- **[Reference →](07-reference/)** - Schemas, error codes, glossary
- **[Migration Guide (L17 Entry) →](migration-from-go.md)** - Current migration entry and accepted limitations
- **[Configuration Reference (L17 Entry) →](configuration.md)** - Top-level configuration domains
- **[Troubleshooting (L17 Entry) →](troubleshooting.md)** - Release-readiness triage

---

## 📖 Documentation Structure

```
docs/
├── 00-getting-started/      🚀 5-minute quickstart, installation
├── 01-user-guide/           📖 Configuration and usage
├── 02-cli-reference/        🔧 Command-line tools (run, check, generate, etc.)
├── 03-operations/           🏗️ Deployment, monitoring, runtime toggles
├── 04-development/          💻 Architecture, contributing, build system
├── 05-api-reference/        📡 HTTP Admin API, gRPC Stats API
├── 06-advanced-topics/      🎓 REALITY, ECH, custom routing, DSL
├── 07-reference/            📚 Schemas, error codes, compatibility
├── 08-examples/             💡 Configuration examples
├── archive/                 🗃️ Historical docs
├── examples/                🧪 YAML example configs
├── protocols/               🧩 Protocol notes (placeholder)
└── testing/                 ✅ Testing guide
```

---

## Subsection Indexes

### User Guide

- [Configuration Index](01-user-guide/configuration/README.md)
- [Protocols Index](01-user-guide/protocols/README.md)
- [Features Index](01-user-guide/features/README.md)

### Operations

- [Deployment Index](03-operations/deployment/README.md)
- [Monitoring Index](03-operations/monitoring/README.md)
- [Performance Index](03-operations/performance/README.md)
- [Security Index](03-operations/security/README.md)

### Development

- [Architecture Index](04-development/architecture/README.md)
- [Contributing Index](04-development/contributing/README.md)
- [Build System Index](04-development/build-system/README.md)
- [Quality Gates Index](04-development/quality-gates/README.md)
- [Protocols Index](04-development/protocols/README.md)

### API Reference

- [Admin API](05-api-reference/admin-api/README.md)
- [V2Ray Stats API](05-api-reference/v2ray-stats/README.md)
- [Internal APIs](05-api-reference/internal/README.md)

### Reference

- [Schemas Index](07-reference/schemas/README.md)

### Examples

- [Basic Examples](08-examples/basic/README.md)
- [Advanced Examples](08-examples/advanced/README.md)
- [DNS Examples](08-examples/dns/README.md)
- [Transport Examples](08-examples/transport/README.md)

---

## 🔥 Popular Topics

### Configuration & Setup

- [Quick Start](00-getting-started/README.md)
- [Basic Configuration](00-getting-started/basic-configuration.md)
- [Your First Proxy](00-getting-started/first-proxy.md)
- [User Guide](01-user-guide/README.md)
- [Migration Guide](MIGRATION_GUIDE.md)

### Networking & TLS

- [TLS Configuration](01-user-guide/configuration/tls.md)
- [DNS Configuration](01-user-guide/configuration/dns.md)
- [UDP Support](UDP_SUPPORT.md)
- [Transport Strategy](TRANSPORT_STRATEGY.md)
- [Transport Mapping](TRANSPORT_MAPPING.md)
- [TLS Decision](TLS_DECISION.md)

### Features

- [DNS Configuration](01-user-guide/configuration/dns.md)
- [TLS Configuration](01-user-guide/configuration/tls.md)
- [Transport Defaults](04-development/transport-defaults.md)
- [Rate Limiting](RATE_LIMITING.md)
- [Metrics Catalog](METRICS_CATALOG.md)

### Operations

- [Operations Overview](03-operations/README.md)
- [Deployment Guide](DEPLOYMENT_GUIDE.md)
- [Environment Toggles](03-operations/env-toggles.md)
- [Grafana Dashboards](03-operations/monitoring/grafana-dashboards.md)
- [Transport Fallback](03-operations/transport-fallback.md)

### Development

- [Development Guide](04-development/README.md)
- [Architecture Overview](04-development/architecture/overview.md)
- [Contributing](04-development/contributing/getting-started.md)
- [Build System](04-development/build-system/overview.md)
- [Quality Gates](04-development/quality-gates/testing.md)

---

## 🆘 Getting Help

### Common Issues

- **[Troubleshooting Guide](troubleshooting.md)** - Common errors and fixes
- **[User Guide](01-user-guide/README.md)** - Configuration and usage reference
- **[Deployment Checklist](DEPLOYMENT_CHECKLIST.md)** - Preflight ops checklist

### Community & Support

- **GitHub Issues**: [Report bugs or request features](https://github.com/your-repo/issues)
- **Discussions**: [Ask questions and share experiences](https://github.com/your-repo/discussions)
- **Documentation Issues**: Found a docs problem? [File an issue](https://github.com/your-repo/issues/new?labels=documentation)

---

## 🌟 Key Features

### Protocol Support

- **Inbounds** (18/18, Go protocols): SOCKS5, HTTP, Mixed, Direct, DNS, TUN, Redirect, TProxy, Shadowsocks, VMess, VLESS, Trojan, Naive, ShadowTLS, AnyTLS, Hysteria v1, Hysteria v2, TUIC
- **Outbounds** (19/19): Direct, Block, DNS, HTTP, SOCKS5, SSH, Shadowsocks, VMess, VLESS, Trojan, ShadowTLS, TUIC, Hysteria v1, Hysteria v2, Tor, AnyTLS, WireGuard, Selector, URLTest
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

- **2026-02-26**: L18 daily convergence reached same-config 3-round continuous PASS in `capstone_daily_convergence_v7_timeout120` (`r1/r2/r3` all PASS; `gui/canary/dual/perf` all PASS; GUI `/proxies` Go/Rust both `200`); baseline dual run `20260226T015945Z-daily-dc0b3935` remained clean (`run_fail_count=0`, `diff_fail_count=0`)
- **2026-02-25**: L18 daily convergence reruns completed with strict artifact isolation under `reports/l18/batches/20260225T134935Z-l18-daily-converge-v4`; `v5` identified `gui_smoke` flake (Rust readiness), and `v6b_timeout120/r1` verified mitigation (`L18_GUI_TIMEOUT_SEC=120`) with full PASS and `/proxies` Go/Rust both `200`
- **2026-02-24**: L17 capstone fast rerun completed with `overall=PASS_STRICT`; optional environment gates recorded as `SKIP` (`docker/gui_smoke/canary`) in `reports/stability/l17_capstone_status.json`
- **2026-02-24**: Parity baseline updated to 209/209 closed (acceptance baseline); PX-015 Linux runtime evidence no longer tracked as open blocker
- **2026-02-12**: Added L17 entry docs (`configuration.md`, `migration-from-go.md`, `troubleshooting.md`) and release-readiness workflows/scripts
- **2026-01-07**: Historical parity snapshot at 88% (183/209) vs sing-box 1.12.14
- **2025-11-23**: 100% protocol coverage achieved (Go 1.12.12 baseline, 历史基线) - 17/17 inbound, 19/19 outbound
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

See the documentation guide for structure and link hygiene tips: [Documentation Guide](04-development/contributing/documentation.md).

---

**Documentation Version**: v2.0 (restructured)  
**Project Version**: v0.2.0+  
**Last Updated**: 2026-02-26

> _Never break userspace_ — we add, we don't remove.
