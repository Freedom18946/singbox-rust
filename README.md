# singbox-rust

A pragmatic rewrite path for sing-box in Rust. Focused on **good taste**, **never break userspace**, and **boring clarity**.

> **🚀 Production Ready**: 100% Protocol Parity with upstream sing-box 1.12.12.
> See [Project Status](docs/STATUS.md) for detailed feature matrix and milestones.

---

## 🚨 IMPORTANT: Authoritative Navigation Document

**⚠️ Developer Must-Read: Before starting any development work, you must read and verify [`PROJECT_STRUCTURE_NAVIGATION.md`](./PROJECT_STRUCTURE_NAVIGATION.md).**

- 📋 **Authoritative**: This document is the *sole* source of truth for project structure.
- 🔄 **Update Responsibility**: Any developer modifying the project structure MUST sync this document.
- ✅ **Verification**: New developers or AI assistants must verify this document's accuracy before work.
- 📍 **Navigation First**: All development activities should trace paths based on this document.

---

## 📚 Documentation

Visit our comprehensive documentation portal at **[docs/](docs/)**:

### 🚀 [Getting Started](docs/00-getting-started/)
- **[Quick Start Guide](docs/00-getting-started/README.md)** - Get up and running in 5 minutes
- **[Basic Configuration](docs/00-getting-started/basic-configuration.md)** - Understand the config file
- **[Your First Proxy](docs/00-getting-started/first-proxy.md)** - Connect to an upstream server

### 📖 [User Guide](docs/01-user-guide/)
- **[Configuration Reference](docs/01-user-guide/configuration/overview.md)** - Full config schema
- **[Protocol Support](docs/01-user-guide/README.md#protocol-support)** - Inbound/Outbound protocols (Shadowsocks, Trojan, VMess, VLESS, Hysteria, etc.)
- **[Routing](docs/01-user-guide/configuration/routing.md)** - Smart routing by domain, IP, process
- **[TLS & Anti-Censorship](docs/01-user-guide/configuration/tls.md)** - REALITY, ECH, Standard TLS

### 🛠️ [Operations](docs/03-operations/)
- **[Deployment](docs/03-operations/README.md#deployment-patterns)** - Systemd, Docker, Kubernetes
- **[Monitoring](docs/03-operations/monitoring/metrics.md)** - Prometheus metrics & Grafana
- **[Troubleshooting](docs/03-operations/README.md#troubleshooting)** - Common issues & fixes

### 💻 [Development](docs/04-development/)
- **[Architecture](docs/04-development/architecture.md)** - System design & modules
- **[Contribution Guide](docs/04-development/contributing.md)** - How to contribute
- **[Migration Guide](docs/MIGRATION_GUIDE.md)** - Go to Rust migration details

---

## Quick Start

Build the full-featured binary:

```bash
cargo +1.90 build -p app --features "acceptance,manpage" --release
./target/release/app version
```

Run with a config:

```bash
./target/release/app run -c config.json
```

See [Getting Started](docs/00-getting-started/) for detailed instructions.

---

## Key Features

- **High Performance**: Native process matching (149x faster on macOS), zero-copy parsing, linear scaling.
- **Memory Safe**: Written in Rust for stability and security.
- **Full Parity**: Supports all 36 protocols from sing-box (Shadowsocks, Trojan, VMess, VLESS, Hysteria, TUIC, etc.).
- **Advanced TLS**: REALITY, ECH, and Standard TLS 1.3 support.
- **Mesh Networking**: Built-in DERP service for cross-region relay.
- **Observability**: Comprehensive Prometheus metrics and tracing.

---

## Community & Support

- **[Project Status](docs/STATUS.md)**: Check current version and roadmap.
- **[Issues](https://github.com/your-repo/issues)**: Report bugs.
- **[Discussions](https://github.com/your-repo/discussions)**: Ask questions and share configs.

---

*For detailed navigation of the project structure, see [PROJECT_STRUCTURE_NAVIGATION.md](PROJECT_STRUCTURE_NAVIGATION.md).*
