# singbox-rust

A pragmatic rewrite path for sing-box in Rust. Focused on **good taste**, **never break userspace**, and **boring clarity**.

> **🚀 Production Ready**: **88% Parity** with upstream sing-box 1.12.14 (183/209 items aligned).
> See [GO_PARITY_MATRIX.md](GO_PARITY_MATRIX.md) for detailed feature matrix and [NEXT_STEPS.md](NEXT_STEPS.md) for milestones.

---

## 🤖 AI/Agent/LLM 必读（Required for AI Assistants）

> **如果你是 AI 助手、Agent、LLM 或 CLI 工具**：必须首先查阅 [`agents-only/`](./agents-only/) 目录。
>
> 该目录包含整合后的需求分析、验收标准和架构规范，是 AI 工作的**唯一真相来源**。

### 🚨 强制执行
| 文档 | 要求 |
|------|------|
| [`init.md`](./agents-only/init.md) | **必须首先执行** - AI 初始化检查 |
| [`log.md`](./agents-only/log.md) | **任务结束前必须写入** - AI 行为日志 |

### 📚 参考文档
| 文档 | 内容 |
|------|------|
| [`05-USER-ABSTRACT-REQUIREMENTS.md`](./agents-only/05-USER-ABSTRACT-REQUIREMENTS.md) | 用户抽象需求 |
| [`06-STRATEGIC-ROADMAP.md`](./agents-only/06-STRATEGIC-ROADMAP.md) | 战略路线图 |
| [`01-REQUIREMENTS-ANALYSIS.md`](./agents-only/01-REQUIREMENTS-ANALYSIS.md) | 需求分析 |
| [`02-ACCEPTANCE-CRITERIA.md`](./agents-only/02-ACCEPTANCE-CRITERIA.md) | 验收标准 |
| [`03-ARCHITECTURE-SPEC.md`](./agents-only/03-ARCHITECTURE-SPEC.md) | 架构规范 |
| [`04-IMPLEMENTATION-GUIDE.md`](./agents-only/04-IMPLEMENTATION-GUIDE.md) | 实现指南 |

---

## 🚨 IMPORTANT: Authoritative Navigation Document

**⚠️ Developer Must-Read: Before starting any development work, you must read and verify [`agents-only/08-PROJECT-STRUCTURE.md`](./agents-only/08-PROJECT-STRUCTURE.md).**

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
- **[User Guide](docs/01-user-guide/README.md)** - Configuration and usage overview
- **[DNS Configuration](docs/01-user-guide/configuration/dns.md)** - DNS strategies and FakeIP
- **[TLS Configuration](docs/01-user-guide/configuration/tls.md)** - REALITY, ECH, Standard TLS

### 🛠️ [Operations](docs/03-operations/)
- **[Operations Overview](docs/03-operations/README.md)** - Deployment and runtime notes
- **[Monitoring](docs/03-operations/monitoring/grafana-dashboards.md)** - Grafana dashboards
- **[Troubleshooting](docs/TROUBLESHOOTING.md)** - Common issues & fixes

### 💻 [Development](docs/04-development/)
- **[Development Guide](docs/04-development/README.md)** - Development notes and workflows
- **[Transport Defaults](docs/04-development/transport-defaults.md)** - Transport inference behavior
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

### 🚀 Performance
- **Native Process Matching**: 149x faster on macOS than Go implementation
- **Zero-Copy Parsing**: Minimal allocations in hot paths
- **Memory Safe**: No GC pauses, predictable footprint

### 🔐 Security & TLS
- **REALITY Protocol**: Anti-censorship TLS fingerprinting
- **ECH (Encrypted Client Hello)**: SNI encryption
- **uTLS Fingerprinting**: 27+ browser fingerprints (Chrome, Firefox, Safari, Edge)
- **ACME Auto-Renewal**: Let's Encrypt/ZeroSSL with HTTP-01/DNS-01 challenges

### 🌐 Protocols (36 Total)
| Inbound | Outbound | Transport |
| --- | --- | --- |
| SOCKS (4/5), HTTP | Shadowsocks, VMess | WebSocket, gRPC |
| Shadowsocks, Trojan | VLESS, Trojan | HTTP Upgrade |
| VMess, VLESS | Hysteria2, TUIC | QUIC, TCP, UDP |
| Hysteria2, TUIC | WireGuard, SSH | REALITY, ECH |
| WireGuard, TUN | Direct, Block | simple-obfs |

### 📊 Observability
- **Prometheus Metrics**: Connection counts, latency histograms
- **Clash/V2Ray API**: Traffic stats and rule management
- **Circuit Breaker**: Automatic failure detection and recovery

### 🔗 Advanced
- **Smart Routing**: 38 rule types (domain, GeoIP, process, user, etc.)
- **DERP Mesh**: Tailscale relay for cross-region connectivity
- **Hot Reload**: Live config updates via Admin API

> 📖 **[Rust-Only Enhancements](docs/RUST_ENHANCEMENTS.md)** - Features beyond Go parity

---

## Community & Support

- **[Project Status](docs/STATUS.md)**: Check current version and roadmap.
- **[Issues](https://github.com/your-repo/issues)**: Report bugs.
- **[Discussions](https://github.com/your-repo/discussions)**: Ask questions and share configs.

---

*For detailed navigation of the project structure, see [PROJECT_STRUCTURE_NAVIGATION.md](PROJECT_STRUCTURE_NAVIGATION.md).*
