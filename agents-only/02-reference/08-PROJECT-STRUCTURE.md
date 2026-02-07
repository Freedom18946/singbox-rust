# 项目结构导航（Project Structure Navigation）

> **位置**：已迁移至 `agents-only/08-PROJECT-STRUCTURE.md`
> **最后更新**：2026-02-07
>
> 此文档是项目结构的权威参考。AI 初始化时需验证结构一致性。

## Project Overview

SingBox-Rust is a high-performance proxy server implementation designed with a modular architecture, supporting multiple protocols and routing strategies.

## Root Directory Structure

```
singbox-rust/
├── 📁 .cache/           # Local cache artifacts (gitignored)
├── 📁 .cargo/           # Cargo configuration (build parameters, aliases, etc.)
├── 📁 .claude/          # Local assistant artifacts (gitignored)
├── 📁 .e2e/             # E2E test artifacts and summaries
├── 📁 .github/          # GitHub workflows and templates
├── 📁 app/              # Main application and multi-bin CLI (feature gated)
├── 📁 benches/          # Benchmark workspace
├── 📁 benchmark_results/# Benchmark results
├── 📁 configs/          # Local/dev configs and test configs
├── 📁 crates/           # Core crate modules workspace
├── 📁 deployment/       # Deployment configurations and scripts
├── 📁 deployments/      # Deployment examples (Docker/K8s/Systemd)
├── 📁 docs/             # Documentation portal (00-.. sections)
├── 📁 examples/         # Examples and configurations
├── 📁 fuzz/             # Fuzz testing
├── 📁 go_fork_source/   # Go reference implementation source
├── 📁 grafana/          # Monitoring dashboards
├── 📁 LICENSES/         # Dependency licenses
├── 📁 SPECS/            # Specifications and design notes
├── 📁 reports/          # Reports and baselines
│   ├── 📄 ACCEPTANCE_QC_2025-11-24.md
│   ├── 📄 GO_DIFF_ANALYSIS_2026-01-31.md
│   ├── 📄 PERFORMANCE_REPORT.md
│   ├── 📄 README.md
│   ├── 📁 stress-tests
│   ├── 📄 TEST_COVERAGE.md
│   └── 📄 VERIFICATION_RECORD.md
├── 📁 scripts/          # CI, tools, scenario scripts
├── 📁 tools/            # Internal tooling (depcheck, deny)
├── 📁 target/           # Local build output (gitignored)
├── 📁 tests/            # Tests (Integration/E2E/Configs/Data etc.)
├── 📁 vendor/           # Vendor dependency overrides (e.g., tun2socks)
├── 📁 xtask/            # Development/Release helper tasks
├── 📁 xtests/           # Extended testing tools
├── 📄 BASELINE_UPSTREAM.env  # Upstream baseline pins
├── 📄 Cargo.toml        # Workspace manifest
├── 📄 Cargo.lock        # Lock file
├── 📄 CHANGELOG.md      # Project changelog
├── 📄 config.yaml       # Default/local config
├── 📄 Dockerfile        # Container build file
├── 📄 GO_PARITY_MATRIX.md  # Parity matrix with sing-box
├── 📄 minimal.yaml      # Minimal config example
├── 📁 agents-only/      # AI 专用文档（需求分析、验收标准、战略规划）
├── 📄 .gitignore        # Git ignore rules
├── 📄 .gitmodules       # Git submodule configuration
├── 📄 public-api-baseline.txt # Public API baseline
├── 📄 README.md         # Project description and quick start
├── 📄 SECURITY.md       # Security instructions
├── 📄 smoke-test.sh     # Quick smoke test runner
├── 📄 test_config.json  # Local test config
├── 📄 USAGE.md          # CLI usage reference
├── 📄 VERIFICATION_RECORD.md # Top-level verification record
└── 📄 Others: deny.toml, clippy.toml, rust-toolchain.toml, Makefile.fuzz etc.
```

## Core Module Architecture (crates/)

### 🏗️ Architecture Hierarchy

```
crates/
├── sb-core/            # 🔧 Core: Routing engine, DNS, NAT, Inbound/Outbound abstractions
├── sb-common/          # 🧩 Common: Shared helpers and utilities
├── sb-config/          # ⚙️ Config: Parsing, Schema/IR
├── sb-adapters/        # 🔌 Adapters: Protocol implementations (VMess/VLESS/Trojan/SS/TUIC/Hysteria etc.)
├── sb-transport/       # 🚀 Transport: TCP/UDP/WS/H2/H3/Upgrade/Multiplex
├── sb-tls/             # 🔐 TLS: Standard/REALITY/ECH
├── sb-metrics/         # 📊 Metrics: Prometheus integration
├── sb-runtime/         # ⚡ Runtime: Task/Resource/IO management
├── sb-platform/        # 🖥️ Platform: Syscalls and platform-specific features
├── sb-proto/           # 📡 Proto: Protocols and common types
├── sb-security/        # 🛡️ Security: JWT, credential redaction
├── sb-api/             # 🌐 External API (V2Ray/Clash)
├── sb-subscribe/       # 📥 Subscribe: Remote rules and nodes
├── sb-admin-contract/  # 🧾 Admin Contract (admin_envelope)
├── sb-test-utils/      # 🧪 Test Utils and fixtures
└── sb-types/           # 🧰 Workspace shared types
```

### 🎯 Module Responsibilities

| Module | Responsibilities | Key Components |
|--------|------------------|----------------|
| **sb-core** | Core functionality and abstractions | Routing engine, DNS system, UDP NAT, Error handling |
| **sb-config** | Configuration management | Schema validation, Config parsing, Error reporting |
| **sb-common** | Shared utilities | Common helpers, cross-crate glue |
| **sb-adapters** | Protocol adapters | VMess, VLESS, Hysteria v1/v2, TUIC, Trojan |
| **sb-transport** | Transport layer | TCP/UDP transport, WebSocket, HTTP/2, Multiplex |
| **sb-tls** | TLS infrastructure | Standard TLS, REALITY, ECH, uTLS (Planned) |
| **sb-metrics** | Monitoring metrics | Prometheus integration, Performance monitoring |
| **sb-runtime** | Runtime | Async task management, Lifecycle |
| **sb-platform** | Platform support | System calls, Platform-specific functions |
| **sb-proto** | Protocol definitions | Protocol structs, Serialization |
| **sb-security** | Security tools | JWT auth, Credential verification, Key management |
| **sb-api** | External API | V2Ray Stats, Clash API |
| **sb-subscribe** | Subscription service | Node subscription, Auto-update |

## Test Structure (tests/)

### 📋 Test Classification

```
tests/
├── integration/   # Integration tests
├── e2e/           # E2E orchestration/tools
├── stress/        # Stress/Stability verification
├── configs/       # Test configurations
├── data/          # Test data
├── scripts/       # Test scripts
├── docs/          # Test documentation
└── Top-level *.rs # Direct E2E/Integration tests (e.g., reality_tls_e2e.rs)
```

### 🧪 Test Type Description

- Integration Tests: `integration/` and root `tests/*.rs`
- End-to-End: `e2e/`
- Stress/Stability: `stress/`
- Configs/Data/Scripts/Docs: `configs/`, `data/`, `scripts/`, `docs/`

## Application Structure (app/)

```
app/
├── src/                 # Main entrypoint and subcommands (bin/*)
├── tests/               # App-level tests
├── benches/             # Benchmarks
├── examples/            # Usage examples
├── scripts/             # App-level scripts
├── build.rs             # Build-time meta info
└── Cargo.toml           # App config and feature gating
```

## Documentation Structure (docs/)

### 📚 Documentation Categories

```
docs/
├── 00-getting-started/        # Quick Start
├── 01-user-guide/             # User Guide/Configuration
├── 02-cli-reference/          # CLI Reference
├── 03-operations/             # Operations/Deployment
├── 04-development/            # Architecture, contributing, build system
├── 05-api-reference/          # API Reference
├── 06-advanced-topics/        # Advanced Topics (REALITY/ECH etc.)
├── 07-reference/              # Reference (Schema/Error Codes)
├── 08-examples/               # Examples
├── archive/                   # Historical Archive
├── examples/                  # YAML config examples
├── protocols/                 # Protocol notes (currently empty placeholder)
├── testing/                   # Testing guides
├── CLEANUP_COMPLETION_REPORT.md
├── DEPLOYMENT.md
├── DEPLOYMENT_CHECKLIST.md
├── DEPLOYMENT_GUIDE.md
├── DERP_USAGE.md
├── METRICS_CATALOG.md
├── MIGRATION_GUIDE.md
├── MIGRATION_GUIDE_M1.md
├── MOBILE_DECISION.md
├── RATE_LIMITING.md
├── README.md
├── REFACTORING_PROPOSAL.md
├── RESTRUCTURE_SUMMARY.md
├── RUST_ENHANCEMENTS.md
├── STATUS.md
├── TAILSCALE_DECISION.md
├── TAILSCALE_LIMITATIONS.md
├── TAILSCALE_RESEARCH.md
├── TEST_EXECUTION_SUMMARY.md
├── TLS_DECISION.md
├── TODO_AUDIT.md
├── TRANSPORT_MAPPING.md
├── TRANSPORT_STRATEGY.md
├── TROUBLESHOOTING.md
├── UDP_SUPPORT.md
├── walkthrough_aead_benchmarks.md
├── wireguard-endpoint-guide.md
└── wireguard-quickstart.md
```

### Development Docs (docs/04-development/)

```
docs/04-development/
├── architecture/        # Architecture notes
├── build-system/        # Workspace build configuration
├── contributing/        # Contribution workflow
├── quality-gates/       # Linting/testing/benchmarks
├── protocols/           # Protocol implementation notes
├── README.md            # Development guide index
└── transport-defaults.md
```

### User Guide (docs/01-user-guide/)

```
docs/01-user-guide/
├── configuration/       # DNS/TLS configuration
├── features/            # Feature stubs (multiplex/transports)
├── protocols/           # Protocol stubs
├── README.md            # User guide index
└── troubleshooting.md
```

### CLI Reference (docs/02-cli-reference/)

```
docs/02-cli-reference/
├── README.md            # CLI index
├── run.md               # Command pages
├── check.md
├── route-explain.md
├── format.md
├── merge.md
├── geoip-geosite.md
├── rule-set.md
├── generate.md
├── tools.md
├── completions.md
├── version.md
├── exit-codes.md
└── environment-variables.md
```

### Operations (docs/03-operations/)

```
docs/03-operations/
├── deployment/          # Systemd/Docker/K8s/Windows stubs
├── monitoring/          # Metrics/logging dashboards
├── performance/         # Optimization notes
├── security/            # Hardening and TLS practices
├── README.md            # Operations guide index
├── data-pipeline.md
├── env-toggles.md
└── transport-fallback.md
```

### API Reference (docs/05-api-reference/)

```
docs/05-api-reference/
├── admin-api/           # Admin HTTP API
├── v2ray-stats/         # gRPC stats API
├── internal/            # Internal API notes
└── README.md
```

### Reference (docs/07-reference/)

```
docs/07-reference/
├── schemas/             # Schema stubs
├── README.md
├── breaking-changes.md
├── compatibility-matrix.md
├── error-codes.md
├── feature-parity.md
└── glossary.md
```

### Examples (docs/08-examples/)

```
docs/08-examples/
├── basic/               # Basic configs
├── advanced/            # Advanced configs
├── dns/                 # DNS examples
├── transport/           # Transport examples
└── README.md
```

## Examples and Configuration (examples/)

```
examples/
├── configs/      # Configuration samples (minimal/advanced/...)
├── rules/        # Routing rule samples
├── scenarios/    # Running scenario scripts/configs
└── *.rs          # Rust example programs
```

## Scripts and Tools (scripts/)

### 🛠️ Script Classification

```
scripts/
├── ci/          # CI related scripts
├── dev/         # Local development helpers
├── e2e/         # E2E test orchestration
├── lib/         # Script shared libraries
├── lint/        # Quality gates/Static checks
├── test/        # Benchmark/Regression guardians etc.
├── tools/       # Tools and visualization scripts
├── run          # Single entrypoint runner (multi-scenario)
├── run-scenarios# Pre-defined scenario batch runner
└── scenarios.d/ # Scenario definition collection
```

## Development Environment Configuration

### 🔧 Configuration Files

| File | Purpose |
|------|---------|
| `Cargo.toml` | Workspace configuration |
| `rust-toolchain.toml` | Rust toolchain version |
| `clippy.toml` | Clippy configuration |
| `deny.toml` | Dependency check configuration |
| `.cargo/config.toml` | Cargo build configuration |

## Quick Navigation

### 🚀 Common Development Paths

1. **Core Feature Development**: `crates/sb-core/src/`
2. **Protocol Implementation**: `crates/sb-adapters/src/`
3. **Configuration Management**: `crates/sb-config/src/`
4. **Test Files**: `tests/`
5. **Documentation Writing**: `docs/`
6. **Example Code**: `examples/`

### 📝 Important Files

- 项目战略: `agents-only/06-STRATEGIC-ROADMAP.md` - 战略路线图
- Go Parity Matrix: `GO_PARITY_MATRIX.md` - Parity status with sing-box 1.12.14
- Migration Guide: `docs/MIGRATION_GUIDE.md` - Go → Rust full migration path
- Performance Benchmarks: `benchmark_results/`, `reports/PERFORMANCE_REPORT.md`, and legacy `docs/archive/root-legacy/BENCHMARKS.md`
- Test Coverage: `reports/TEST_COVERAGE.md`
- Security Documentation: `SECURITY.md`
- Changelog: `CHANGELOG.md`
- Doc Entry: `docs/README.md` and `00-..` section directories
- CLI/Usage Ref: Root `README.md` and `docs/02-cli-reference/`
- Test Guide: `tests/README.md`

### 🔍 Search Guide

- **Find Feature Implementation**: Browse by module in `crates/sb-core/src/`
- **Find Protocol Support**: Browse in `crates/sb-adapters/src/`
- **Find Configuration Options**: Browse in `crates/sb-config/src/` and `examples/configs/`
- **Find Test Cases**: Browse by function classification in `tests/` directory
- **Find Usage Examples**: Browse in `examples/` directory

## Recent Updates

### Structure Sync (2026-02-01)

- Removed tracked local logs: `check_log.txt`, `test_output.txt`
- Refreshed document timestamps after structure verification

### Parity Baseline (2026-01-07)

**Current Baseline**: sing-box Go 1.12.14 — overall parity 88% (183/209), feature-gated parity builds. See `GO_PARITY_MATRIX.md` and `NEXT_STEPS.md`.

#### Protocol Coverage (Go)

**Inbound Protocols** (18/18):
- ✅ SOCKS5, HTTP, Mixed, Direct, DNS
- ✅ TUN, Redirect, TProxy (Linux)
- ✅ Shadowsocks, VMess, VLESS, Trojan
- ✅ Naive, ShadowTLS, AnyTLS
- ✅ Hysteria v1, Hysteria2, TUIC

**Outbound Protocols** (19/19):
- ✅ Direct, Block, HTTP, SOCKS5, DNS
- ✅ Shadowsocks, VMess, VLESS, Trojan
- ✅ SSH, ShadowTLS, Tor, AnyTLS
- ✅ Hysteria v1, Hysteria2, TUIC
- ✅ WireGuard
- ✅ Selector, URLTest

#### DNS Transports (11/11 aligned, feature-gated)

- ✅ TCP, UDP, DoT, DoH
- ✅ DoQ, DoH3
- ✅ system, local
- ✅ DHCP, resolved, tailscale

#### Services & Endpoints (parity gaps remain)

- ✅ DERP service aligned
- ◐ V2Ray API gRPC parity partial
- ◐ Resolved/SSMAPI parity gaps (feature-gated; see `GO_PARITY_MATRIX.md`)
- ◐ WireGuard endpoint userspace MVP; Tailscale endpoint de-scoped

### 📊 Current Coverage Summary

| Category | Current Status | Notes |
|----------|----------------|-------|
| **Inbound Protocols** | **100% (18/18)** | Go protocols aligned |
| **Outbound Protocols** | **100% (19/19)** | Go protocols aligned |
| **DNS Transport** | **100% (11/11)** | Feature-gated |
| **Services** | **Partial** | V2Ray API gRPC + Resolved/SSMAPI gaps |
| **Endpoints** | **Partial** | WireGuard userspace; Tailscale de-scoped |
| **TLS** | **Partial** | uTLS/ECH limitations |

## 📋 Document Maintenance Guidelines

### 🔄 Update Responsibilities
- **Developers**: Must synchronously update this document when modifying project structure
- **AI Assistants**: Must verify and update document accuracy before starting work
- **Automation Tools**: Must trigger document update check after structure changes

### ✅ Verification Checklist
Before starting development work, please verify the following:
- [ ] Root directory structure matches document description
- [ ] crates/ module list is complete and accurate
- [ ] tests/ directory classification is correct
- [ ] Document path references are valid
- [ ] Recent updates section reflects current status

### 🚨 Inconsistency Handling Process
1. **Immediately stop current development work**
2. **Update document to reflect actual structure**
3. **Verify accuracy of updated document**
4. **Resume original development task**

### 📝 Document Update Format
When updating, please follow this format:
- Use clear directory tree structure
- Include purpose description for files/directories
- Update "Recent Updates" section
- Maintain consistency of emoji icons

---

**⚠️ Important Reminder**: The accuracy of this document directly impacts development efficiency and code quality. Please strictly abide by the maintenance guidelines to ensure the document stays in sync with the actual project structure.

*Document Version: v2.0 | Last Updated: February 7, 2026 | Location: agents-only/*
