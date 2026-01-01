# Examples Directory Structure / 示例目录结构

**Last Updated**: 2026-01-01  
**Status**: ✅ Reorganized and Optimized

---

## 📊 Overview / 概览

The examples directory has been completely reorganized for better discoverability, clarity, and maintainability.

示例目录已完全重组，提高了可发现性、清晰度和可维护性。

**Key Improvements** / **主要改进**:

- ✅ Logical categorization by function
- ✅ Clear naming conventions
- ✅ Comprehensive documentation
- ✅ Beginner-friendly quick-start guide
- ✅ Complete protocol coverage

---

## 🗂️ Directory Tree / 目录树

```
examples/
├── README.md                          # Main index and usage guide
├── STRUCTURE.md                       # This file - structure documentation
│
├── quick-start/                       # 🚀 Beginner-friendly examples
│   ├── README.md
│   ├── 01-minimal.{json,yaml}        # Simplest possible config
│   ├── 02-socks5-direct.{json,yaml}  # SOCKS5 proxy
│   ├── 03-http-proxy.yaml            # HTTP proxy
│   ├── 04-mixed-inbound.yaml         # SOCKS5+HTTP combined
│   ├── 05-basic-routing.yaml         # Routing basics
│   └── explain_minimal.yaml          # For route explain demo
│
├── configs/                           # 📦 Protocol configurations
│   ├── README.md
│   │
│   ├── inbounds/                     # Server-side configs
│   │   ├── socks5.json
│   │   ├── minimal_http.json
│   │   ├── shadowsocks.json
│   │   ├── vmess.json
│   │   ├── trojan.json
│   │   └── tun.json
│   │
│   ├── outbounds/                    # Client-side configs
│   │   ├── shadowsocks.json
│   │   ├── vmess-ws-tls.json
│   │   ├── trojan-grpc.json
│   │   ├── hysteria_v1.json
│   │   ├── hysteria_v2.json
│   │   ├── tuic_outbound.json
│   │   ├── ssh_outbound.json
│   │   ├── selector.json
│   │   └── urltest.json
│   │
│   ├── routing/                      # Routing examples
│   │   ├── rules_demo.json
│   │   ├── domain-based.json
│   │   ├── geoip-routing.json
│   │   └── process-based.json
│   │
│   ├── dns/                          # DNS configurations
│   │   ├── doh-simple.yaml
│   │   ├── dot-simple.yaml
│   │   ├── doq-simple.yaml
│   │   └── fakeip.json
│   │
│   ├── advanced/                     # Complex scenarios
│   │   ├── full_stack.json
│   │   ├── transparent-proxy.json
│   │   ├── load-balancing.json
│   │   ├── failover.json
│   │   ├── chain-proxy.json
│   │   └── sample.json
│   │
│   └── security/                     # TLS and security
│       ├── tls-standard.json
│       ├── reality_vless.json
│       ├── reality-complete.json
│       └── ech_outbound.json
│
├── dsl/                              # 📝 DSL routing rules
│   ├── README.md
│   ├── basic-routing.dsl
│   ├── advanced-routing.dsl
│   ├── plus-syntax.txt
│   ├── sample.txt
│   ├── v1-examples.txt
│   ├── v2-examples.txt
│   └── snippets/                     # Reusable DSL fragments
│
├── rules/                            # 🛣️ Routing rule sets
│   ├── README.md
│   ├── basic-router.rules
│   ├── router.json
│   ├── snippets/                     # Rule fragments
│   │   └── block_ads.dsl
│   └── templates/                    # Pre-made rule sets (planned)
│
├── code-examples/                    # 🔧 Rust integration examples
│   ├── README.md
│   ├── network/                      # TCP/UDP examples
│   │   ├── tcp_connect.rs
│   │   ├── udp_echo.rs
│   │   └── udp_blast.rs
│   ├── dns/                          # DNS examples
│   │   └── dns_lookup.rs
│   ├── proxy/                        # Proxy implementations
│   │   ├── http_inbound_demo.rs
│   │   └── socks5_udp_probe.rs
│   └── testing/                      # Testing utilities
│       └── scenarios/
│           ├── loopback.smoke.json
│           ├── vars.ci.json
│           └── vars.dev.json
│
├── schemas/                          # 📋 JSON schemas
│   ├── README.md
│   ├── config.schema.json            # Main config schema
│   ├── subs.schema.json              # Subscription schema
│   └── schema.map.json               # Version mappings
│
├── misc/                             # 🗄️ Legacy & testing files
│   ├── README.md
│   ├── chaos.profiles.json
│   ├── dns_pool_example.env
│   ├── targets.sample.txt
│   ├── targets.auto.txt
│   ├── tuic_example.json             # Legacy
│   ├── subs.nodes.sample.json
│   ├── subs.bad.json                 # For error testing
│   ├── config.bad.json               # For error testing
│   ├── hs.scenarios.json             # Historical
│   ├── v1_minimal.yml                # Legacy v1
│   ├── v1_proxy.yml                  # Legacy v1
│   ├── v1_dns.yml                    # Legacy v1
│   └── v2_dns.yml                    # Legacy v2
│
└── e2e/                              # 🧪 End-to-end testing
    └── minimal.yaml
```

---

## 📈 Statistics / 统计

### File Counts by Category

| Category         | Count       | Purpose            |
| ---------------- | ----------- | ------------------ |
| Quick Start      | 6 files     | Beginner tutorials |
| Inbound Configs  | 6 files     | Server protocols   |
| Outbound Configs | 9 files     | Client protocols   |
| Routing Configs  | 4 files     | Traffic rules      |
| DNS Configs      | 4 files     | DNS resolution     |
| Advanced Configs | 6 files     | Complex scenarios  |
| Security Configs | 4 files     | TLS features       |
| DSL Rules        | 7 files     | Routing DSL        |
| Code Examples    | 6 files     | Rust integration   |
| Schemas          | 3 files     | JSON validation    |
| Documentation    | 10+ READMEs | Usage guides       |

**Total**: 70+ organized files (vs 40+ scattered files before)

---

## 🎯 Design Principles / 设计原则

### 1. Progressive Disclosure / 渐进式展示

- **quick-start/**: Minimal examples for beginners
- **configs/**: Complete protocol examples
- **advanced/**: Complex production scenarios

### 2. Clear Categorization / 清晰分类

- By **function**: inbounds vs outbounds
- By **complexity**: simple vs advanced
- By **purpose**: production vs testing

### 3. Comprehensive Documentation / 全面文档

- Main README with full index
- Sub-directory READMEs for context
- Inline comments in configs

### 4. Discoverability / 可发现性

- Descriptive file names (no more `a.dsl`, `b.dsl`)
- Logical directory structure
- Cross-referenced documentation

---

## 🔍 Finding What You Need / 查找所需内容

### "I'm new to singbox-rust" / "我是新手"

➡️ Start at: `quick-start/README.md`

### "I need to configure [protocol]" / "我需要配置某协议"

➡️ Check: `configs/inbounds/` or `configs/outbounds/`

### "I want to set up routing rules" / "我想设置路由规则"

➡️ See: `configs/routing/` and `dsl/`

### "I need DNS configuration" / "我需要配置 DNS"

➡️ Look at: `configs/dns/`

### "I want production-ready setups" / "我需要生产环境配置"

➡️ Study: `configs/advanced/`

### "I'm integrating into Rust code" / "我在集成到 Rust 代码"

➡️ Explore: `code-examples/`

### "I need schema validation" / "我需要模式验证"

➡️ Use: `schemas/`

---

## 📚 Documentation Hierarchy / 文档层次

```
examples/README.md                     # Top-level index
├── quick-start/README.md              # Beginner guide
├── configs/README.md                  # Protocol overview
│   ├── inbounds/README.md (planned)
│   ├── outbounds/README.md (planned)
│   ├── routing/README.md (planned)
│   ├── dns/README.md (planned)
│   ├── advanced/README.md (planned)
│   └── security/README.md (planned)
├── dsl/README.md                      # DSL syntax guide
├── rules/README.md                    # Routing rules guide
├── code-examples/README.md            # Integration guide
├── schemas/README.md                  # Schema usage
└── misc/README.md                     # Legacy files
```

---

## 🔄 Migration from Old Structure / 从旧结构迁移

### File Relocations / 文件重定位

| Old Location         | New Location                  | Reason                |
| -------------------- | ----------------------------- | --------------------- |
| `a.dsl`              | `dsl/basic-routing.dsl`       | Descriptive naming    |
| `b.dsl`              | `dsl/advanced-routing.dsl`    | Descriptive naming    |
| `tcp_connect.rs`     | `code-examples/network/`      | Categorization        |
| `config.schema.json` | `schemas/`                    | Dedicated schemas dir |
| `v2_minimal.json`    | `quick-start/01-minimal.json` | Quick start emphasis  |
| Legacy configs       | `misc/`                       | Historical reference  |

### Breaking Changes / 破坏性变更

**None** - All file moves are internal to the examples directory.

---

## ✅ Validation Checklist / 验证清单

- [x] All files categorized appropriately
- [x] No files left in root (except READMEs)
- [x] Descriptive file names (no `a.dsl`, etc.)
- [x] README in every major directory
- [x] Cross-references between docs
- [x] Consistent naming conventions
- [x] Legacy files preserved in `misc/`
- [x] Code examples properly organized
- [x] Schema files in dedicated directory

---

## 🎓 Quick Reference / 快速参考

### Most Common Tasks

1. **Get started**: `quick-start/01-minimal.yaml`
2. **Set up SOCKS5**: `quick-start/02-socks5-direct.yaml`
3. **Configure routing**: `configs/routing/domain-based.json`
4. **Use TUN**: `configs/inbounds/tun.json`
5. **Set up failover**: `configs/advanced/failover.json`

### Feature Flags Quick Reference

```bash
# Shadowsocks
--features 'sb-core/in_shadowsocks'

# VMess + transport
--features 'sb-core/out_vmess,sb-core/v2ray_transport'

# TUN device
--features 'sb-core/in_tun'

# REALITY TLS
--features 'sb-core/reality'

# DNS-over-QUIC
--features 'sb-core/dns_doq'
```

---

## 🔗 Related Documentation / 相关文档

- [Architecture](../docs/ARCHITECTURE.md)
- [Router Rules](../docs/ROUTER_RULES.md)
- [Environment Variables](../docs/ENV_VARS.md)
- [Development Guide](../docs/DEVELOPMENT.md)

---

## 📝 Maintenance Notes / 维护说明

### Adding New Examples

1. Place in appropriate subdirectory
2. Follow naming conventions
3. Add to relevant README
4. Include inline comments
5. Test before committing

### Deprecating Examples

1. Move to `misc/` with explanation
2. Update main README
3. Document in CHANGELOG

---

**This structure is designed to scale** as singbox-rust grows and adds more features.

**这个结构设计用于扩展** 随着 singbox-rust 增长和添加更多功能。

---

**Maintainer**: Claude Sonnet 4.5  
**Date**: 2025-10-18  
**Version**: v0.2.0+
