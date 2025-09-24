# singbox-rust

A pragmatic rewrite path for sing-box in Rust. Focused on **good taste**, **never break userspace**, and **boring clarity**.

## 🚨 重要：项目导航权威文档

**⚠️ 开发者必读：在开始任何开发工作之前，请务必阅读并验证 [`PROJECT_STRUCTURE_NAVIGATION.md`](./PROJECT_STRUCTURE_NAVIGATION.md) 的准确性。**

- 📋 **权威性**: 该文档是项目结构的唯一权威参考
- 🔄 **更新责任**: 任何修改项目结构的开发者都必须同步更新该导航文档
- ✅ **验证要求**: 新的开发者或AI助手在开始工作前必须验证导航文档的准确性
- 📍 **导航优先**: 所有开发活动都应基于该导航文档进行路径规划

**如发现导航文档与实际项目结构不符，请立即更新文档后再继续开发工作。**

## Quick Start

```bash
cargo check --workspace --all-features
bash scripts/ci-local.sh
```

Run with an example:

```bash
bash scripts/run-examples.sh examples/configs/full_stack.json
```

## 📚 文档导航

### 🗺️ 项目结构导航 (必读)
- **[PROJECT_STRUCTURE_NAVIGATION.md](./PROJECT_STRUCTURE_NAVIGATION.md)** - 项目结构权威导航文档

### 📖 核心文档
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) - 架构设计文档
- [docs/ROUTER_RULES.md](docs/ROUTER_RULES.md) - 路由规则文档
- [docs/ENV_VARS.md](docs/ENV_VARS.md) - 环境变量配置

### 🧪 测试文档
- [tests/README.md](tests/README.md) - 测试指南和目录结构

## Status

Phase 2.4: inbounds (HTTP/SOCKS) wired, rule engine minimal, env-driven suffix rules.
## Troubleshooting

- Set `SB_PRINT_ENV=1` to print a one-line JSON snapshot of relevant environment variables at startup.
- Common errors and meanings:
  - `outbound_error_total{kind="udp",class="no_upstream"}`: proxy mode selected but no upstream configured; falls back to direct.
  - `balancer_failures_total{reason}`: upstream connect/send/recv failures with exponential backoff applied.
  - `udp_nat_reject_total{reason="capacity"}`: NAT table reached capacity; increase `SB_UDP_NAT_MAX` or reduce churn.
