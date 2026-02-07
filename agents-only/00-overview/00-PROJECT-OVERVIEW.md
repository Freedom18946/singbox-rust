# singbox-rust 项目概览（Agents Only）

> **本文档为 AI Agent 专用**：整合了根目录和 `singbox_archspec_v2` 的所有核心信息，提供清晰的需求分析和验收标准。

---

## 项目定位

singbox-rust 是 sing-box (Go) 的 Rust 重写版本，设计理念：
- **Good Taste**：追求工程美学
- **Never Break Userspace**：向后兼容
- **Boring Clarity**：代码易读易维护

### 当前状态
- **Parity**: 88% (183/209 items aligned)
- **Baseline**: sing-box Go 1.12.14
- **Rust Toolchain**: 1.92+

---

## 核心架构层次

```
┌───────────────────────────────┐
│             app               │  ← 组合根 + CLI
│   composition root + CLI      │
└───────────────┬───────────────┘
                │
    ┌───────────┴────────────┐
    │                        │
┌───▼───┐              ┌─────▼─────┐
│sb-api │              │  sb-core  │  ← 数据面引擎
│ 控制面 │              │ 路由/策略  │
└───┬───┘              └─────┬─────┘
    │                        │
    │                  (Ports via sb-types)
    │                        │
    │                  ┌─────▼─────┐
    │                  │sb-adapters│  ← 协议适配器
    │                  │ 协议实现层  │
    │                  └──┬────┬───┘
    │                     │    │
┌───▼────┐          ┌─────▼┐  ┌▼────────┐
│sb-metrics│        │sb-transport│ │sb-platform│
│ 可观测性  │         │ 传输层     │ │ 平台能力   │
└─────────┘         └──────┘  └─────────┘
```

### Crate 职责一览

| Crate | 职责 | 核心组件 |
|-------|------|---------|
| **sb-core** | 路由/策略/会话编排 | Router, DNS, NAT, Error handling |
| **sb-config** | 配置解析/验证 | Schema validation, Config IR |
| **sb-adapters** | 协议实现 | VMess, VLESS, Hysteria, TUIC, Trojan |
| **sb-transport** | 传输层 | TCP/UDP, WebSocket, HTTP/2, QUIC, Multiplex |
| **sb-tls** | TLS 基础设施 | Standard TLS, REALITY, ECH, uTLS |
| **sb-types** | 契约层 | Ports traits, 领域类型 |
| **sb-platform** | 平台能力 | TUN, tproxy, syscalls |
| **sb-api** | 外部 API | Clash API, V2Ray Stats |
| **sb-metrics** | 监控 | Prometheus integration |

---

## 关键文档索引

| 文档 | 位置 | 用途 |
|------|------|------|
| 项目导航 | `PROJECT_STRUCTURE_NAVIGATION.md` | 目录结构唯一真相 |
| 下一步计划 | `NEXT_STEPS.md` | 当前里程碑和任务 |
| Go 对齐矩阵 | `GO_PARITY_MATRIX.md` | 详细功能对比 |
| 安全策略 | `SECURITY.md` | 密钥管理/日志安全 |
| 测试覆盖 | `TEST_COVERAGE.md` | 测试状态报告 |
| 架构规范 | `singbox_archspec_v2/` | V2 重构规范 |

---

## 快速验证命令

```bash
# 构建 parity 版本
cargo +1.92 build -p app --features "parity" --release

# 运行测试
cargo test --workspace

# 检查依赖安全
cargo deny check

# Lint
cargo clippy --workspace --all-features
```

---

*下一步：阅读 [01-REQUIREMENTS-ANALYSIS.md](./01-REQUIREMENTS-ANALYSIS.md) 了解详细需求分析*
