# CLAUDE.md — singbox-rust 项目记忆

> 每次会话自动读取。详细历史见 `agents-only/07-memory/`。

---

## 环境约束

- **Task subagent 必须用 `model: "opus"`**（haiku/sonnet 返回 403）
- **Go 参考源码**: `go_fork_source/sing-box-1.12.14/`
- **GUI 参考源码**: `GUI_fork_source/`
- **AI 工作区**: `agents-only/`（启动检查清单: `agents-only/init.md`）

---

## 项目概况

- **项目**: singbox-rust — Go sing-box 1.12.14 的 Rust 重写，与 GUI.for SingBox 完全兼容
- **阶段**: L2 功能对齐（Tier 1 ✅，L2.1 审计 ✅，L2.6 ✅，L2.7 ✅，Tier 2 进行中）
- **Parity**: ~92% (192/209)
- **L1 架构整固**: ✅ 完成（check-boundaries.sh exit 0）
- **L2 Tier 1**: ✅（maxminddb + Config schema + Clash API + CLI）
- **L2.1 Clash API 审计**: ✅ 完成（18 项偏差修复，GUI.for 完全兼容）
- **L2.6 Selector 持久化**: ✅ 完成（OutboundGroup trait + CacheFile 联通 + as_group() bug 修复）
- **L2.7 URLTest 历史**: ✅ 完成（URLTestHistoryStorage + history 填充 + tolerance 防抖）
- **当前状态**: 见 `agents-only/active_context.md`

### L2 Tier 2 工作包（按 GUI 可感知度排序）

| 包 | 名称 | 工作量 | 状态 | 关键内容 |
|----|------|--------|------|---------|
| L2.6 | Selector 持久化 + Proxy 状态真实化 | 中 | ✅ | OutboundGroup trait + CacheFile 联通 + as_group() 转发修复 |
| L2.7 | URLTest 历史 + 健康检查对齐 | 中 | ✅ | URLTestHistoryStorage + history 填充 + tolerance 防抖 |
| L2.8 | ConnectionTracker + 连接面板 | 中 | 待做 | Router 级 connection table + 真实 close |
| L2.9 | Lifecycle 编排 | 中 | 待做 | start_all 接入拓扑排序 + staged startup |
| L2.10 | DNS 栈对齐 | 大 | 待做 | DNSRouter / EDNS0 / FakeIP / RDRC |

---

## 架构

```
sb-types (契约) → sb-config → sb-core (引擎) → sb-adapters (协议) → app (组合根)
                                  ↑                     ↑
                              sb-tls              sb-transport
```

**核心事实**:
- sb-adapters/outbound/ 包含 10 个完全独立的协议实现（L1 后从 sb-core 迁出）
- sb-core/outbound/ 仅保留管理/调度 + hysteria inbound + naive_h2
- `out_*` features 在 sb-core 中为空数组 `[]`（保留名称兼容，但**空 feature 仍激活 cfg blocks**）

### Feature Gate 要点

- rustls/tokio-rustls: optional behind `tls_rustls`
- reqwest: optional behind `dns_doh` / `service_derp`
- axum/tonic: optional behind `service_ssmapi` / `service_v2ray_api`
- Hysteria/Hysteria2 inbound 仍依赖 sb-core 的 `out_hysteria`/`out_hysteria2`

### sb-types Port Traits

`OutboundConnector`, `InboundHandler`, `InboundAcceptor`, `DnsPort`, `MetricsPort`,
`AdminPort`, `StatsPort`, `Service`, `Lifecycle`, `Startable`, `HttpClient`,
`Session`, `TargetAddr`, `CoreError`, `DnsError`, `TransportError`

---

## 边界检查

- 脚本: `agents-only/06-scripts/check-boundaries.sh`
- 用法: `make boundaries`（严格）或 `make boundaries-report`
- V1/V2/V3: feature-gate 感知
- V4: 拆分为 V4a（可操作违规）和 V4b（合法依赖，INFO only）

---

## 构建状态

| 构建 | 状态 |
|------|------|
| `cargo check --workspace` | ✅ |
| `cargo check -p app --features router` | ✅ |
| `cargo check -p app --features parity` | ✅ |
| `cargo test --workspace` | ✅ 1441 passed |
| `check-boundaries.sh` | ✅ exit 0 |

---

## 详细参考

| 内容 | 位置 |
|------|------|
| 当前上下文 & 下一步 | `agents-only/active_context.md` |
| **Clash API 审计报告** | **`agents-only/05-analysis/CLASH-API-AUDIT.md`** |
| L2 缺口分析 | `agents-only/05-analysis/L2-PARITY-GAP-ANALYSIS.md` |
| L2.1 工作包 | `agents-only/workpackage_latest.md` |
| 实施历史 (L1/L2) | `agents-only/07-memory/implementation-history.md` |
| 踩坑记录 | `agents-only/07-memory/TROUBLESHOOTING.md` |
| 工作流/架构模式 | `agents-only/07-memory/LEARNED-PATTERNS.md` |
| 边界检查脚本 | `agents-only/06-scripts/check-boundaries.sh` |
