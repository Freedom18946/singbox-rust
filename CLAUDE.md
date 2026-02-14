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
- **阶段**: **L17 收口完成（PASS_ENV_LIMITED，L1-L16 ✅ Closed）**
- **Parity**: ~99% (208/209)
- **L1 架构整固**: ✅ Closed（check-boundaries.sh exit 0）
- **L2 功能对齐**: ✅ Closed（Tier 1 + Tier 2 全部完成，88% → 99%）
- **L5-L7 联测仿真**: ✅ Closed（22 工作包全部完成，57 YAML case，11 单元测试）
- **L8-L11 CI 治理**: ✅ Closed（CI workflow + 趋势门禁 + 历史追踪 + 回归检测）
- **L12 迁移治理**: ✅ Closed（弃用检测 + 迁移诊断 + WG 迁移辅助）
- **L13 服务安全**: ✅ Closed（Clash API/SSMAPI 认证 + 故障隔离 + 健康 API）
- **L14 TLS 高级**: ✅ Closed（证书存储模式 + 热重载 + TLS 能力矩阵 + 趋势模板）
- **L15 CLI 完善**: ✅ Closed（generate uuid/rand/ech-keypair + AdGuard convert + Chrome cert store + 验收清单签署）
- **L16 基准与稳定性**: ✅ Closed（feature matrix 46/46 + benchmark 产物 + long_tests 稳定性 + CI bench gate）
- **当前状态**: 见 `agents-only/active_context.md`

### L17 发布收口（2026-02-14 最新）

- **已完成**:
  - L17.1.1: CI 门禁定义已固定（fmt / clippy-all-targets / test-workspace / parity / boundaries）。
  - L17.1.2 + L17.2.1: Release workflow 与 `scripts/package_release.sh` 已对齐；产物命名切换到 `singbox-rust-{version}-{os}-{arch}`，并合并 `checksums.txt`。
  - L17.1.3: Dockerfile/compose 链路已收敛到 non-root + `/services/health` + `<50MB` 校验步骤说明。
  - L17.1.4 + L17.2.2 + L17.2.3: CHANGELOG、L17 三篇文档入口、security audit 可复验报告均已落地。
  - L17.3.1 + L17.3.2: GUI smoke / Canary 脚本与报告模板已落地。
- **最新快跑结论**:
  - `scripts/l17_capstone.sh --profile fast --api-url http://127.0.0.1:19090` => `PASS_ENV_LIMITED`
  - 门禁 `boundaries / parity_check / workspace_test / fmt_check / clippy / hot_reload(20x) / signal(5x)` 全部 PASS
  - 环境项 `docker / gui_smoke / canary` 标记 `ENV_LIMITED`（可复跑）

### L5-L16 交付概览

| 层级 | 交付 | 状态 |
|----|------|------|
| L5 | 协议×故障矩阵（6 协议 × 4 故障类型 = 24 cell 全覆盖）+ env_limited 归因 | ✅ |
| L6 | WsRoundTrip/TlsRoundTrip/TCP-TLS delay 注入 + 趋势报告 + CI workflow | ✅ |
| L7 | WsParallel + GUI 启动/切换/delay/reconnect/connections 回放 + E2E capstone | ✅ |
| L8-L11 | CI smoke/nightly + 趋势门禁配置化 + JSONL 历史追踪 + 回归检测 | ✅ |
| L12 | IssueCode::Deprecated + 弃用目录 + 验证器弃用检测 + 迁移诊断 + WG 迁移辅助 | ✅ |
| L13 | Clash API/SSMAPI 认证中间件 + 非 localhost 警告 + ServiceStatus 故障隔离 + 健康 API | ✅ |
| L14 | 证书存储模式（System/Mozilla/None）+ 热重载 + TLS fragment 接线 + 能力矩阵 + 趋势模板 | ✅ |
| L15 | generate uuid/rand/ech-keypair + AdGuard convert + Chrome cert store + format -w + 验收清单签署 | ✅ |
| L16 | baseline/latency/go-vs-rust/memory 基准 + feature-matrix + hot-reload/signal 稳定性 + CI bench gate | ✅ |

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
| `cargo fmt --all -- --check` | ✅ |
| `cargo clippy --workspace --all-features --all-targets -- -D warnings` | ✅ |
| `cargo test --workspace` | ✅ |
| `cargo test -p interop-lab` | ✅ 27 passed |
| `check-boundaries.sh` | ✅ exit 0 |
| `docker build` | ⚠️ 环境阻塞（daemon 未启动） |
| interop-lab cases | 83 total (72 strict, 10 env_limited, 1 smoke) |

---

## 详细参考

| 内容 | 位置 |
|------|------|
| 当前上下文 & 下一步 | `agents-only/active_context.md` |
| **Clash API 审计报告** | **`agents-only/05-analysis/CLASH-API-AUDIT.md`** |
| L2 缺口分析 | `agents-only/05-analysis/L2-PARITY-GAP-ANALYSIS.md` |
| L2.1 工作包 | `agents-only/workpackage_latest.md` |
| **L5-L7 工作包规划与执行** | **`agents-only/03-planning/09-L5-L7-DETAILED-WORKPACKAGES.md`** |
| **L11-L14 工作包规划与执行** | **`agents-only/03-planning/10-L11-L14-DETAILED-WORKPACKAGES.md`** |
| **L15 工作包规划与执行** | **`agents-only/03-planning/11-L15-L17-DETAILED-WORKPACKAGES.md`** |
| interop-lab case 清单 | `labs/interop-lab/docs/case_backlog.md` |
| interop-lab 兼容矩阵 | `labs/interop-lab/docs/compat_matrix.md` |
| 实施历史 (L1/L2) | `agents-only/07-memory/implementation-history.md` |
| 踩坑记录 | `agents-only/07-memory/TROUBLESHOOTING.md` |
| 工作流/架构模式 | `agents-only/07-memory/LEARNED-PATTERNS.md` |
| 边界检查脚本 | `agents-only/06-scripts/check-boundaries.sh` |
