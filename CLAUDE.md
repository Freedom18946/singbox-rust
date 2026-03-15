# CLAUDE.md — singbox-rust 项目记忆

> 每次会话自动读取。详细历史见 `agents-only/archive/`。

---

## 文档分级制度

| Tier | 语义 | 操作规则 |
|------|------|----------|
| **S** | 每次会话必读 | ≤200 行，严格瘦身。仅 `active_context.md` + 当前 phase 工作包 |
| **A** | 按需读取 | 稳定参考，不随 phase 变化。`reference/` + `memory/` |
| **B** | 深挖时才读 | 已完成但可能有参考价值。新文件默认 B-tier |
| **C** | 不读除非明确要求 | 审计留痕。`archive/` + `log.md` |

**标记方式**：文件第一行 `<!-- tier: S/A/B/C -->`

**运营纪律**：
1. `active_context.md` 更新时，先删除 >7 天的快照段落，再写新的。严格 ≤100 行。
2. Phase 关闭后，其工作包/分析文档移入 `archive/{phase}/`。
3. `log.md` 持续追加（C-tier），是终极流水帐，不主动读取但永不删除。
4. 新文件默认 B-tier，除非显式标 S/A。

---

## 环境约束

- **Task subagent 必须用 `model: "opus"`**（haiku/sonnet 返回 403）
- **Go 参考源码**: `go_fork_source/sing-box-1.12.14/`
- **GUI 参考源码**: `GUI_fork_source/`
- **AI 工作区**: `agents-only/`（启动检查清单: `agents-only/init.md`）

---

## 项目概况

- **项目**: singbox-rust — Go sing-box 1.12.14 的 Rust 重写，与 GUI.for SingBox 完全兼容
- **阶段**: **全部关闭（L1-L22 Closed）**，维护状态
- **Parity**: 100%（209/209 closed）
- **Dual-kernel**: 52/60 (86.7%)，天花板已达
- **MIG-02**: ACCEPTED（2026-03-07，541 V7 assertions，零隐式直连回退）
- **L1-L22**: ✅ 全部 Closed
- **当前状态**: 见 `agents-only/active_context.md`

### 双核黄金基准规则（保留参考）

- **双核黄金基准**（`labs/interop-lab/docs/dual_kernel_golden_spec.md`）是行为对齐权威。
  - 双核差分解读 **必须** 引用 S2（维度映射）+ S3（行为注册表）定位 BHV-ID
  - 差分失败归因 **必须** 先查 S4（偏差注册表）排除已知偏差
  - Case promote **必须** 遵循 S5（路线图）的优先级和工作量分级
  - 覆盖率统计 **必须** 使用 S6 公式，不手工编数字
  - Go 配置创建 **必须** 遵循 S8 翻译指南的字段映射和端口约定

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
| `cargo clippy --workspace --all-features --all-targets -- -D warnings` | ✅ |
| `cargo test -p sb-core` | ✅ 504 passed |
| `cargo test -p interop-lab` | ✅ 29 passed |
| `check-boundaries.sh` | ✅ exit 0 (541 assertions) |

---

## agents-only 目录结构

```
agents-only/
├── active_context.md         # S-tier: 事件细节 / 刚做了什么 / 下一步（≤100行）
├── workpackage_latest.md     # S-tier: 阶段地图 / 全局位置（≤120行）
├── init.md                   # S-tier: 启动检查清单
├── log.md                    # C-tier: 终极流水帐（持续写入，不主动读取）
├── planning/                 # S-tier: 仅当前 phase 活跃规划（当前为空）
│   └── (empty)
├── reference/                # A-tier: 稳定参考
│   ├── GO_PARITY_MATRIX.md
│   ├── PROJECT-STRUCTURE.md
│   ├── ARCHITECTURE-SPEC.md
│   ├── ACCEPTANCE-CRITERIA.md
│   └── GO-DESIGN-REFERENCE.md
├── memory/                   # A-tier: 可复用经验
│   ├── LEARNED-PATTERNS.md
│   ├── TROUBLESHOOTING.md
│   └── implementation-history.md
├── 06-scripts/               # 可执行脚本
├── templates/                # 模板
└── archive/                  # C-tier: 按 phase 归档，不主动加载
    ├── L01-L04/
    ├── L05-L11/
    ├── L12-L17/
    ├── L19-L21-MIG/
    ├── L22/                  # dual-kernel parity 收口归档
    ├── analysis/
    ├── logs/                 # workpackage_latest.md 历史快照
    ├── workflows/
    └── dump/
```

---

## 详细参考

| 内容 | 位置 | Tier |
|------|------|------|
| 阶段地图（在哪） | `agents-only/workpackage_latest.md` | S |
| 事件细节（刚做了什么） | `agents-only/active_context.md` | S |
| L22 归档 | `agents-only/archive/L22/` | C |
| Go/GUI/API 参考 | `scripts/l18/REFERENCE.md` | A |
| Parity 矩阵 | `agents-only/reference/GO_PARITY_MATRIX.md` | A |
| 架构 Spec | `agents-only/reference/ARCHITECTURE-SPEC.md` | A |
| 经验模式 | `agents-only/memory/LEARNED-PATTERNS.md` | A |
| 踩坑记录 | `agents-only/memory/TROUBLESHOOTING.md` | A |
| 边界检查脚本 | `agents-only/06-scripts/check-boundaries.sh` | A |
| **双核黄金基准** | `labs/interop-lab/docs/dual_kernel_golden_spec.md` | **A** |
| interop-lab case 清单 | `labs/interop-lab/docs/case_backlog.md` | B |
| interop-lab 兼容矩阵 | `labs/interop-lab/docs/compat_matrix.md` | B |
| 流水帐日志 | `agents-only/log.md` | C |
| 完整工作包历史 | `agents-only/archive/logs/workpackage_latest.md` | C |
