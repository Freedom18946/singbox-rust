# CLAUDE.md — singbox-rust 项目记忆

> 每次会话自动读取。**本文件只放稳定事实**（架构、约定、纪律、落位规则）。
> 一切随时间变化的状态（阶段、parity 数字、构建/门禁结果、当前在做什么）
> 一律以 `agents-only/active_context.md` 为准——**本文件不复制这些数值**。
> 这是 2026-06 重构后的核心反漂移原则：旧版 CLAUDE.md 因硬编码易变数字
> 而落后真相 ~2.5 个月。详细历史见 `agents-only/archive/`。

---

## 单一真相源（最重要）

| 想知道 | 唯一权威 | 不要去问 |
|--------|----------|----------|
| 当前阶段 / 在做什么 / 下一步 | `agents-only/active_context.md` | 本文件、README |
| 构建 & 门禁实时状态 | `agents-only/active_context.md` | 本文件的任何表格 |
| dual-kernel 行为对齐数字 | `active_context.md` + `labs/interop-lab/docs/dual_kernel_golden_spec.md` | 本文件 |
| 验收基线 closed/total | `agents-only/reference/GO_PARITY_MATRIX.md` | 本文件 |
| 协议/能力逐项验收 | `agents-only/archive/MT-GUI/mt_gui_04_acceptance.md` | 本文件 |

**规则**：任何易变数字只允许活在它的权威源里。其它文档引用时只给指针，不抄数字。
写新数字前先确认你写的是不是权威源；不是，就改成指向权威源的一行。

---

## 文档分级制度（Tier）

| Tier | 语义 | 操作规则 |
|------|------|----------|
| **S** | 每次会话必读 | `active_context.md` + `workpackage_latest.md` + `init.md`。严格瘦身 |
| **A** | 按需读取 | 稳定参考，不随 phase 变化：`reference/` + `memory/`(经验) |
| **B** | 深挖时才读 | 已完成但可能有参考价值。新文件默认 B-tier |
| **C** | 除非明确要求否则**勿读** | 审计留痕：`archive/` + `log.md` + `memory/implementation-history.md` |

**标记**：文件第一行 `<!-- tier: S/A/B/C -->`。

**纪律**：
1. `active_context.md` 严格 ≤100 行：写新快照前先删 >7 天旧段落。
2. `workpackage_latest.md` 严格 ≤120 行：phase 关闭后压成一行。
3. Phase / 工作线关闭后，其工作包/inventory/acceptance **立即** `git mv` 进 `archive/{track}/`，不留顶层。
4. `log.md` 持续追加（C-tier），永不删除、永不主动读取。
5. 新文件默认 B-tier，除非显式标 S/A。

---

## 记忆体系（两套，分工明确）

**1. Claude 项目记忆** `~/.claude/projects/-Users-bob-...-singbox-rust/memory/`
- 跨会话自动加载的 `MEMORY.md` 索引 + 每条一事一文件。
- 放：用户画像、对我的工作反馈、代码/历史推不出的项目约束、外部资源指针。
- **不放**：代码结构、过往修复、git 历史能查到的、只在本次对话有效的东西。
- 当前已存校正笔记（均经 2026-06-03 复核仍准确）：parity 三轴、boundary 门禁漂移、REALITY arch-limit 实为可动。

**2. agents-only 项目内记忆**（仓库内，团队共享）
- `active_context.md`：当前易变状态的唯一权威（见上）。
- `reference/`：稳定参考（架构、parity 矩阵、脚本地图、术语、Go 设计、Rust_spec_v2）。
- `memory/LEARNED-PATTERNS.md` + `TROUBLESHOOTING.md`：可复用经验/踩坑（A-tier）。
- `memory/implementation-history.md` + `log.md`：历史流水（C-tier，**勿主动读**）。

**写记忆前先查重**：更新已有文件优于新建；发现错误的记忆要删。

---

## 根目录与工作产物纪律（防乱扔垃圾）

- **仓库根目录只放工程结构**（crate、配置、Makefile、LICENSE、README 等）。
- Agent 的分析/审计/规划草稿一律落 `agents-only/`，**不在根目录新建工作目录**。
- 关闭轨迹的产物 → `agents-only/archive/{track}/`，不滞留顶层。
- `.DS_Store`、`*.orig`、`*.tmp`、构建产物等**永不提交**（`.gitignore` 已覆盖；发现即删）。
- Go/GUI 参考源码（`go_fork_source/`、`GUI_fork_source/`）为 gitignore 的外部 fork，体积大但保留。

---

## 环境约束

- **Task subagent 必须用 `model: "opus"`**（haiku/sonnet 返回 403）。
- **Go 参考源码**：`go_fork_source/sing-box-1.12.14/`
- **GUI 参考源码**：`GUI_fork_source/`
- **AI 工作区**：`agents-only/`（启动检查清单：`agents-only/init.md`）

---

## 项目概况

- **项目**：singbox-rust — Go sing-box 1.12.14 的 Rust 重写，与 GUI.for SingBox 完全兼容。
- **阶段框架**：L1-L25 基线阶段 + 2026-04 一批 MT-* 维护/验收线**全部关闭**；
  **MT-REAL-02（REALITY ClientHello / uTLS 对齐）实验线 2026-04-16 重开**，是当前最高目标前沿。
  → 这条线的实时状态、轮次、结论一律见 `active_context.md`（**勿在本文件追当前轮次**）。
- **Parity 三轴**（互不等价，勿混；数值只在各自权威源里，见"单一真相源"）：
  1. **验收基线** closed/total —— 含 accepted-limitation / won't-fix / de-scoped / Rust-only，**≠ 行为对齐**。
  2. **dual-kernel 行为对齐**（BHV）—— `dual_kernel_golden_spec.md` 为权威。
  3. **MT-GUI-04 能力验收** —— 逐能力 PASS-STRICT / DIV-COVERED / ENV-LIMITED 三态。
- **MIG-02**：ACCEPTED（2026-03-07，零隐式直连回退）。
- **ARCH-LIMIT-REALITY**：REALITY live dataplane 4 个行为槽位登记为已接受偏差、不计入活动 parity debt；
  但 MT-REAL-02 正在以 baseline 驱动方式**主动重新挑战**该上限（详见 memory 笔记与 active_context）。

### 双核黄金基准规则（稳定，保留）

- **双核黄金基准**（`labs/interop-lab/docs/dual_kernel_golden_spec.md`）是行为对齐权威。
  - 双核差分解读 **必须** 引用 S2（维度映射）+ S3（行为注册表）定位 BHV-ID。
  - 差分失败归因 **必须** 先查 S4（偏差注册表）排除已知偏差。
  - Case promote **必须** 遵循 S5（路线图）优先级与工作量分级。
  - 覆盖率统计 **必须** 用 S6 公式，不手工编数字。
  - Go 配置创建 **必须** 遵循 S8 翻译指南的字段映射与端口约定。

---

## 架构

```
sb-types (契约) → sb-config → sb-core (引擎) → sb-adapters (协议) → app (组合根)
                                  ↑                     ↑
                              sb-tls              sb-transport
```

**核心事实**：
- `sb-adapters/outbound/` 含 10 个完全独立的协议实现（L1 后从 sb-core 迁出）。
- `sb-core/outbound/` 仅保留管理/调度 + hysteria inbound + naive_h2。
- `out_*` features 在 sb-core 中为空数组 `[]`（保留名称兼容，但**空 feature 仍激活 cfg blocks**）。

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

- 脚本：`agents-only/06-scripts/check-boundaries.sh`；用法 `make boundaries`（严格）/ `make boundaries-report`。
- V1/V2/V3 feature-gate 感知；V4 拆 V4a（可操作违规）+ V4b（合法依赖，INFO only）。
- **已知现状**：门禁当前 **exit 1**（少量 V7 迁移断言因脚本扫描目标陈旧 / `validator/v2.rs` 已拆成
  `validator/v2/` 目录而失配）。这是**登记在案的非阻塞漂移**（见 `active_context.md` 与
  `reference/ACCEPTANCE-CRITERIA.md`），不是回归。具体失败计数以 `active_context.md` 为准。

---

## agents-only 目录结构（2026-06 重构后）

```
agents-only/
├── active_context.md            # S: 当前状态唯一权威（≤100行）
├── workpackage_latest.md        # S: 阶段地图 / 全局位置（≤120行）
├── init.md                      # S: 启动检查清单
├── README.md                    # 索引
├── log.md                       # C: 终极流水帐（勿读）
├── mt_real_02_baseline.md       # 活跃前沿：REALITY ClientHello 基线长报告
├── mt_real_02_fresh_sample_intake.md   # 活跃前沿
├── mt_mixed_fresh_intake.md     # 前沿邻接（被 baseline 引用）
├── mt_trojan_fresh_sample_intake.md    # 被 trojan.rs 源码引用
├── reference/                   # A: 稳定参考（含 Rust_spec_v2.md）
├── memory/                      # A: 可复用经验 + C: implementation-history
├── 06-scripts/                  # 脚本（check-boundaries / restore-context / verify-consistency）
├── templates/                   # 文档模板
└── archive/                     # C: 按轨迹归档，不主动加载
    ├── L01-L04 / L05-L11 / L12-L17 / L19-L21-MIG / L22..L25
    ├── MT-MAINTENANCE/          # 2026-04 维护线 inventory/recap（已关闭）
    ├── MT-GUI/ MT-DEPLOY/ MT-AUDIT/ MT-REAL-01/   # 已关闭验收/审计/REAL-01
    ├── mt_real_02/              # MT-REAL-02 早期轮次归档
    ├── layer12-review-2026-03/  # 旧 planning/ 的 layer12 工作包
    └── analysis / logs / workflows / dump
```

---

## 详细参考

| 内容 | 位置 | Tier |
|------|------|------|
| 当前状态（唯一权威） | `agents-only/active_context.md` | S |
| 阶段地图 | `agents-only/workpackage_latest.md` | S |
| **双核黄金基准** | `labs/interop-lab/docs/dual_kernel_golden_spec.md` | **A** |
| Parity 矩阵（验收基线） | `agents-only/reference/GO_PARITY_MATRIX.md` | A |
| 架构 Spec | `agents-only/reference/ARCHITECTURE-SPEC.md` | A |
| 验收口径 | `agents-only/reference/ACCEPTANCE-CRITERIA.md` | A |
| Rust 规则原文 | `agents-only/reference/Rust_spec_v2.md` | A |
| 脚本地图 | `agents-only/reference/SCRIPTS-MAP.md` | A |
| 经验模式 / 踩坑 | `agents-only/memory/LEARNED-PATTERNS.md`、`TROUBLESHOOTING.md` | A |
| MT-GUI-04 能力验收 | `agents-only/archive/MT-GUI/mt_gui_04_acceptance.md` | C |
| 审计长报告 | `agents-only/archive/MT-AUDIT/mt_audit_01_full_report.md` | C |
| interop-lab case / 兼容矩阵 | `labs/interop-lab/docs/case_backlog.md`、`compat_matrix.md` | B |
| 流水帐 / 完整工作包历史 | `agents-only/log.md`、`agents-only/archive/logs/` | C |
