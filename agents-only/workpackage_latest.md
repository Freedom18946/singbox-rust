<!-- tier: S -->
# 工作阶段总览（Workpackage Map）
> **用途**：阶段划分 + 当前位置。S-tier，每次会话必读。
> **纪律**：Phase 关闭后压缩为一行状态。本文件严格 ≤120 行。
> **对比**：本文件管"在哪"；`active_context.md` 管"刚做了什么 / 当前基线"，
> 且是易变状态（轮次、parity 数字、门禁）的唯一权威——本文件不复制这些数值。
---
## 已关闭阶段（一行总结）
| 阶段 | 交付 | 关闭时间 |
|------|------|----------|
| L1-L17 | 架构整固、功能对齐、CI / 发布收口 | 2026-01 ~ 2026-02 |
| MIG-02 / L21 | 隐式回退消除，生产路径零隐式直连回退 | 2026-03-07 |
| L18 Phase 1-4 | 认证替换、证据模型收口、GUI gate 复验、长跑恢复决策门 | 2026-03-11 |
| L22 | dual-kernel parity 收口，both-case + Sniff Phase A+B | 2026-03-15 |
| 后 L22 补丁 | QUIC 多包重组、OverrideDestination、UDP datagram sniff | 2026-03-15 |
| L23 | TUN/Sniff 运行时补全、Provider wiring、T4 Protocol Suite | 2026-03-16 |
| L24 | 性能/安全/质量/功能补全，30 任务 (B1-B4)，综合验收 | 2026-03-17 |
| L25 | 生产加固 + 跨平台补全 + 文档完善，10/10 任务 | 2026-03-17 |
| MT-* 维护/验收线（见下表） | 运行时/路由/服务/观测/审计/GUI/部署逐线收口 | 2026-04 |

> 各阶段产物已强压缩进 `archive/*_summary.md`，C-tier 不主动加载。

---

## 当前状态：维护基线 + REALITY 本地主线已封箱（T3 收口）

**L1-L25 + 全部 MT-* 维护/验收线已关闭**。项目**不是纯维护态**：在用户显式要求继续追求
"可直接替换 Go sing-box 的 Rust 二进制"后，**`MT-REAL-02`（REALITY ClientHello / `uTLS`
对齐）于 2026-04-16 作为实验线重开**；其目标（Go `uTLS` ↔ Rust REALITY `ClientHello` 基线、
推进 REALITY live dataplane）已由 T3 track 在本地达成并**封箱**（详见 `active_context.md`）。

> **MT-REAL-02 实时状态（轮次/结论/下一步）一律见 `active_context.md`**。
> REALITY 本地主线已封箱（T3-0..T3-2，2026-06-08）；当前状态与下一步一律以 `active_context.md` 为准。
> 长报告：`mt_real_02_baseline.md`；证据：`mt_real_02_evidence/`。
> dual-kernel BHV 数字以 `active_context.md` + golden_spec 为准（勿在此抄）。

### 维护/验收 close-out 清单（全部已完成，已归档）

| 线 | 归档位置 |
|--------|------|
| MT-OBS/RTC/HOT-OBS/SVC/TEST/RD/PERF/ADP/MLOG/ADM/DEEP/CONTRACT/CONV | `archive/mt_summary.md` |
| MT-RECAP-01（maintenance_recap） | `archive/mt_summary.md` |
| MT-AUDIT-01（reconciliation + full report） | `archive/mt_summary.md` |
| MT-DEPLOY-01 | `archive/mt_summary.md` |
| MT-GUI-01/02/03/04 | `archive/mt_summary.md` |
| MT-REAL-01（ARCH-LIMIT-REALITY 收口，2026-04-15） | `archive/reality_summary.md` |
| 旧 deployment-acceptance 下一阶段口径（已被 MT-REAL-02 取代） | `archive/mt_summary.md` |

### MT-GUI-04 结论（验收基线，非 parity completion）

- 对所有声明完成项的 exhaustive per-capability acceptance（55 项能力 / 6 类别）。
- 双内核同时运行 + mock 公网逐项测试，三态：PASS-STRICT / PASS-DIV-COVERED / PASS-ENV-LIMITED。
- 历史摘要：`archive/mt_summary.md`。

### 下一阶段默认路线

- **最高目标线**：REALITY 本地主线已封箱（T3 收口）；当前推荐下一卡与优先级以 `active_context.md` 为准。
- **MIG-03（架构去重迁移，2026-07-06 立项）**：4 阶段 / 14 工作包，全集见
  `agents-only/mig03/`（README 为索引与全局纪律）；各包状态以包头 `Status:` 为准。
- **参考内核抬版本后的任务入口**：`agents-only/post1313/`（Go 1.13.13 / GUI 1.25.1
  差异分析与任务包；P1313-09 已本地关闭，其余任务以各包状态为准）。
- **维护基线**：声明完成能力已逐项验收闭环；不再拆细维护卡，不重开旧 maintenance 线名。
- **后续 agents 先看**：
  - `agents-only/active_context.md`（当前状态唯一权威）
  - `agents-only/mt_real_02_baseline.md`
  - `labs/interop-lab/docs/dual_kernel_golden_spec.md`
  - `agents-only/reference/AGENT-DEVELOPMENT-GUIDELINES.md`

### 明确暂停事项

- 不恢复 `.github/workflows/*`。
- 不把维护工作误写成 dual-kernel parity completion。
- 不再继续 `WP-30k` 风格微卡化排程。
- 不推进 public `RuntimePlan` / public `PlannedConfigIR` / generic query API。
- 不在仓库根目录新建工作目录；产物落 `agents-only/`，关闭即归档。
