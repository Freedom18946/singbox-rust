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

> 各阶段产物已 `git mv` 进 `archive/{L*,MT-*}/`，C-tier 不主动加载。

---

## 当前状态：维护基线 + MT-REAL-02 实验前沿（活跃但休眠）

**L1-L25 + 全部 MT-* 维护/验收线已关闭**。但项目**不是纯维护态**：在用户显式要求继续追求
"可直接替换 Go sing-box 的 Rust 二进制"后，**`MT-REAL-02`（REALITY ClientHello / `uTLS`
对齐）已于 2026-04-16 作为实验线重开**，目标是建立 Go `uTLS` ↔ Rust REALITY `ClientHello`
基线并据此突破 REALITY live dataplane。

> **MT-REAL-02 实时状态（轮次/结论/下一步）一律见 `active_context.md`**。
> 截至 2026-06-03：该线在 **R91 (2026-05-09) 后休眠**，待授权的 fresh 样本 intake 续推。
> 长报告：`mt_real_02_baseline.md`；证据：`mt_real_02_evidence/`。
> dual-kernel BHV 数字以 `active_context.md` + golden_spec 为准（勿在此抄）。

### 维护/验收 close-out 清单（全部已完成，已归档）

| 线 | 归档位置 |
|--------|------|
| MT-OBS/RTC/HOT-OBS/SVC/TEST/RD/PERF/ADP/MLOG/ADM/DEEP/CONTRACT/CONV | `archive/MT-MAINTENANCE/` |
| MT-RECAP-01（maintenance_recap） | `archive/MT-MAINTENANCE/` |
| MT-AUDIT-01（reconciliation + full report） | `archive/MT-AUDIT/` |
| MT-DEPLOY-01 | `archive/MT-DEPLOY/` |
| MT-GUI-01/02/03/04 | `archive/MT-GUI/` |
| MT-REAL-01（ARCH-LIMIT-REALITY 收口，2026-04-15） | `archive/MT-REAL-01/` |
| 旧 deployment-acceptance 下一阶段口径（已被 MT-REAL-02 取代） | `archive/MT-MAINTENANCE/deployment_acceptance_next_stage.md` |

### MT-GUI-04 结论（验收基线，非 parity completion）

- 对所有声明完成项的 exhaustive per-capability acceptance（55 项能力 / 6 类别）。
- 双内核同时运行 + mock 公网逐项测试，三态：PASS-STRICT / PASS-DIV-COVERED / PASS-ENV-LIMITED。
- 报告：`archive/MT-GUI/mt_gui_04_acceptance.md`（+ matrix / capability_inventory / gap_list）。

### 下一阶段默认路线

- **最高目标线（默认优先）**：MT-REAL-02 REALITY 突破，baseline-driven。续推前读 `active_context.md`。
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
