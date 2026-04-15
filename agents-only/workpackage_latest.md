<!-- tier: S -->
# 工作阶段总览（Workpackage Map）
> **用途**：阶段划分 + 当前位置。S-tier，每次会话必读。
> **纪律**：Phase 关闭后压缩为一行状态。本文件严格 ≤120 行。
> **对比**：本文件管"在哪"；`active_context.md` 管"刚做了什么 / 当前基线"。
---
## 已关闭阶段（一行总结）
| 阶段 | 交付 | 关闭时间 |
|------|------|----------|
| L1-L17 | 架构整固、功能对齐、CI / 发布收口 | 2026-01 ~ 2026-02 |
| MIG-02 / L21 | 隐式回退消除，541 V7 assertions，生产路径零隐式直连回退 | 2026-03-07 |
| L18 Phase 1-4 | 认证替换、证据模型收口、GUI gate 复验、长跑恢复决策门 | 2026-03-11 |
| L22 | dual-kernel parity 52/60 (86.7%)，16 个 both-case，Sniff Phase A+B | 2026-03-15 |
| 后 L22 补丁 | QUIC 多包重组、OverrideDestination、UDP datagram sniff、编译修复 | 2026-03-15 |
| L23 | TUN/Sniff 运行时补全、Provider wiring、T4 Protocol Suite、parity 92.9% | 2026-03-16 |
| L24 | 性能/安全/质量/功能补全，30 任务 (B1-B4)，综合验收 39/41 PASS | 2026-03-17 |
| L25 | 生产加固 + 跨平台补全 + 文档完善，10/10 任务，4 批次全部交付 | 2026-03-17 |

---

## 当前状态：维护态默认口径 + 最高目标实验重开

**全部阶段关闭**。dual-kernel parity 以 `labs/interop-lab/docs/dual_kernel_golden_spec.md` 为准。**默认仍是 maintenance / deployment-acceptance 口径；但在用户显式要求继续追求“可直接替换 Go sing-box 的 Rust 二进制”后，`MT-REAL-02` 已于 2026-04-16 作为实验线重开。当前实验目标不是改写 parity 账面，而是建立 Go `uTLS` ↔ Rust REALITY `ClientHello` 基线并据此继续突破 REALITY live dataplane**。

### 维护线 + 部署/验收 close-out 清单

| 线 | 状态 | 日期 |
|--------|------|------|
| MT-CONTRACT-01/02 | 已完成 | 2026-04 |
| MT-RECAP-01 | 已完成 | 2026-04 |
| MT-CONV-01/02/03 | 已完成 | 2026-04-05 |
| MT-AUDIT-01 | 已完成 | 2026-04-06 |
| 文档闭环 / 准则固化 | 已完成 | 2026-04-09 |
| MT-DEPLOY-01 | 已完成 | 2026-04-10 |
| MT-GUI-01 | 已完成 | 2026-04-10 |
| MT-GUI-02 | 已完成 | 2026-04-11 |
| MT-GUI-03 | 已完成 | 2026-04-12 |
| **MT-GUI-04** | **已完成** | **2026-04-12** |
| **MT-REAL-01** | **已收口（ARCH-LIMIT-REALITY）** | **2026-04-15** |
| **MT-REAL-02** | **实验重开（ClientHello baseline harness）** | **2026-04-16** |

### MT-REAL-02 当前结论

- 已建立 Go `uTLS` ↔ Rust REALITY `ClientHello` 基线工具链
- 首次结果：
  - Go record length `528`
  - Rust record length `241`
  - 差异不仅在顶层 GREASE/顺序，也包括：
    - 额外 cipher suites
    - `0x0012` / `0x001b` / `0x44cd` / `0xfe0d` / `0x0023` / `0xff01`
    - `supported_versions` / `supported_groups` / `key_share` / `signature_algorithms`
  - 额外发现：
    - Go `uTLS` 两次独立 dump 的 record length 与 extension order 也会变化，说明目标是动态模板族而不是单一固定报文
- 当前报告：
  - `agents-only/mt_real_02_baseline.md`
- 当前证据：
  - `agents-only/mt_real_01_evidence/clienthello_baseline/`

### MT-GUI-04 结论

- **不是** parity completion；是对所有声明完成项的 exhaustive per-capability acceptance
- 从 golden spec + GUI kernel.ts + MT-DEPLOY-01 枚举 55 项能力，6 个类别
- 双内核同时运行 + mock 公网 → 逐项测试
- **55/55 通过：35 PASS-STRICT + 7 PASS-DIV-COVERED + 13 PASS-ENV-LIMITED + 0 FAIL**
- 7 个 DIV-COVERED 全部挂到 DIV-M-005..011；13 个 ENV-LIMITED 全部有 interop-lab 真实覆盖
- 无"粗颗粒已过、细项未清"空白；无新发现；无新 blocker
- 报告：`mt_gui_04_acceptance.md`、`mt_gui_04_matrix.md`、`mt_gui_04_capability_inventory.md`、`mt_gui_04_gap_list.md`
- 证据：`mt_gui_04_evidence/`

### 维护线分类（按当前仓库事实）

- **archive-safe close-out**
  - `WP-30` archive baseline / planned seam baseline
  - `MT-SVC-01`, `MT-TEST-01`, `MT-ADP-01`
  - `MT-AUDIT-01` (reconciliation archived)
- **close-out but future boundary remains**
  - `MT-CONV-01/02/03`, `MT-OBS-01`, `MT-RTC-01/02/03`
  - `MT-HOT-OBS-01`, `MT-RD-01`, `MT-PERF-01`
  - `MT-MLOG-01`, `MT-ADM-01`, `MT-DEEP-01`

### 下一阶段默认路线

- **默认结论**：声明完成能力逐项验收已闭环；maintenance 线不再拆细卡
- **例外**：REALITY 在“最高目标”口径下已重开实验线，后续按 baseline-driven 方式推进
- **后续 agents 先看**
  - `agents-only/active_context.md`
  - `labs/interop-lab/docs/dual_kernel_golden_spec.md`
  - `agents-only/mt_real_02_baseline.md`
  - `agents-only/mt_gui_04_acceptance.md`
  - `agents-only/reference/AGENT-DEVELOPMENT-GUIDELINES.md`

### 明确暂停事项

- 不恢复 `.github/workflows/*`
- 不把 maintenance 工作误写成 dual-kernel parity completion
- 不再继续 `WP-30k` 风格微卡化排程
- 不推进 public `RuntimePlan`、public `PlannedConfigIR`、generic query API
