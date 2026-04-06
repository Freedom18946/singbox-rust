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

## 当前状态：维护模式（L1-L25 全部 Closed）

**全部阶段关闭**。项目处于稳定维护；dual-kernel parity 状态以 `labs/interop-lab/docs/dual_kernel_golden_spec.md` 为准。

### 维护线 close-out 清单（2026-04-06）

| 维护线 | 状态 | 日期 |
|--------|------|------|
| MT-CONTRACT-01/02 | 已完成 | 2026-04 |
| MT-RECAP-01 | 已完成 | 2026-04 |
| MT-CONV-01 | 已完成 | 2026-04 |
| MT-CONV-02 | 已完成 | 2026-04 |
| MT-CONV-03 | 已完成 | 2026-04-05 |
| **MT-AUDIT-01** | **已完成** | **2026-04-06** |

### MT-AUDIT-01 结论摘要

- 重新执行 5.4pro second-audit 同口径扫描，6 大风险类全部覆盖
- **Partial clearance**: P1 resolved/future-boundary; P2/P3 structural debt still-active but non-blocking
- 详见 `agents-only/mt_audit_01_reconciliation.md`
- 验证：1205 tests passed, clippy clean, no-unwrap-core PASS, boundaries 520/541

### 维护线分类（按当前仓库事实）

- **archive-safe close-out**
  - `WP-30` archive baseline / planned seam baseline
  - `MT-SVC-01`, `MT-TEST-01`, `MT-ADP-01`
  - `MT-AUDIT-01` (reconciliation archived)
- **close-out but future boundary remains**
  - `MT-CONV-01`, `MT-CONV-02`, `MT-CONV-03`
  - `MT-OBS-01`, `MT-RTC-01/02/03`
  - `MT-HOT-OBS-01`, `MT-RD-01`, `MT-PERF-01`
  - `MT-MLOG-01`, `MT-ADM-01`, `MT-DEEP-01`
- **still active / needs regrouping**
  - 无旧 maintenance 线继续维持为单独 active 卡

### 下一阶段路线收束

- **默认结论**：当前阶段应暂停继续拆新的细卡；已完成维护线不再恢复为滚动 backlog
- **若未来继续，只保留 1-3 条高层主题**
  - boundary assertion script 更新（21 stale targets）
  - tun_enhanced.rs expect() cleanup（112 production expect）
  - mega-file splits 仅在功能变更时附带推进

### 明确暂停事项

- 不恢复 `.github/workflows/*`
- 不把 maintenance 工作误写成 dual-kernel parity completion
- 不再继续 `WP-30k` 风格微卡化排程
- 不把 `future boundary` 直接写成"下一卡默认继续做"
- 不推进 public `RuntimePlan`、public `PlannedConfigIR`、generic query API
