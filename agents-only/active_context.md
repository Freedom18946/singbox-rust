<!-- tier: S -->
# 当前上下文（Active Context）
> **用途**：高频更新，每次任务结束时维护。**S-tier：每次会话必读。**
> **纪律**：仅保留当前阶段最关键事实。本文件严格 ≤100 行。
---
## 战略状态
**当前阶段**: 维护模式，L1-L25 全部 Closed
**Parity**: 92.9% (52/56)，以 `labs/interop-lab/docs/dual_kernel_golden_spec.md` 为准
**当前阶段焦点**: 维护闭环已完成，转入“实际部署收尾验收准备”

## 最近闭环（2026-04-09）

### 文档闭环与长期准则固化 — 已完成
- 已将 Rust 规范与 maintenance/audit 复盘结论固化为长期开发准则：
  - `agents-only/reference/AGENT-DEVELOPMENT-GUIDELINES.md`
  - `agents-only/Rust_spec_v2.md`
  - `agents-only/mt_audit_01_reconciliation.md`
  - `agents-only/mt_audit_01_full_report.md`
- 已将下一阶段切换为“部署收尾验收准备”：
  - `agents-only/deployment_acceptance_next_stage.md`
- `README.md` / `init.md` / `active_context.md` / `workpackage_latest.md` 已统一改为收束口径，不再以 maintenance 拆卡为默认动作

### 已完成维护线（归档视角）
- `WP-30` archive baseline、`MT-SVC-01`、`MT-TEST-01`、`MT-ADP-01`：archive-safe close-out
- `MT-OBS-01`、`MT-RTC-01/02/03`、`MT-HOT-OBS-01`、`MT-MLOG-01`、`MT-ADM-01`、`MT-RD-01`、`MT-PERF-01`、`MT-DEEP-01`、`MT-CONV-01/02/03`：close-out，但仅保留高层 future boundary
- `MT-AUDIT-01`：给出最终复扫结论 `Partial clearance, no current blocker`

## 当前验证事实
- 全部 1205 sampled tests 通过，clippy clean，no-unwrap-core PASS
- Boundary 21/541 failures 均为 stale targets（v2.rs split, bootstrap decomposition）

## 当前阶段结论
- maintenance 主线已整体闭环，当前没有新的最前置 blocker
- 5.4pro second-audit P1 findings 已 resolved 或降级为 architecturally-accepted future boundary
- 当前默认目标不是继续拆 maintenance 卡，而是准备“实际部署收尾验收”

## 当前默认准则
- 后续 agents 先读：`active_context.md` → `workpackage_latest.md` → `reference/AGENT-DEVELOPMENT-GUIDELINES.md` → `deployment_acceptance_next_stage.md`
- 不恢复细碎 maintenance 排程
- 不把 maintenance / quality work 写成 parity completion
- 不把 `future boundary` 自动等同于“下一卡默认继续做”

## 部署验收前保留的高层 boundary
- lifecycle-aware compat shells / metrics statics / registry bootstrap：允许保留，但需诚实标注为 future boundary
- 4 个 mega-file、`tun_enhanced.rs` residual panic density、spawn coverage 未全量分类：仍是 non-blocking structural debt
- 若未来继续推进，只允许以少数高层 regroup 主题立项，不再恢复旧线名

## 暂停事项
- 不恢复 `.github/workflows/*`
- 不恢复 `WP-30k` 风格微卡
- 不推进 public `RuntimePlan`、public `PlannedConfigIR`、generic query API
