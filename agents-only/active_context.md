<!-- tier: S -->
# 当前上下文（Active Context）
> **用途**：高频更新，每次任务结束时维护。**S-tier：每次会话必读。**
> **纪律**：仅保留当前阶段最关键事实。本文件严格 ≤100 行。
---
## 战略状态
**当前阶段**: 维护模式，L1-L25 全部 Closed
**Parity**: 92.9% (52/56)，以 `labs/interop-lab/docs/dual_kernel_golden_spec.md` 为准
**当前维护线**: `MT-AUDIT-01` full rescan and audit reconciliation — 已完成

## 最近完成（2026-04-06）

### MT-AUDIT-01：full rescan and audit reconciliation — 已完成
- 性质：maintenance / audit-quality work，不是 parity completion
- 重新执行 5.4pro second-audit 同口径扫描，对比 6 大风险类的原始基线
- 产出：`agents-only/mt_audit_01_reconciliation.md`（B-tier，可归档参考）
- 结论：**Partial clearance**
  - P1 items (lifecycle singletons, hot-path panics in core, config boundary debt) 已 resolved 或降级为 future boundary
  - P2/P3 structural debt (mega-files, tun_enhanced expect, spawn tracking) 仍为 still-active，但均非 blocker
- 验证：
  - `cargo test -p sb-core --all-features --lib` ✅ 703 passed
  - `cargo test -p app --all-features --lib` ✅ 286 passed
  - `cargo test -p sb-adapters --all-features --lib` ✅ 216 passed
  - `cargo clippy --workspace --all-features --all-targets -- -D warnings` ✅
  - `no-unwrap-core.sh` ✅ PASS
  - `make boundaries` 520/541 passed (21 stale assertion targets, not regressions)

### MT-CONV-03：standalone entrypoint logging/tracing convergence — 已完成
- standalone bins 与 cli/run.rs 的 entrypoint install contract 已收敛

## 当前验证事实
- 全部 1205 sampled tests 通过，clippy clean，no-unwrap-core PASS
- Boundary 21/541 failures 均为 stale targets（v2.rs split, bootstrap decomposition）

## 当前阶段结论
- 5.4pro second-audit P1 findings 已 resolved 或降级为 architecturally-accepted future boundary
- 剩余 still-active items 均为 structural debt，非 blocker
- 不存在需要立即响应的回归或新风险

## 剩余 future boundary（压缩后）
- Lifecycle-aware singleton shells (logging, security_metrics, geoip, prefetch) — Weak<T> pattern
- Metrics LazyLock statics — prometheus standard pattern
- registry_ext.rs Box::leak — intentional 'static promotion
- 21 stale boundary assertions — need script update, not code change

## 剩余 still-active structural debt（非 blocker）
- 4 mega-files >3000L (derp/server, register, ir/raw, dns/upstream)
- tun_enhanced.rs 112 production expect()
- 304 total tokio::spawn (tracking coverage unaudited)

## 暂停事项
- 不恢复细碎 maintenance 排程
- 不把 maintenance work 写成 parity completion
- 不把 `future boundary` 自动等同于"下一卡默认继续做"
