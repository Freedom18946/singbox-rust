<!-- tier: S -->
# 当前上下文（Active Context）
> **用途**：高频更新，每次任务结束时维护。**S-tier：每次会话必读。**
> **纪律**：仅保留当前阶段最关键事实。本文件严格 ≤100 行。
---
## 战略状态
**当前阶段**: 维护模式，L1-L25 全部 Closed
**Parity**: 92.9% (52/56)，以 `labs/interop-lab/docs/dual_kernel_golden_spec.md` 为准
**当前维护线**: `MT-RECAP-01` maintenance recap and next-stage convergence — 已完成；`WP-30` 与 `MT-OBS-01`、`MT-RTC-01/02/03`、`MT-HOT-OBS-01`、`MT-SVC-01`、`MT-TEST-01`、`MT-RD-01`、`MT-PERF-01`、`MT-ADP-01`、`MT-MLOG-01`、`MT-ADM-01`、`MT-DEEP-01` 保持已完成 / 已归档状态

## 最近完成（2026-04-03）

### MT-RECAP-01：maintenance recap and next-stage convergence — 已完成
- 本卡按当前仓库事实推进，性质明确为 maintenance / planning-quality work，不是 dual-kernel parity completion；没有恢复 `.github/workflows/*`，也没有推进 `planned.rs` 公共化、public `RuntimePlan`、public `PlannedConfigIR`、generic query API
- 开工前已重建上下文并复核当前仓库事实：
  - 已重新阅读 `AGENTS.md`、`agents-only/{active_context,workpackage_latest,planned_preflight_inventory}.md`、全部已完成 maintenance inventory、`重构package相关/2026-03-25_5.4pro第三次审计核验记录.md`、`重构package相关/singbox_rust_rebuild_workpackage.md`
  - `git status --short --branch` 显示当前在 `main...origin/main`，但 workspace 仍有大量无关在制改动；其中包含 `app/src/admin_debug/{middleware/rate_limit,prefetch}.rs`、`crates/sb-config/src/ir/planned.rs` 等，本卡未回滚或覆盖这些改动
  - `git log --oneline --decorate -n 20` 确认最近主线连续提交已覆盖 `MT-OBS-01` 到 `MT-DEEP-01`，`a7eb1e4e` 为当前 `main`
- 源码抽样复核确认：
  - `crates/sb-config/src/ir/planned.rs` 仍是 staged crate-private seam；`collect_planned_facts` / `validate_with_planned_facts` / `validate_planned_facts` 仍为 `pub(crate)`，`Config::validate()` 继续走 thin entry；当前仍无 public `RuntimePlan`、public `PlannedConfigIR`
  - `app/src/run_engine_runtime/context.rs` 与 `app/src/admin_debug/mod.rs` 继续围绕 `RuntimeContext` / `AdminDebugState` 提供 owner-first runtime/admin wiring；runtime actor/context 主线已 close-out，不应按旧细卡继续拆
  - `crates/sb-core/src/router/{shared_index,runtime_override}.rs` 与 `crates/sb-core/src/dns/upstream_pool.rs` 仍是当前 router/dns 结构边界；mega-file 风险还在，但已不是新的最前置 blocker
  - `crates/sb-adapters/src/outbound/shadowtls.rs`、`crates/sb-adapters/src/inbound/{tun_session,tun_enhanced}.rs` 仍保持 ShadowTLS wrapper raw-stream 语义与 detached/draining TUN TCP lifecycle seam；deep corner-case 线已收成高层 boundary

## 当前验证事实
- 已通过最小充分跨模块验证：
  - `cargo test -p app --all-features --lib -- --test-threads=1`
  - `cargo test -p sb-core --all-features --lib -- --test-threads=1`
  - `cargo test -p sb-adapters --all-features --lib -- --test-threads=1`
  - `cargo clippy -p app --all-features --all-targets -- -D warnings`
  - `cargo clippy -p sb-core --all-features --all-targets -- -D warnings`
  - `cargo clippy -p sb-adapters --all-features --all-targets -- -D warnings`

## 当前阶段结论
- 当前没有新的“最前置基线阻塞”或必须立即开卡的质量问题；仓库事实更支持“收束下一阶段路线”，而不是继续机械拆 maintenance 细卡
- 可明确视为 archive-safe close-out 的主线：
  - `WP-30` archive baseline / planned seam baseline
  - `MT-SVC-01`
  - `MT-TEST-01`
  - `MT-ADP-01`
- 已 close-out 但仍保留高层 future boundary 的主线：
  - `MT-OBS-01`、`MT-RTC-01/02/03`、`MT-HOT-OBS-01`、`MT-MLOG-01`、`MT-ADM-01`
  - `MT-RD-01`
  - `MT-PERF-01`、`MT-DEEP-01`
- 当前没有需要继续按“单线 still active”维持的旧 maintenance 卡；剩余未来工作只应按跨线高层 boundary regroup

## Next-Stage Gates（只保留高层主题）
- 默认结论：**当前阶段不建议继续拆新的细卡**
- 若未来确需继续推进，只保留 1-3 条高层主题：
  - runtime / control-plane / observability convergence：signal/reload/shutdown manager、`logging` / `security_metrics` / `subs` limiter 等剩余 compat-owner boundary 必须成组推进
  - router / dns / tun / outbound convergence：router/dns mega-file shared-state、TUN/outbound lifecycle/perf、ShadowTLS wrapper contract / detached TCP lifecycle 必须按系统主题成组推进
  - planned/private seam 仅在出现真实稳定 consumer 时再评估；当前明确暂停 public `RuntimePlan` / public `PlannedConfigIR` / generic query API

## 暂停事项
- 不再恢复 `WP-30k` ~ `WP-30as` 式细碎 maintenance 排程
- 不把 maintenance work 写成 parity completion
- 不把 `future boundary` 自动等同于“下一卡默认继续做”
