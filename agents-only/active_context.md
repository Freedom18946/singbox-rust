<!-- tier: S -->
# 当前上下文（Active Context）
> **用途**：高频更新，每次任务结束时维护。**S-tier：每次会话必读。**
> **纪律**：仅保留当前阶段最关键事实。本文件严格 ≤100 行。
---
## 战略状态
**当前阶段**: 维护模式，L1-L25 全部 Closed
**Parity**: 92.9% (52/56)，以 `labs/interop-lab/docs/dual_kernel_golden_spec.md` 为准
**当前维护线**: `MT-CONV-03` standalone entrypoint logging/tracing convergence — 已完成

## 最近完成（2026-04-05）

### MT-CONV-03：standalone entrypoint logging/tracing convergence — 已完成
- 性质：maintenance / structural-quality work，不是 parity completion
- 本轮收敛的是 standalone bins 与 cli/run.rs 的 entrypoint install contract：
  - `lib.rs` 的 `tracing_init` 模块从 `observe || dev-cli` feature gate 改为始终 pub 暴露
  - `bin/run.rs`、`bin/tools.rs` 手搓 `tracing_subscriber::fmt()...init()` → `app::tracing_init::init_tracing_once()`
  - `bin/metrics-serve.rs` 手搓 tracing init + 手动 exporter → canonical `init_tracing_once()` + `install_configured_metrics_exporter()`
  - `cli/run.rs` 两次独立 `AppRuntimeDeps::new()` → 合并为单次构建 + 条件 fallback
- 复核后刻意不动：`sb-explaind`、`diag`、`sb-bench`、`probe-outbound`（功能特化 dev 工具，强行统一收益不大）
- 验证：
  - `cargo test -p app --all-features --lib -- --test-threads=1` ✅ 286 passed
  - `cargo test -p app --all-features --bin app -- --test-threads=1` ✅ 186 passed
  - `cargo test -p app --all-features --test admin_auth_contract -- --test-threads=1` ✅ 7 passed
  - `cargo test -p app --all-features --test e2e_subs_security -- --test-threads=1` ✅ 23 passed
  - `cargo test -p sb-metrics --all-features --lib -- --test-threads=1` ✅ 19 passed
  - `cargo test -p sb-core --all-features --lib registry_ext::tests -- --test-threads=1` ✅ 4 passed
  - `cargo clippy -p app --all-features --all-targets -- -D warnings` ✅
  - `cargo clippy -p sb-metrics --all-features --all-targets -- -D warnings` ✅
  - `cargo clippy -p sb-core --all-features --all-targets -- -D warnings` ✅

### MT-CONV-02：logging / tracing install convergence — 已完成
- app 主路径上的 logging/tracing/exporter install contract 收成 owner-first / compat shell / metrics exporter plan

### MT-CONV-01：runtime / control-plane / observability convergence — 已完成
- exporter lifecycle owner 统一到 `MetricsExporterHandle` + `AppObservability`
- admin read/query 收成 `AdminDebugQuery`

## 当前验证事实
- 全部测试与 clippy 通过（见上方验证详情）

## 当前阶段结论
- install 语义现在在三个层面明确：
  - main.rs: `install_logging_owner` — 完整 owner（flush/signal/redaction）
  - standalone bins: `init_tracing_once` — 轻量 canonical subscriber init
  - compat paths: `install_logging_compat` / `install_compat_metrics_exporter` — legacy shell
- 本轮没有误推进 `RuntimePlan` / `PlannedConfigIR` / generic query API
- 本轮没有把 logging/tracing entrypoint 以外的主题卷进来

## 剩余 future boundary（压缩后）
- 部分 dev/debug 专属 bins 仍无 tracing init 或用独立路径；强行统一收益不大
- `logging owner` vs `tracing init` 分层是有意义的，不需要进一步合并
- standalone bins / legacy exporter entrypoints 的 convergence 至此已基本完成

## 暂停事项
- 不恢复细碎 maintenance 排程
- 不把 maintenance work 写成 parity completion
- 不把 `future boundary` 自动等同于"下一卡默认继续做"
