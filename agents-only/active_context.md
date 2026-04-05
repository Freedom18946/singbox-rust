<!-- tier: S -->
# 当前上下文（Active Context）
> **用途**：高频更新，每次任务结束时维护。**S-tier：每次会话必读。**
> **纪律**：仅保留当前阶段最关键事实。本文件严格 ≤100 行。
---
## 战略状态
**当前阶段**: 维护模式，L1-L25 全部 Closed
**Parity**: 92.9% (52/56)，以 `labs/interop-lab/docs/dual_kernel_golden_spec.md` 为准
**当前维护线**: `MT-CONV-02` logging / tracing install convergence — 已完成

## 最近完成（2026-04-05）

### MT-CONV-02：logging / tracing install convergence — 已完成
- 性质：maintenance / structural-quality work，不是 parity completion
- 本轮真正收敛的是 install contract，而不是重写日志系统：
  - `app/src/logging.rs` 引入 `install_logging_owner(...)` / `install_logging_compat(...)`
  - `init_logging(...)` / `init_logging_with_owner(...)` 明确退为 compat shell
  - `app/src/tracing_init.rs` 引入 `MetricsExporterPlan` 与 `install_metrics_exporter*` canonical 入口
  - `start_metrics_exporter*` / `init_metrics_exporter_once(...)` 保留为 compat shell
  - `app/src/runtime_deps.rs` 的 `AppObservability` 现在同时承担 owner-first / configured / compat exporter install
  - `RuntimeContext`、`telemetry.rs`、`cli/run.rs` 不再各自保留平行 exporter install glue
- 复核后刻意不硬改：
  - `app/src/analyze/registry.rs`
  - `crates/sb-metrics/src/lib.rs`
  - `crates/sb-core/src/metrics/registry_ext.rs`
  - 当前这层 registry/query seam 已稳定；继续 churn 不会提高 install convergence 质量
- 验证：
  - `cargo test -p app --all-features --lib -- --test-threads=1` ✅
  - `cargo test -p app --all-features --bin app -- --test-threads=1` ✅
  - `cargo test -p app --all-features --test admin_auth_contract -- --test-threads=1` ✅
  - `cargo test -p app --all-features --test e2e_subs_security -- --test-threads=1` ✅
  - `cargo test -p sb-metrics --all-features --lib -- --test-threads=1` ✅
  - `cargo test -p sb-core --all-features --lib registry_ext::tests -- --test-threads=1` ✅
  - `cargo clippy -p app --all-features --all-targets -- -D warnings` ✅
  - `cargo clippy -p sb-metrics --all-features --all-targets -- -D warnings` ✅
  - `cargo clippy -p sb-core --all-features --all-targets -- -D warnings` ✅

### MT-CONV-01：runtime / control-plane / observability convergence — 已完成
- exporter lifecycle owner 统一到 `MetricsExporterHandle` + `AppObservability`
- admin read/query 收成 `AdminDebugQuery`
- 这些 seam 现在是 `MT-CONV-02` 的稳定前置，不再回退成分散 helper

### MT-CONTRACT-02：transport/session contract convergence — 已完成
- ShadowTLS typed wrapper contract、TUN detached/draining cleanup policy 已完成并稳定

## 当前验证事实
- `app --all-features --lib`、`app --all-features --bin app`、`admin_auth_contract`、`e2e_subs_security` 全部通过
- `sb-metrics --all-features --lib` 通过
- `sb-core --all-features --lib registry_ext::tests` 通过
- `app` / `sb-metrics` / `sb-core` 对应 clippy 全部 0 warnings

## 当前阶段结论
- 当前没有新的基线阻塞或必须立即开卡的问题
- install 语义现在清楚分成：
  - logging owner install
  - logging compat install
  - metrics exporter explicit install
  - metrics exporter configured/compat install
- 本轮没有误推进 `RuntimePlan` / `PlannedConfigIR` / generic query API
- 本轮没有把 logging / tracing 以外主题卷回主线

## 剩余 future boundary（压缩后）
- 若未来继续，只保留更高层的 tracing subscriber / logging bootstrap 统一，而不是继续拆 install 小尾巴
- standalone bins / legacy exporter entrypoints 若再统一，应成组处理，不单点扩散到 read-model 或 registry internals

## 暂停事项
- 不恢复细碎 maintenance 排程
- 不把 maintenance work 写成 parity completion
- 不把 `future boundary` 自动等同于“下一卡默认继续做”
