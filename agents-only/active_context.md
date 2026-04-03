<!-- tier: S -->
# 当前上下文（Active Context）
> **用途**：高频更新，每次任务结束时维护。**S-tier：每次会话必读。**
> **纪律**：仅保留当前阶段最关键事实。本文件严格 ≤100 行。
---
## 战略状态
**当前阶段**: 维护模式，L1-L25 全部 Closed
**Parity**: 92.9% (52/56)，以 `labs/interop-lab/docs/dual_kernel_golden_spec.md` 为准
**当前维护线**: `MT-MLOG-01` metrics / logging compat-global cleanup — 已完成；`MT-ADP-01`、`MT-PERF-01`、`MT-RD-01`、`MT-TEST-01`、`MT-SVC-01`、`MT-HOT-OBS-01`、`MT-RTC-03`、`MT-RTC-02`、`MT-RTC-01`、`MT-OBS-01` 与 `WP-30` 继续保持已完成 / 已归档状态

## 最近完成（2026-04-03）

### MT-MLOG-01：metrics / logging compat-global cleanup — 已完成
- 本卡按当前源码与工作区事实推进，性质明确为 maintenance / observability quality work，不是 dual-kernel parity completion；没有恢复 `.github/workflows/*`，也没有推进 `planned.rs`、public `RuntimePlan`、public `PlannedConfigIR`、generic query API
- 开工前复核确认：`app/src/logging.rs`、`app/src/admin_debug/security_metrics.rs`、`crates/sb-metrics/src/lib.rs`、`crates/sb-core/src/metrics/registry_ext.rs` 仍有值得继续收口的一层 compat/current/default plumbing；`app/src/telemetry.rs`、`app/src/runtime_deps.rs`、`app/src/analyze/registry.rs` 当前邻接 seam 已可接受，不为凑卡硬改
- 本轮真实收口：
  - `app/src/logging.rs`：`LoggingOwner::install_compat()` 成为显式 compat 安装入口；`init_logging(...)` 退成 thin compat shell，owner-first 路径不再需要直接摸 `ACTIVE_RUNTIME`
  - `app/src/admin_debug/security_metrics.rs`：新增 `snapshot_with_control_plane(...)` 与 `compat_snapshot()`，把 owner-first read path 和 legacy default/current snapshot 壳分开；`app/src/admin_debug/mod.rs` 改走显式 control-plane query seam
  - `app/src/tracing_init.rs`：新增 `spawn_metrics_exporter_if_configured(...)`，把“显式 exporter spawn”与 `init_metrics_exporter_once(...)` 的 compat 壳分开
  - `crates/sb-metrics/src/lib.rs`：`DEFAULT_REGISTRY` 改用 `parking_lot::Mutex`，新增 `current_registry_handle()` 与 `export_prometheus_active()`；`active/current/shared` 语义更清楚，env exporter parse/spawn helper 不再重复散落
  - `crates/sb-core/src/metrics/registry_ext.rs`：新增 `get_or_insert_metric(...)`，统一 counter/gauge/histogram 的 construct/register/fallback plumbing，减少重复 compat/fallback 树
- 本轮新增 / 强化的关键 pin：
  - `app/src/admin_debug/security_metrics.rs`：`explicit_snapshot_with_control_plane_uses_supplied_owner_state`
  - `crates/sb-metrics/src/lib.rs`：`active_registry_switches_to_owned_handle_when_owner_is_installed`、`export_prometheus_active_prefers_installed_owner`
  - `app/src/logging.rs` 既有 `explicit_owner_does_not_install_compat_registry` 与 `explicit_owner_flush_cancels_owned_signal_task` 继续 pin 住 owner/compat 边界

## 当前稳定事实
- `logging` 的 compat shell 已压缩到少数明确入口：`init_logging(...)` 与 `flush_logs()`
- `security_metrics` 的 owner-first读路径已明确收口到 `snapshot_with_control_plane(...)`；legacy `snapshot()` 继续仅作为 compat wrapper
- `sb-metrics` 的 registry 安装 / 当前 owner 查询 / active export 语义已对齐一轮；shared/global merged view 仍只留在兼容路径
- `tracing_init.rs` / `telemetry.rs` / `runtime_deps.rs` 当前没有被重新做大；prom exporter owner 主线仍在 `run_engine_runtime/context.rs`
- `planned.rs` 仍是 staged crate-private seam；当前仓库仍无 public `RuntimePlan`、public `PlannedConfigIR`、generic query API
- 当前 workspace 仍存在大量无关在制改动；本卡只触达 metrics/logging 相关文件与 `agents-only` 文档，没有回滚或覆盖 unrelated workspace changes

## 当前验证事实
- 已通过：
  - `cargo test -p sb-metrics --all-features --lib -- --test-threads=1`
  - `cargo test -p sb-core --all-features --lib registry_ext::tests -- --test-threads=1`
  - `cargo test -p app --all-features --lib -- --test-threads=1`
  - `cargo test -p app --all-features --test admin_auth_contract -- --test-threads=1`
  - `cargo test -p app --all-features --test e2e_subs_security -- --test-threads=1`
  - `cargo clippy -p app --all-features --all-targets -- -D warnings`
  - `cargo clippy -p sb-metrics --all-features --all-targets -- -D warnings`
  - `cargo clippy -p sb-core --all-features --all-targets -- -D warnings`

## Future Work（高层方向）
- metrics/logging 剩余债务现在应压缩成少数高层 boundary：
  - `sb-metrics` 里仍然存在大量 `LazyLock` metric family statics；只有在真实 owner/query 收益出现时再继续动
  - dev-cli / examples / legacy exporter 启动路径仍有 detached compat 语义，但 runtime 主线已经由 `PromExporterHandle` 持有；后续若继续收口，应围绕 exporter lifecycle owner，而不是继续散修 helper
  - `admin_debug` 里 cache / breaker / subs legacy wrappers 仍有更宽的 compat 面；若再推进，应按 control-plane read/write boundary 成组处理，而不是细碎拆卡

## 归档判断
- `WP-30` 继续视为 archive baseline，`ef333bb7` 仍是归档基线
- `MT-MLOG-01` 已完成；当前 metrics/logging 剩余债务已压缩成少数高层 future boundary，不值得继续拆很多小卡
