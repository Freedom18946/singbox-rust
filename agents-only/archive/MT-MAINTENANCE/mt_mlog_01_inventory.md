# MT-MLOG-01 inventory

## 定位

- 主题：metrics / logging compat-global cleanup
- 性质：maintenance / observability quality work
- 形式：10 合 1，但实际实现严格按当前源码事实，只围绕 `metrics / logging` 仍真实存在的 compat/current/default/query seams 收口
- 非目标：dual-kernel parity completion、恢复 `.github/workflows/*`、推进 `planned.rs` 公共化、public `RuntimePlan`、public `PlannedConfigIR`、generic query API、重新打开 runtime actor/context、router/dns、tun/outbound、DERP/services 主线

## 开工前复核结论

- 仓库处于 maintenance mode，L1-L25 全部 Closed；`WP-30` 已归档，`ef333bb7` 仍是 archive baseline
- `MT-OBS-01` 与 `MT-HOT-OBS-01` 已做过一轮 observability owner/query/lifecycle 收口；本卡不能把维护工作表述成 parity completion
- 当前工作区有大量无关在制改动；本卡只围住 `metrics / logging` 直接相关文件与 `agents-only` 文档推进，没有回滚或覆盖 unrelated workspace changes
- 逐个复核目标后，当前真正值得继续收口的是：
  - `app/src/logging.rs` 的 compat 安装入口仍散在 free helper
  - `app/src/admin_debug/security_metrics.rs` 的 owner-first read path 还没有单独命名成明确 control-plane query seam
  - `crates/sb-metrics/src/lib.rs` 的 default/current/active registry helper 仍有一层重复 plumbing，env exporter parse/spawn 也还散着
  - `crates/sb-core/src/metrics/registry_ext.rs` 的 construct/register/fallback tree 仍然重复
- 同时按当前源码事实确认：
  - `app/src/telemetry.rs` 当前只是 observe/minimal facade，没有新的 compat/global debt 值得为凑卡硬改
  - `app/src/runtime_deps.rs` 当前已稳定暴露 owned metrics handle 与稳定 `AdminDebugState`
  - `app/src/analyze/registry.rs` 当前 owner/query 规模已可接受，不是这条线的真实热点

## 本轮源码收口

### `app/src/logging.rs`

- `LoggingOwner` 新增 `install_compat()`
- `init_logging(...)` 改为 owner-first helper 的 thin compat shell
- 兼容安装不再要求调用方直接摸 `ACTIVE_RUNTIME` plumbing
- 既有 owner flush / signal-task cleanup 语义保持不变

### `app/src/admin_debug/security_metrics.rs` + `app/src/admin_debug/mod.rs`

- `SecurityMetricsState` 新增 `snapshot_with_control_plane(...)`
- `snapshot()` 明确退成 compat shell，并显式暴露 `compat_snapshot()`
- `AdminDebugState::security_snapshot()` 改为走 `snapshot_with_control_plane(...)`
- 结果是 owner-first read path 与 legacy default/current snapshot path 不再混在同一层 free wrapper 命名里

### `app/src/tracing_init.rs`

- 新增 `spawn_metrics_exporter_if_configured(...)`
- `init_metrics_exporter_once(...)` 退成 compat shell：只负责 legacy “if configured then spawn + log” 语义
- 显式 exporter spawn helper 现在与 compat init 壳分开，和 `run_engine_runtime/context.rs` 的 owner-first prom exporter 语义更一致

### `crates/sb-metrics/src/lib.rs`

- `DEFAULT_REGISTRY` 改用 `parking_lot::Mutex`，去掉 poison fallback plumbing
- 新增 `current_registry_handle()`，把“当前是否存在显式 owner registry”收成单一 query seam
- `active_registry()` 现在直接复用该 seam；`shared_registry()` 继续保留 compat merged-view 壳
- 新增 `export_prometheus_active()`，明确 owner-first encode/export 语义
- env exporter parse/spawn 收成 `spawn_http_exporter_from_env_addr(...)` + `spawn_http_exporter_from_env(...)`

### `crates/sb-core/src/metrics/registry_ext.rs`

- 新增 `get_or_insert_metric(...)`
- `get_or_register_*` 系列全部复用同一层 construct/register/fallback helper
- `counter/gauge/histogram` 不再各自保留一份重复的 fallback tree / warn plumbing
- 行为保持兼容，没有引入新的 public registry/query API

## 本轮 10 合 1 实际切口

- `app/src/logging.rs`
- `app/src/admin_debug/security_metrics.rs`
- `app/src/admin_debug/mod.rs`
- `app/src/tracing_init.rs`
- `crates/sb-metrics/Cargo.toml`
- `crates/sb-metrics/src/lib.rs`
- `crates/sb-core/src/metrics/registry_ext.rs`
- 与上述直接相关的 owner/query/read tests
- 与上述直接相关的 registry encode/export tests
- 与上述直接相关的 compat shell pin

## 本轮测试 / pins

- `app/src/logging.rs`
  - `explicit_owner_does_not_install_compat_registry`
  - `explicit_owner_flush_cancels_owned_signal_task`
- `app/src/admin_debug/security_metrics.rs`
  - `explicit_snapshot_with_control_plane_uses_supplied_owner_state`
- `crates/sb-metrics/src/lib.rs`
  - `active_registry_switches_to_owned_handle_when_owner_is_installed`
  - `export_prometheus_active_prefers_installed_owner`
- `crates/sb-core/src/metrics/registry_ext.rs`
  - `repeated_registration_returns_same_instance`
  - `concurrent_registration_is_singleton`
  - `histogram_repeated_buckets_ignored_after_first`

## 验收命令

- `cargo test -p sb-metrics --all-features --lib -- --test-threads=1`
- `cargo test -p sb-core --all-features --lib registry_ext::tests -- --test-threads=1`
- `cargo test -p app --all-features --lib -- --test-threads=1`
- `cargo test -p app --all-features --test admin_auth_contract -- --test-threads=1`
- `cargo test -p app --all-features --test e2e_subs_security -- --test-threads=1`
- `cargo clippy -p app --all-features --all-targets -- -D warnings`
- `cargo clippy -p sb-metrics --all-features --all-targets -- -D warnings`
- `cargo clippy -p sb-core --all-features --all-targets -- -D warnings`

## 当前验证结论

- 上述命令已按当前 workspace 事实通过
- 本卡没有把 maintenance 工作误写成 parity completion
- 本卡没有推进 `planned.rs`、public `RuntimePlan`、public `PlannedConfigIR`
- 本卡没有为了“去 global”重新引入新的 owner/query 混乱或无主后台任务
- 本卡没有把 runtime/services/router-dns/tun-outbound 这些已稳定边界重新打穿

## Future Work（高层方向）

- `sb-metrics` 里仍有大量 `LazyLock` metric family statics；后续若继续推进，应围绕真正的 owner/query 收益，而不是把 registry surface 硬公共化
- exporter lifecycle 在 dev-cli / examples / legacy entrypoints 上仍有 detached compat 语义；若再推进，应围绕 lifecycle owner 成组处理
- `admin_debug` 里 cache / breaker / subs 的更宽 compat 面仍然存在；若 future 再做，应按 control-plane 读写边界打包，不继续拆细小卡
- 当前阶段不值得继续把 metrics/logging 债务拆成很多小尾巴；本卡结束后，剩余问题已压缩成少数高层 future boundary
