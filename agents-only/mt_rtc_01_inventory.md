# MT-RTC-01 inventory

## 定位

- 主题：runtime actor/context consolidation
- 性质：maintenance / runtime quality work
- 目标：沿现有 runtime seam 再收一轮 owner-first context / deps / lifecycle discipline
- 非目标：dual-kernel parity completion、恢复 `WP-30k` ~ `WP-30as` 编号体系、public `RuntimePlan`、public `PlannedConfigIR`、generic query API、重做 `bootstrap.rs` / `run_engine.rs` 巨石

## 本轮源码事实与收口

### `app/src/run_engine_runtime/*`

- `context.rs`
  - 新增 `RuntimeContext`
  - 显式持有 `AppRuntimeDeps`、reload fingerprint/state
  - 提供 owner-first `admin_state()` / `metrics_registry()` / `maybe_start_prom_exporter(...)`
- `context.rs`
  - 新增 `PromExporterHandle`
  - Prom exporter 不再在 `supervisor.rs` 中起完就丢 handle
  - shutdown 时显式 abort + await
- `context.rs`
  - 新增 `RuntimeLifecycle`
  - 聚合 watch / admin services / prom exporter shutdown
- `supervisor.rs`
  - startup 改为围绕 `RuntimeContext::from_raw(...)`
  - `AdminStartContext` / `WatchRuntime` / `RuntimeLifecycle` 成为统一 wiring 路径
  - `run_engine.rs` 继续只是 facade
- `admin_start.rs`
  - 新增 `AdminStartContext`
  - admin startup 改吃显式 runtime context，而不是零散 `opts + supervisor + runtime_deps`
- `watch.rs`
  - 新增 `WatchRuntime`
  - watch/reload 的输入状态（entries / config inputs / import path / reload state / supervisor）收成显式 owner object
- `output.rs`
  - startup 输出改从 `RuntimeContext` 读取 startup fingerprint
  - `output` 不再只吃裸字符串 fingerprint

### `app/src/bootstrap_runtime/*`

- `dns_apply.rs`
  - 新增 `DnsRuntimeEnv`
  - runtime helper 现在可走 `DnsRuntimeEnv::from_config(...).apply()`
  - 先算出显式 env plan，再做 side effect
- `proxy_registry.rs`
  - 新增 `ProxyRegistryPlan`
  - runtime helper 现在可走 `ProxyRegistryPlan::from_env().install()`
  - 先算出显式 registry plan，再做 global install
- `bootstrap.rs`
  - 继续是 legacy facade / compat shell
  - 仅接线到 `DnsRuntimeEnv` / `ProxyRegistryPlan`
  - 没有重新回灌 runtime owner 逻辑

## 配套修正

- `app/src/admin_debug/reloadable.rs`
  - `loom` smoke test 从过期 `CONFIG` 名字修正到当前 `DEFAULT_STORE`
- `app/tests/admin_auth_contract.rs`
  - `AdminDebugState` 构造补齐 `breaker` / `cache` / `reloadable`，与当前 owner 结构对齐

## 本轮测试 pins

- `run_engine_runtime::context::tests::runtime_context_tracks_reload_fingerprint`
- `run_engine_runtime::context::tests::runtime_lifecycle_shutdown_aborts_owned_prom_exporter_task`
- `run_engine_runtime::watch::tests::watch_handle_shutdown_waits_for_spawned_task`
- `run_engine_runtime::watch::tests::watch_runtime_carries_explicit_reload_wiring`
- `bootstrap_runtime::dns_apply::tests::dns_runtime_env_collects_vars_before_side_effects`
- `bootstrap_runtime::proxy_registry::tests::proxy_registry_plan_collects_registry_before_install`

## 验收命令

- `cargo test -p app --all-features --lib -- --test-threads=1`
- `cargo clippy -p app --all-features --all-targets -- -D warnings`

## 当前边界

- `crates/sb-config/src/ir/planned.rs` 仍是 staged crate-private seam
- 当前仍无 public `RuntimePlan`
- 当前仍无 public `PlannedConfigIR`
- 当前仍无 generic query API
- `app/src/run_engine.rs` / `app/src/bootstrap.rs` 继续视为 facade / legacy shell，不重新长回 owner 巨石

## Future Work（高层方向）

- signal / reload / shutdown 更统一的 runtime manager / actor 化
- router / dns / inbounds 更深一层 handle 化，但只在真实 consumer 出现时继续推进
- observability、DNS/router mega-file、TUN 热路径、metrics compat/global 的后续 maintenance 治理
