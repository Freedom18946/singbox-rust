# MT-OBS-01 inventory

## 定位

- 主题：runtime / control-plane / observability ownership consolidation
- 性质：maintenance / quality work
- 非目标：dual-kernel parity completion、`planned.rs` 公共化、public `RuntimePlan`、public `PlannedConfigIR`、generic query API、更大的 runtime actor/context 化

## 本轮已落地事实

- `app/src/admin_debug/reloadable.rs`
  - `ReloadableConfigStore` 成为显式 owner
  - `ReloadSignalHandle` 收口 SIGHUP reload lifecycle
  - 旧 `get/apply/version/reload` 继续保留 compat 壳
- `app/src/admin_debug/cache.rs`
  - `CacheStore` 成为 owner-first store
  - `global()` 退化为 compat 壳
  - `byte_usage_snapshot()` 明确 query helper
- `app/src/admin_debug/breaker.rs`
  - `BreakerStore` 成为 owner-first store
  - `global()` 退化为 compat 壳
  - `state_stats_snapshot()` 明确 query helper
- `app/src/admin_debug/security_metrics.rs`
  - 新增 `SecuritySnapshotQuery`
  - `snapshot_with_query(...)` 成为显式 query seam
  - 旧 `snapshot()` 继续保留 compat 路径
- `app/src/admin_debug/mod.rs` / `app/src/runtime_deps.rs`
  - `AdminDebugState` / `AppRuntimeDeps` 显式持有 breaker/cache/reloadable/security_metrics owner
  - `security_snapshot()` / `config_version()` 变成 owner-first facade
- `app/src/admin_debug/http_server.rs`
  - `AdminDebugHandle` 可挂载 reload signal handle
  - shutdown/drop 会一起取消 reload signal task
- `crates/sb-metrics/src/lib.rs`
  - 新增 `active_registry()` 区分 owner-first registry access
  - `MetricsRegistryOwner::encode_text()` 补 owner-first query helper
- `crates/sb-core/src/metrics/registry_ext.rs`
  - collector registration / fallback helper 收口
  - 保留 `'static` compat API，但移除散落 `eprintln!` 和复杂 emergency fallback 树

## 本轮测试 pins

- `app/src/logging.rs` 现有 owner/compat pin 继续有效
- `app/src/admin_debug/reloadable.rs`
  - `signal_handle_shutdown_completes`
- `app/src/admin_debug/security_metrics.rs`
  - `explicit_snapshot_query_uses_supplied_control_plane_state`
- `crates/sb-metrics/src/lib.rs`
  - `active_registry_switches_to_owned_handle_when_owner_is_installed`

## 验收命令

- `cargo test -p app --features admin_debug,admin_tests,dev-cli --lib -- --test-threads=1`
- `cargo test -p sb-metrics --lib -- --test-threads=1`
- `cargo test -p sb-core --features metrics --lib registry_ext::tests -- --test-threads=1`
- `cargo clippy -p app --features admin_debug,admin_tests,dev-cli --lib -- -D warnings`
- `cargo clippy -p sb-metrics --all-targets -- -D warnings`
- `cargo clippy -p sb-core --features metrics --lib --tests -- -D warnings`
