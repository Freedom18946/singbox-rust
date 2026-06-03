# MT-RTC-02 inventory

## 定位

- 主题：runtime actorization follow-up
- 性质：maintenance / runtime quality work
- 形式：runtime owner/query/manager seam 10 合 1 收口
- 非目标：dual-kernel parity completion、恢复 `WP-30k` ~ `WP-30as` 编号体系、public `RuntimePlan`、public `PlannedConfigIR`、generic query API、把 `run_engine.rs` / `bootstrap.rs` 重新做大

## 本轮源码事实与收口

### `app/src/runtime_deps.rs` + `app/src/admin_debug/*`

- `runtime_deps.rs`
  - `AppRuntimeDeps` 现在预组装并缓存稳定的 `AdminDebugState`
  - `admin_state()` 变成稳定 handle clone，而不是每次临时拼一份新 state
- `admin_debug/mod.rs`
  - `AdminDebugState` 改成 private fields + 显式 constructor
  - 新增 `analyze_registry()`、`security_metrics_state()`、`prefetch_queue_high_watermark()`、`started_at()`、`spawn_reload_signal()`
  - `init()` 不再偷走 `reloadable::init_signal_handler()` 默认 owner，而是跟随 supplied state 的 reloadable owner
- `admin_debug/http_server.rs`
  - `/subs/*` 读路径改走 `state.security_metrics_state()`
  - `http_server` test state 与 integration tests 均改成 `AdminDebugState::new(...)`
- `admin_debug/endpoints/{health,metrics,analyze}.rs`
  - query/read path 不再直接摸 `AdminDebugState` public field
  - control-plane 现在围绕显式 query method 读取 analyze registry、started_at、prefetch watermark

### `app/src/run_engine_runtime/*`

- `context.rs`
  - `RuntimeContext` 新增 `admin_reload_signal()` 与 `watch_runtime(...)`
  - active runtime owner 不再只是“装状态的 struct”，而是开始直接派生 admin/watch runtime seam
- `admin_start.rs`
  - admin debug startup 先拿显式 `admin_state`，再通过 `ctx.runtime.admin_reload_signal()` 挂载 reload signal
  - 不再走 `reloadable::init_signal_handler()` 的隐式 default owner 路径
- `supervisor.rs`
  - watch startup 改成通过 `RuntimeContext::watch_runtime(...)` 派生
  - `run_engine.rs` 继续只是 facade，没有回灌 owner 逻辑
- `watch.rs`
  - `WatchHandle` 从 oneshot stop sender 改成 `CancellationToken` + owned `JoinHandle`
  - `shutdown()` 仍显式 cancel + await
  - `Drop` 现在也会 cancel，避免丢失 handle 后留下无主 watch task

### `app/src/bootstrap_runtime/*` + `app/src/bootstrap.rs`

- `bootstrap_runtime/inbounds.rs`
  - 新增 `InboundRuntimeDeps`
  - inbound startup 支持“显式 deps carrier -> start_from_ir(...)”路径
  - compat `start_inbounds_from_ir(...)` 继续保留，但只当 thin shell
- `bootstrap_runtime/router_helpers.rs`
  - 新增 `RouterRuntime`
  - `RouterRuntime::from_env()` 统一承接 router handle + max_rules env
  - `install_config_index(...)` 负责显式 build/apply router index
- `bootstrap_runtime/runtime_shell.rs`
  - 新增 `Runtime::new(...)`
  - legacy runtime shell 仍负责 shutdown 汇总，但构造路径不再散落结构体字面量
- `bootstrap.rs`
  - `build_router_index_from_config(...)` 改成委托 `bootstrap_runtime::router_helpers`
  - `start_from_config(...)` 改走 `RouterRuntime::from_env()`、`InboundRuntimeDeps::new(...)`、`Runtime::new(...)`
  - facade 继续保持薄，没有把 runtime owner 逻辑重新灌回 `bootstrap.rs`

## 本轮测试 / pins

- `runtime_deps::tests::app_runtime_deps_reuses_stable_admin_state_handle`
- `run_engine_runtime::watch::tests::watch_handle_drop_cancels_spawned_task`
- `bootstrap_runtime::router_helpers::tests::router_runtime_from_env_tracks_rule_limit`
- `bootstrap_runtime::inbounds::tests::start_inbounds_facade_keeps_compat_shell`
- 既有 source pin 已对齐：
  - `run_engine_runtime::admin_start::tests::wp30ao_pin_admin_start_owner_moved_out_of_run_engine_rs`
  - `bootstrap_runtime::inbounds::tests::wp30an_pin_inbound_starter_owner_lives_in_bootstrap_runtime`
  - `bootstrap_runtime::router_helpers::tests::wp30an_pin_router_helpers_owner_lives_in_bootstrap_runtime`
  - `bootstrap_runtime::runtime_shell::tests::wp30an_pin_runtime_shell_owner_lives_in_bootstrap_runtime`
  - `router_text::tests::wp30ak_pin_bootstrap_delegates_router_text_owner`
- integration verification 对齐：
  - `app/tests/admin_auth_contract.rs`
  - `app/tests/e2e_subs_security.rs`

## 验收命令

- `cargo test -p app --all-features --lib -- --test-threads=1`
- `cargo test -p app --all-features --test admin_auth_contract -- --test-threads=1`
- `cargo test -p app --all-features --test e2e_subs_security -- --test-threads=1`
- `cargo clippy -p app --all-features --all-targets -- -D warnings`

## 当前边界

- 当前仍无 public `RuntimePlan`
- 当前仍无 public `PlannedConfigIR`
- 当前仍无 generic query API
- `app/src/run_engine.rs` 继续是 active runtime facade
- `app/src/bootstrap.rs` 继续是 legacy high-level facade
- 本卡没有把控制面重新改成直接摸活体 runtime owner，也没有引入新的无主后台任务

## Future Work（高层方向）

- 更统一的 signal / reload / shutdown manager 仍是 future boundary
- router / dns / inbounds 更深层 handle 化可继续做，但应围绕真实 consumer，而不是为 actor 化硬造抽象
- `planned.rs` / 配置公共 API / router-dns-tun 热路径治理仍保持独立 future boundary，不并入本卡
