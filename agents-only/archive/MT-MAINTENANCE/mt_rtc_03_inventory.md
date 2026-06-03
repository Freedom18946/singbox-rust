# MT-RTC-03 inventory

## 定位

- 主题：runtime actorization close-out
- 性质：maintenance / runtime quality work
- 形式：runtime owner/query/manager seam 10 合 1 收口
- 非目标：dual-kernel parity completion、恢复 `WP-30k` ~ `WP-30as` 编号体系、public `RuntimePlan`、public `PlannedConfigIR`、generic query API、把 `run_engine.rs` / `bootstrap.rs` 重新做大

## 本轮复核结论

- `run_engine_runtime/{watch,output}.rs` 当前 owner/query/lifecycle seam 已稳定：
  - `watch.rs` 已有 `CancellationToken + JoinHandle + Drop cancel`
  - `output.rs` 已围绕 `RuntimeContext` 读取 startup fingerprint
- `admin_debug/http_server.rs` 当前 accept loop / connection task / shutdown 语义已稳定：
  - `AdminDebugHandle` 持有明确 cancel/join owner
  - per-connection task 已由 `JoinSet` 跟踪
- `bootstrap_runtime/{runtime_shell,inbounds,router_helpers}.rs` 当前 carrier / helper seam 已稳定：
  - `Runtime::new(...)`
  - `InboundRuntimeDeps`
  - `RouterRuntime`
- `run_engine.rs` 仍是 facade，`bootstrap.rs` 仍是 legacy high-level facade；本卡没有把 owner 逻辑重新灌回入口

## 本轮已落地源码事实

### `app/src/runtime_deps.rs`

- `AppRuntimeDeps` 与 `AdminDebugState` 现在共享同一份 `AnalyzeRegistry` owner
- runtime deps 不再为 admin control-plane 重复拼装第二份 analyze/query owner

### `app/src/admin_debug/mod.rs`

- `AdminDebugState` 新增：
  - `spawn_http_server(...)`
  - `spawn_plain_http_server_sync(...)`
- admin HTTP server + reload signal wiring 现在从 state owner 统一派生
- `admin_debug::init()` 改走 state-owned helper，不再手写 `spawn_plain_sync(...).with_reload_signal(...)`

### `app/src/run_engine_runtime/context.rs`

- `RuntimeContext` 新增：
  - `spawn_watch(...)`
  - `start_admin_services(...)`
- active runtime manager/service seam 进一步由 `RuntimeContext` 显式派生
- `RuntimeContext` 在当前阶段已是实际 owner carrier，而不仅是参数桶

### `app/src/run_engine_runtime/admin_start.rs`

- debug admin startup 改成 `admin_state.spawn_http_server(...)`
- admin server wiring 不再在 runtime startup 路径重复拼装 reload signal owner

### `app/src/run_engine_runtime/supervisor.rs`

- supervisor 改成通过 `RuntimeContext::start_admin_services(...)` 与 `RuntimeContext::spawn_watch(...)` 派生 runtime service owner
- `run_engine.rs` 继续保持 thin facade

## 本轮测试 / pins

- `admin_debug::tests::admin_debug_state_keeps_http_server_wiring_owner_local`
- `runtime_deps::tests::app_runtime_deps_reuses_analyze_registry_owner_for_admin_state`
- 既有 source pin 已同步更新：
  - `run_engine_runtime::admin_start::tests::wp30ao_pin_admin_start_owner_moved_out_of_run_engine_rs`
  - `run_engine_runtime::supervisor::tests::wp30ao_pin_run_engine_is_thin_supervisor_facade`
  - `run_engine_runtime::context::tests::runtime_context_tracks_reload_fingerprint`

## 验收命令

- `cargo test -p app --all-features --lib -- --test-threads=1`
- `cargo test -p app --all-features --test admin_auth_contract -- --test-threads=1`
- `cargo test -p app --all-features --test e2e_subs_security -- --test-threads=1`
- `cargo clippy -p app --all-features --all-targets -- -D warnings`

## 当前边界

- 当前仍无 public `RuntimePlan`
- 当前仍无 public `PlannedConfigIR`
- 当前仍无 generic query API
- `run_engine.rs` 继续是 active runtime facade
- `bootstrap.rs` 继续是 legacy high-level facade
- 本卡没有把控制面重新改成直接摸活体 runtime owner，也没有引入新的无主后台任务

## Close-out 判断

- 当前 runtime 主线已经达到“维护期可接受的 close-out”：
  - active runtime 的主要 owner/query/lifecycle seam 已统一到 `RuntimeContext` / `RuntimeLifecycle` / `AdminDebugState` / explicit bootstrap carriers
  - 剩余未做项已收缩成少数高层 future boundary，而不是低垂散乱 seam
  - 继续为 `watch/output/http_server/bootstrap_runtime helpers` 这类已稳定切口硬做 actor 化，只会增加抽象噪音和 churn

## Future Work（高层方向）

- 更统一的 signal / reload / shutdown manager 仍可作为后续高层 maintenance 主题
- router / dns / inbound manager 更深层 handle 化，只有在出现真实 consumer 时再推进
- `logging.rs` / `telemetry.rs` / `tracing_init.rs` 的 observability 线继续独立治理
- DNS/router mega-file、TUN 热路径、metrics compat/global 仍保持独立 maintenance boundary
