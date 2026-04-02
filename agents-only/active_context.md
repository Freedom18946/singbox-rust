<!-- tier: S -->
# 当前上下文（Active Context）
> **用途**：高频更新，每次任务结束时维护。**S-tier：每次会话必读。**
> **纪律**：仅保留当前阶段最关键事实。本文件严格 ≤100 行。
---
## 战略状态
**当前阶段**: 维护模式，L1-L25 全部 Closed
**Parity**: 92.9% (52/56)，以 `labs/interop-lab/docs/dual_kernel_golden_spec.md` 为准
**当前维护线**: `MT-RTC-03` runtime actorization close-out — 已完成 runtime owner/query/manager seam 第三轮收口；`MT-RTC-02`、`MT-RTC-01`、`MT-OBS-01` 与 `WP-30` 继续保持已完成 / 已归档状态

## 最近完成（2026-04-02）

### MT-RTC-03：runtime actorization close-out — 已完成
- 已重新复核 `run_engine_runtime/{context,supervisor,admin_start,watch,output}.rs`、`bootstrap_runtime/{runtime_shell,inbounds,router_helpers}.rs`、`admin_debug/{mod,http_server}.rs`、`runtime_deps.rs`、`run_engine.rs`、`bootstrap.rs` 与当前工作区事实；本卡继续明确为 maintenance / runtime quality work，不是 dual-kernel parity completion
- `app/src/runtime_deps.rs` 不再为 `AppRuntimeDeps` 与 `AdminDebugState` 重复拼装两份 `AnalyzeRegistry` owner；admin control-plane 与 runtime deps 现在共享同一份 analyze/query owner
- `app/src/admin_debug/mod.rs` 新增 `AdminDebugState::spawn_http_server(...)` / `spawn_plain_http_server_sync(...)`；admin HTTP server + reload signal wiring 现在由 state owner 统一派生，`run_engine_runtime/admin_start.rs` 与 `admin_debug::init()` 不再各自手搓 `spawn(...).with_reload_signal(...)`
- `app/src/run_engine_runtime/context.rs` 新增 `start_admin_services(...)` / `spawn_watch(...)`；`supervisor.rs` 改成从 `RuntimeContext` 直接派生 admin/watch owner seam，`RuntimeContext` 进一步成为 active runtime owner carrier，而不只是状态桶
- 这次复核后确认 `watch.rs`、`output.rs`、`admin_debug/http_server.rs`、`bootstrap_runtime/{runtime_shell,inbounds,router_helpers}.rs`、`run_engine.rs`、`bootstrap.rs` 的当前边界已经处于维护期可接受状态，因此没有为了凑“10 合 1”继续硬造抽象或把 owner 逻辑回灌 facade
- 新增 / 补强回归：`admin_debug_state_keeps_http_server_wiring_owner_local`、`app_runtime_deps_reuses_analyze_registry_owner_for_admin_state`，并把既有 source pin 更新到 `RuntimeContext::start_admin_services(...)` / `spawn_watch(...)` 与 `admin_state.spawn_http_server(...)` 这条新 wiring
- 本卡验收命令已按当前仓库事实通过：`cargo test -p app --all-features --lib -- --test-threads=1`、`cargo test -p app --all-features --test admin_auth_contract -- --test-threads=1`、`cargo test -p app --all-features --test e2e_subs_security -- --test-threads=1`、`cargo clippy -p app --all-features --all-targets -- -D warnings`

### MT-RTC-02：runtime actorization follow-up — 已完成
- 已重新复核 `run_engine_runtime/*`、`bootstrap_runtime/*`、`runtime_deps.rs`、`admin_debug/*`、`bootstrap.rs`、`run_engine.rs` 与当前工作区事实；本卡明确是 maintenance / runtime quality work，不是 dual-kernel parity completion，也没有恢复 `WP-30k` ~ `WP-30as` 编号体系
- `app/src/runtime_deps.rs` 现在预组装并复用稳定的 `AdminDebugState` owner；`app/src/admin_debug/mod.rs` 把 analyze/metrics/reload query 收成显式方法，`admin_debug::init()` 与 `run_engine_runtime/admin_start.rs` 都改成围绕显式 state / reload owner 接线，不再偷读默认 reload helper
- `app/src/run_engine_runtime/context.rs` 新增 `admin_reload_signal()` / `watch_runtime(...)`；`supervisor.rs` 现在从 `RuntimeContext` 直接派生 watch wiring；`watch.rs` 的后台任务改成 `CancellationToken` owner 语义，补上 drop-cancel 行为，避免无主 watch task 残留
- `app/src/admin_debug/http_server.rs` 与 `endpoints/{health,metrics,analyze}.rs` 不再直接摸 `AdminDebugState` public field；控制面读路径改走显式 query/state helper，只读快照/query seam 比之前稳定
- `app/src/bootstrap_runtime/{inbounds,router_helpers,runtime_shell}.rs` 新增 `InboundRuntimeDeps`、`RouterRuntime`、`Runtime::new(...)`；`bootstrap.rs` 继续保持 legacy facade，只接线到显式 deps/runtime carrier，没有把 owner 逻辑灌回 facade
- 新增 / 补强回归：`app_runtime_deps_reuses_stable_admin_state_handle`、`watch_handle_drop_cancels_spawned_task`、`router_runtime_from_env_tracks_rule_limit`、`start_inbounds_facade_keeps_compat_shell`；受影响的 source pin 与 integration tests 已对齐新的 admin/query/bootstrap wiring
- 本卡验收命令已按当前仓库事实通过：`cargo test -p app --all-features --lib -- --test-threads=1`、`cargo test -p app --all-features --test admin_auth_contract -- --test-threads=1`、`cargo test -p app --all-features --test e2e_subs_security -- --test-threads=1`、`cargo clippy -p app --all-features --all-targets -- -D warnings`

### MT-RTC-01：runtime actor/context consolidation — 已完成
- `RuntimeContext` / `RuntimeLifecycle` 首批 startup/shutdown/orchestration seam 继续作为 `MT-RTC-02` 的稳定基础，没有被本卡打穿；`run_engine.rs` 继续保持 thin facade

### MT-OBS-01：runtime / control-plane / observability ownership consolidation — 已完成
- `AdminDebugHandle` / `AdminDebugState` / `AppRuntimeDeps` / metrics registry query helper 已在上一卡完成 owner-first 收口；reload signal lifecycle、security snapshot query、metrics registry owner path 已稳定

### WP-30at：`WP-30k` ~ `WP-30as` maintenance line 总体验收 / 归档收口 — 已完成
- `crates/sb-config/src/ir/mod.rs` / `validator/v2/mod.rs` 稳定为 thin facade；`planned.rs` 稳定停在 crate-private staged seam；`app/src/run_engine.rs` / `app/src/bootstrap.rs` 稳定为 facade / legacy shell

## 当前稳定事实
- `MT-RTC-03` 是 runtime actor/context maintenance close-out，不是 parity completion，也不是 `RuntimePlan` / `PlannedConfigIR` 推进卡
- 当前仓库仍无 public `RuntimePlan`、public `PlannedConfigIR`、generic query API；`crates/sb-config/src/ir/planned.rs` 仍应视为 staged crate-private seam
- `app/src/run_engine.rs`、`app/src/bootstrap.rs`、`crates/sb-config/src/ir/mod.rs`、`crates/sb-config/src/validator/v2/mod.rs` 继续视为稳定 facade / compat shell，不应重新回灌 owner 巨石
- runtime startup/shutdown/orchestration 当前可接受的承载点已经更明确：`RuntimeContext` / `RuntimeLifecycle` 负责 active runtime owner，`AdminDebugState` 负责 admin HTTP + reload signal wiring，watch/admin startup 通过 `RuntimeContext` 显式派生
- bootstrap runtime helper 当前接受的边界仍是“显式 deps/runtime carrier -> facade wiring”；`InboundRuntimeDeps`、`RouterRuntime`、`Runtime::new(...)` 与既有 `DnsRuntimeEnv` / `ProxyRegistryPlan` 一起构成当前维护期可接受的 owner-first 形态，`bootstrap.rs` 仍只保留 legacy wiring
- `AppRuntimeDeps`、`AdminDebugState`、`RuntimeContext` 之间的 owner map 已避免低垂重复拼装；当前 runtime 主线剩余尾巴已经压缩成少数高层 boundary，而不是散乱 seam

## Future Work（高层方向）
- 更大的 runtime actor/context 化仍是明确保留的 future boundary：例如更统一的 signal/reload/shutdown manager、router/dns/inbound manager handle 化
- `logging.rs` / `telemetry.rs` / `tracing_init.rs` 继续保持 thin observability facade；本卡没有把更大的 observability 主链重新展开
- DNS/router mega-file、TUN 热路径、metrics compat/global 更深层治理仍属于 maintenance 债务，但不挂回 `WP-30` 细碎排程

## 归档判断
- `WP-30` 继续视为 archive baseline
- runtime actor/context 主线在当前阶段已达到可接受 close-out：active runtime 的主要 owner/query/lifecycle seam 已统一到 `RuntimeContext` / `RuntimeLifecycle` / `AdminDebugState` / explicit bootstrap carriers；剩余项已是高层 future boundary，不再值得继续按零散 seam 细碎拆卡
- 后续如再开 runtime maintenance 卡，继续按高层主题命名；不要恢复 `WP-30k` ~ `WP-30as` 式连续拆卡
