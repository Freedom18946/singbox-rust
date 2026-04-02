<!-- tier: S -->
# 当前上下文（Active Context）
> **用途**：高频更新，每次任务结束时维护。**S-tier：每次会话必读。**
> **纪律**：仅保留当前阶段最关键事实。本文件严格 ≤100 行。
---
## 战略状态
**当前阶段**: 维护模式，L1-L25 全部 Closed
**Parity**: 92.9% (52/56)，以 `labs/interop-lab/docs/dual_kernel_golden_spec.md` 为准
**当前维护线**: `MT-RTC-02` runtime actorization follow-up — 已完成 runtime owner/query/manager seam 第二轮收口；`MT-RTC-01`、`MT-OBS-01` 与 `WP-30` 继续保持已完成 / 已归档状态

## 最近完成（2026-04-02）

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
- `MT-RTC-02` 是 runtime actor/context maintenance follow-up，不是 parity completion，也不是 `RuntimePlan` / `PlannedConfigIR` 推进卡
- 当前仓库仍无 public `RuntimePlan`、public `PlannedConfigIR`、generic query API；`crates/sb-config/src/ir/planned.rs` 仍应视为 staged crate-private seam
- `app/src/run_engine.rs`、`app/src/bootstrap.rs`、`crates/sb-config/src/ir/mod.rs`、`crates/sb-config/src/validator/v2/mod.rs` 继续视为稳定 facade / compat shell，不应重新回灌 owner 巨石
- runtime startup/shutdown/orchestration 现在有两层可接受承载点：`RuntimeContext` / `RuntimeLifecycle` 负责 active runtime owner，`AdminDebugState` / watch handle / reload signal 改走显式 owner/query seam
- bootstrap runtime helper 当前接受的边界是“显式 deps/runtime carrier -> facade wiring”；`InboundRuntimeDeps`、`RouterRuntime`、`Runtime::new(...)` 与既有 `DnsRuntimeEnv` / `ProxyRegistryPlan` 一起构成当前维护期可接受的 owner-first 形态，`bootstrap.rs` 仍只保留 legacy wiring

## Future Work（高层方向）
- 更大的 runtime actor/context 化仍是明确保留的 future boundary：例如更统一的 signal/reload/shutdown manager、router/dns/inbound manager handle 化
- `logging.rs` / `telemetry.rs` / `tracing_init.rs` 继续保持 thin observability facade；本卡没有把更大的 observability 主链重新展开
- DNS/router mega-file、TUN 热路径、metrics compat/global 更深层治理仍属于 maintenance 债务，但不挂回 `WP-30` 细碎排程

## 归档判断
- `WP-30` 继续视为 archive baseline
- 后续如再开 runtime maintenance 卡，继续按高层主题命名；不要恢复 `WP-30k` ~ `WP-30as` 式连续拆卡
