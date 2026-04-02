<!-- tier: S -->
# 当前上下文（Active Context）
> **用途**：高频更新，每次任务结束时维护。**S-tier：每次会话必读。**
> **纪律**：仅保留当前阶段最关键事实。本文件严格 ≤100 行。
---
## 战略状态
**当前阶段**: 维护模式，L1-L25 全部 Closed
**Parity**: 92.9% (52/56)，以 `labs/interop-lab/docs/dual_kernel_golden_spec.md` 为准
**当前维护线**: `MT-RTC-01` runtime actor/context consolidation — 已完成首批 runtime startup/shutdown/orchestration 收口；`MT-OBS-01` 与 `WP-30` 继续保持已完成 / 已归档状态

## 最近完成（2026-04-02）

### MT-RTC-01：runtime actor/context consolidation — 已完成
- 已先按仓库当前事实复核 `run_engine_runtime/*`、`bootstrap_runtime/*`、`runtime_deps.rs`、`bootstrap.rs`、`run_engine.rs`，确认本卡定位是 runtime maintenance / quality work，不是 dual-kernel parity completion，也没有恢复 `WP-30k` ~ `WP-30as` 编号体系
- `app/src/run_engine_runtime/context.rs` 新增当前阶段可接受的 `RuntimeContext` / `RuntimeLifecycle` owner seam：`AppRuntimeDeps`、reload fingerprint/state、prom exporter handle、admin services、watch handle 都改由显式 context / lifecycle carrier 接线
- `app/src/run_engine_runtime/supervisor.rs` 不再自己散着 build deps / 丢 prom exporter handle / 直接拼 admin+watch 参数串；startup/shutdown 现在围绕 `RuntimeContext::from_raw(...)`、`AdminStartContext`、`WatchRuntime`、`RuntimeLifecycle` 收口
- `app/src/run_engine_runtime/admin_start.rs` 新增 `AdminStartContext`；`watch.rs` 新增 `WatchRuntime`；`output.rs` 的 startup 输出改成吃 `RuntimeContext`；依赖注入边界比之前清楚，`run_engine.rs` 继续保持 thin facade
- `app/src/bootstrap_runtime/dns_apply.rs` 新增 `DnsRuntimeEnv::from_config(...).apply()`；`proxy_registry.rs` 新增 `ProxyRegistryPlan::from_env().install()`；legacy `bootstrap.rs` 继续只是调用 plan/apply 的 compat shell，没有重新长回 owner 巨石
- 本轮顺手修正了当前仓库事实下会阻塞验证的配套点：`admin_debug/reloadable.rs` 的 `loom` smoke test 重新对齐到 `DEFAULT_STORE` owner；`app/tests/admin_auth_contract.rs` 对齐当前 `AdminDebugState` 字段
- 新增 / 补强回归：`runtime_context_tracks_reload_fingerprint`、`runtime_lifecycle_shutdown_aborts_owned_prom_exporter_task`、`watch_handle_shutdown_waits_for_spawned_task`、`watch_runtime_carries_explicit_reload_wiring`、`dns_runtime_env_collects_vars_before_side_effects`、`proxy_registry_plan_collects_registry_before_install`
- 本卡验收命令已按当前仓库事实通过：`cargo test -p app --all-features --lib -- --test-threads=1`、`cargo clippy -p app --all-features --all-targets -- -D warnings`

### MT-OBS-01：runtime / control-plane / observability ownership consolidation — 已完成
- `AdminDebugHandle` / `AdminDebugState` / `AppRuntimeDeps` / metrics registry query helper 已在上一卡完成 owner-first 收口；reload signal lifecycle、security snapshot query、metrics registry owner path 已稳定

### WP-30at：`WP-30k` ~ `WP-30as` maintenance line 总体验收 / 归档收口 — 已完成
- `crates/sb-config/src/ir/mod.rs` / `validator/v2/mod.rs` 稳定为 thin facade；`planned.rs` 稳定停在 crate-private staged seam；`app/src/run_engine.rs` / `app/src/bootstrap.rs` 稳定为 facade / legacy shell

## 当前稳定事实
- `MT-RTC-01` 是新的 runtime/context maintenance 线，不是 parity completion，也不是 `RuntimePlan` 或 `PlannedConfigIR` 推进卡
- 当前仓库仍无 public `RuntimePlan`、public `PlannedConfigIR`、generic query API；`crates/sb-config/src/ir/planned.rs` 仍应视为 staged crate-private seam
- `app/src/run_engine.rs`、`app/src/bootstrap.rs`、`crates/sb-config/src/ir/mod.rs`、`crates/sb-config/src/validator/v2/mod.rs` 继续视为稳定 facade / compat shell，不应重新回灌 owner 巨石
- runtime startup/shutdown/orchestration 现已具备一层显式 `RuntimeContext` / `RuntimeLifecycle` 承载点；prom exporter、watch、admin startup 不再由 `supervisor.rs` 临时散接
- bootstrap runtime helper 当前接受的边界是“显式 plan/context -> apply/install”；`DnsRuntimeEnv` / `ProxyRegistryPlan` 已是这一轮的 owner-first 形态，`bootstrap.rs` 仍只保留 legacy wiring

## Future Work（高层方向）
- 更大的 runtime actor/context 化仍是明确保留的 future boundary：例如更统一的 signal/reload/shutdown manager、router/dns/inbound manager handle 化
- `logging.rs` / `telemetry.rs` / `tracing_init.rs` 继续保持 thin observability facade；本卡没有把更大的 observability 主链重新展开
- DNS/router mega-file、TUN 热路径、metrics compat/global 更深层治理仍属于 maintenance 债务，但不挂回 `WP-30` 细碎排程

## 归档判断
- `WP-30` 继续视为 archive baseline
- 后续如再开 runtime maintenance 卡，继续按高层主题命名；不要恢复 `WP-30k` ~ `WP-30as` 式连续拆卡
