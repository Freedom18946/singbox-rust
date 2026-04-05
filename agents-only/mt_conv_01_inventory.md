# MT-CONV-01 inventory

## 定位

- 主题：runtime / control-plane / observability convergence
- 性质：maintenance / structural-quality work
- 形式：高层 convergence 线，不是继续拆旧 maintenance 小尾巴
- 非目标：dual-kernel parity completion、恢复 `.github/workflows/*`、推进 public `RuntimePlan` / public `PlannedConfigIR` / generic query API、扩散到 router/dns、tun/outbound、DERP/services

## 开工前按当前仓库事实复核

- 起点为 `main...origin/main`，workspace 干净；本卡没有回滚或覆盖无关改动
- 已重新阅读：
  - `AGENTS.md`
  - `agents-only/{active_context,workpackage_latest,maintenance_recap_2026-04-03}.md`
  - `agents-only/{mt_obs_01,mt_rtc_01,mt_rtc_02,mt_rtc_03,mt_mlog_01,mt_adm_01,mt_contract_01,mt_contract_02}_inventory.md`
  - `重构package相关/{2026-03-25_5.4pro第三次审计核验记录,singbox_rust_rebuild_workpackage}.md`
- 复核后确认最值得继续收敛的是两层重复 seam：
  - metrics exporter lifecycle 在 `RuntimeContext` 与 `tracing_init` 间存在平行 owner/install 路径
  - admin read/query path 在 `AdminDebugState`、endpoint glue、`SecuritySnapshot` 间仍有重复 query 语义

## 本轮收敛结论

### 1. runtime / observability lifecycle 收敛

- `app/src/tracing_init.rs`
  - 新增共享 `MetricsExporterHandle`
  - `start_metrics_exporter(...)` 成为显式 owner-first exporter 入口
  - `start_metrics_exporter_if_configured(...)` / `init_metrics_exporter_once(...)` 退成 env compat shell + detach 语义
- `app/src/runtime_deps.rs`
  - 新增 `AppObservability`
  - metrics registry 与 exporter spawn 不再只是零散 helper，改为稳定 owner carrier
- `app/src/run_engine_runtime/context.rs`
  - 删除本地 `PromExporterHandle`
  - `RuntimeContext` 改走 `start_metrics_exporter(...)`
  - `RuntimeLifecycle` 直接持有共享 exporter handle
- `app/src/run_engine_runtime/supervisor.rs`
  - startup wiring 改成 `runtime_context.start_metrics_exporter(...)`
  - source pin 同步锁住新的 runtime observability seam

### 2. admin control-plane query 收敛

- `app/src/admin_debug/mod.rs`
  - 新增 `AdminDebugQuery`
  - `reloadable_config()` / `security_snapshot()` / `config_version()` 退成 thin state-owned compat shell
  - `state.query()` 成为显式 read/query port
- `app/src/admin_debug/endpoints/health.rs`
  - uptime / analyze capability counts / config version / security snapshot 改走 `state.query()`
- `app/src/admin_debug/endpoints/metrics.rs`
  - metrics read path 改走 `state.query().security_snapshot()`
  - 不再单独摸 `state.prefetch_queue_high_watermark()`
- `app/src/admin_debug/endpoints/analyze.rs`
  - registry query 改经由 `state.query()`
- `app/src/admin_debug/security_metrics.rs`
  - `SecuritySnapshot` 新增 `prefetch_queue_high_watermark`
  - 控制面 read path 现在可由单次 snapshot 覆盖更多指标，而不是 endpoint 再拼一层胶水

## 复核后刻意不动的切口

- `app/src/logging.rs`
- `app/src/run_engine_runtime/admin_start.rs`
- `app/src/admin_debug/http_server.rs`

原因：当前源码里这些切口的 owner/lifecycle 口径已经稳定，继续改只会引入新的 churn，不会提高 convergence 质量。

## 本轮真实 write-set

- `app/src/runtime_deps.rs`
- `app/src/tracing_init.rs`
- `app/src/run_engine_runtime/context.rs`
- `app/src/run_engine_runtime/supervisor.rs`
- `app/src/admin_debug/mod.rs`
- `app/src/admin_debug/security_metrics.rs`
- `app/src/admin_debug/endpoints/{health,metrics,analyze}.rs`
- 与上述直接相关的 source pin / regression tests

## 验收命令

- `cargo test -p app --all-features --lib -- --test-threads=1`
- `cargo test -p app --all-features --test admin_auth_contract -- --test-threads=1`
- `cargo test -p app --all-features --test e2e_subs_security -- --test-threads=1`
- `cargo test -p sb-metrics --all-features --lib -- --test-threads=1`
- `cargo test -p sb-core --all-features --lib registry_ext::tests -- --test-threads=1`
- `cargo clippy -p app --all-features --all-targets -- -D warnings`
- `cargo clippy -p sb-metrics --all-features --all-targets -- -D warnings`
- `cargo clippy -p sb-core --all-features --all-targets -- -D warnings`

## 验证结论

- 全部命令按当前源码事实通过
- 本卡没有把 maintenance 工作误写成 parity completion
- 本卡没有误推进 `planned.rs`、public `RuntimePlan`、public `PlannedConfigIR`
- 本卡没有把 runtime/control-plane/observability 以外的主题卷进来

## 收敛后剩余 future boundary

- logging compat install path 仍分布在 `main.rs` / dev-cli / legacy bootstrap；若 future 再做，应围绕 logging + tracing 的统一 observability owner 一起处理
- admin query port 目前只覆盖最值得收敛的 read path；若 future 再做，应成组处理 config / subs / prefetch 更宽 read model，而不是继续散修 endpoint helper
- router / dns / tun / outbound 仍保持独立高层 boundary，不并入本卡
