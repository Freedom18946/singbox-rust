# MT-CONV-02 inventory

## 定位

- 主题：logging / tracing install convergence
- 性质：maintenance / structural-quality work
- 形式：高层 convergence 线，不是继续拆 observability 小尾巴
- 非目标：dual-kernel parity completion、恢复 `.github/workflows/*`、推进 public `RuntimePlan` / public `PlannedConfigIR` / generic query API、扩散到 router/dns、tun/outbound、DERP/services

## 开工前按当前仓库事实复核

- 已重读：
  - `AGENTS.md`
  - `agents-only/{active_context,workpackage_latest,maintenance_recap_2026-04-03,mt_mlog_01_inventory,mt_conv_01_inventory}.md`
  - `重构package相关/{2026-03-25_5.4pro第三次审计核验记录,singbox_rust_rebuild_workpackage}.md`
- `git status --short --branch` 起点为 `main...origin/main`，workspace 干净
- 复核目标切口后确认真正还重复的是 install contract：
  - `logging.rs` 仍由 `init_logging(...)` / `init_logging_with_owner(...)` 承载 owner install 与 compat install 两层语义
  - `tracing_init.rs`、`runtime_deps.rs`、`RuntimeContext`、`telemetry.rs`、`cli/run.rs` 之间仍混用 `start` / `init` / configured exporter install glue
  - `app/src/analyze/registry.rs`、`crates/sb-metrics/src/lib.rs`、`crates/sb-core/src/metrics/registry_ext.rs` 当前不是 install convergence 的真实热点

## 本轮收敛结论

### 1. logging install contract 收敛

- `app/src/logging.rs`
  - 新增 `install_logging_owner(...)`
  - 新增 `install_logging_compat(...)`
  - `init_logging(...)` / `init_logging_with_owner(...)` 明确退为 compat shell
- `app/src/main.rs`
  - 主入口改走 `install_logging_owner(...)`
  - 结果是 owner-first install 与 legacy compat install 不再继续共用模糊 `init_*` 名义

### 2. metrics exporter install contract 收敛

- `app/src/tracing_init.rs`
  - 新增 `MetricsExporterPlan`
  - 新增 `install_metrics_exporter(...)`
  - 新增 `install_metrics_exporter_from_listen(...)`
  - 新增 `install_configured_metrics_exporter(...)`
  - 新增 `install_compat_metrics_exporter(...)`
  - `start_metrics_exporter*` / `init_metrics_exporter_once(...)` 退成 compat shell
- `app/src/runtime_deps.rs`
  - `AppObservability` 现在统一暴露 explicit / from-listen / configured / compat exporter install
- `app/src/run_engine_runtime/context.rs`
  - runtime wiring 改走 `install_metrics_exporter(...)`
  - listen 地址解析不再在 runtime context 本地重复
- `app/src/telemetry.rs` + `app/src/cli/run.rs`
  - dev-cli / telemetry compat 启动改走 `deps.observability().install_compat_metrics_exporter()`
- `app/src/lib.rs`
  - `tracing_init` 暴露条件改为 `observe || dev-cli`，与实际 observability wiring 对齐

## 本轮刻意不动的 inspected 切口

- `app/src/analyze/registry.rs`
- `crates/sb-metrics/src/lib.rs`
- `crates/sb-core/src/metrics/registry_ext.rs`

原因：

- 当前 registry/exporter/query seam 已稳定，继续动只会把 install convergence 主线扩散到不必要的层
- 本卡目标是减少平行 install API，不是继续重做 registry internals

## 本轮真实 write-set

- `app/src/logging.rs`
- `app/src/main.rs`
- `app/src/tracing_init.rs`
- `app/src/runtime_deps.rs`
- `app/src/run_engine_runtime/context.rs`
- `app/src/run_engine_runtime/supervisor.rs`
- `app/src/telemetry.rs`
- `app/src/cli/run.rs`
- `app/src/lib.rs`
- `agents-only/{active_context,workpackage_latest,mt_conv_02_inventory}.md`

## 测试 / source pin

- `app/src/logging.rs`
  - `explicit_owner_does_not_install_compat_registry`
  - `explicit_owner_flush_cancels_owned_signal_task`
  - `logging_install_contract_keeps_owner_and_compat_paths_distinct`
- `app/src/tracing_init.rs`
  - `tracing_init_keeps_metrics_exporter_lifecycle_owner_explicit`
- `app/src/runtime_deps.rs`
  - `app_runtime_deps_observability_install_contract_uses_owned_registry_handle`
- `app/src/run_engine_runtime/context.rs`
  - source pin 改锁 `install_metrics_exporter(...)`
- `app/src/run_engine_runtime/supervisor.rs`
  - source pin 改锁 `runtime_context.install_metrics_exporter(...)`

## 验收命令

- `cargo test -p app --all-features --lib -- --test-threads=1`
- `cargo test -p app --all-features --bin app -- --test-threads=1`
- `cargo test -p app --all-features --test admin_auth_contract -- --test-threads=1`
- `cargo test -p app --all-features --test e2e_subs_security -- --test-threads=1`
- `cargo test -p sb-metrics --all-features --lib -- --test-threads=1`
- `cargo test -p sb-core --all-features --lib registry_ext::tests -- --test-threads=1`
- `cargo clippy -p app --all-features --all-targets -- -D warnings`
- `cargo clippy -p sb-metrics --all-features --all-targets -- -D warnings`
- `cargo clippy -p sb-core --all-features --all-targets -- -D warnings`

## 验证结论

- 上述命令全部按当前源码事实通过
- 本卡没有把 maintenance 工作误写成 parity completion
- 本卡没有误推进 `planned.rs`、public `RuntimePlan`、public `PlannedConfigIR`
- 本卡没有把 logging / tracing install 以外的主题卷进主线

## 收束后剩余 future boundary

- 若 future 再做，更值得处理的是 tracing subscriber / logging bootstrap 的更高层统一，而不是继续拆 `install_*` 小尾巴
- standalone bins、legacy exporter entrypoints、deprecated compat shell 若再统一，应成组处理，不扩散到 registry internals 或 control-plane read model
- 当前阶段应停在这里：install contract 已够明确，再往下拆只会把稳定 seam 重新 churn 开
