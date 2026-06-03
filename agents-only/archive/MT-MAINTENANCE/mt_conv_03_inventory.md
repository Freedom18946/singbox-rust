# MT-CONV-03 inventory

## 定位

- 主题：standalone entrypoint logging/tracing convergence
- 性质：maintenance / structural-quality work
- 形式：高层 convergence 线，不是继续拆 observability 小尾巴
- 非目标：dual-kernel parity completion、恢复 `.github/workflows/*`、推进 public `RuntimePlan` / public `PlannedConfigIR` / generic query API、扩散到 router/dns、tun/outbound、DERP/services

## 开工前按当前仓库事实复核

- 已重读：
  - `AGENTS.md`
  - `agents-only/{active_context,workpackage_latest,maintenance_recap_2026-04-03,mt_mlog_01,mt_conv_01,mt_conv_02}_inventory.md`
  - `重构package相关/{2026-03-25_5.4pro第三次审计核验记录,singbox_rust_rebuild_workpackage}.md`
- `git status --short --branch` 起点为 `main...origin/main`，workspace 干净
- 复核目标切口后确认真正还在绕过 canonical install contract 的是 3 个 standalone bins：
  - `bin/run.rs` — 手搓 `tracing_subscriber::fmt()...init()`
  - `bin/tools.rs` — 手搓 `tracing_subscriber::fmt()...init()`
  - `bin/metrics-serve.rs` — 手搓 `tracing_subscriber::fmt()...try_init()` + 手动 registry/exporter setup
- 同时发现 `cli/run.rs` 存在两次独立 `AppRuntimeDeps::new()` 调用（各创建独立 owner 实例）
- 按当前源码事实确认：
  - `main.rs` 已走 `install_logging_owner()`——正确的 owner-first path
  - `telemetry.rs` 已走 `tracing_init::init_tracing_once()` + `install_compat_metrics_exporter()`
  - `tracing_init.rs` 的 `init_tracing_once()` 是 standalone bin 应该用的 canonical subscriber init
  - `lib.rs` 的 `tracing_init` module 被 feature-gated 在 `observe || dev-cli` 下，导致 `bin/run.rs`（仅需 `router`）和 `bin/tools.rs`（仅需 `tools`）无法访问

## 本轮收敛结论

### 1. tracing_init module 暴露收敛

- `app/src/lib.rs`
  - `tracing_init` 从 `#[cfg(any(feature = "dev-cli", feature = "observe"))] pub mod` 改为始终 `pub mod`
  - 模块内部各 item 的 feature gate 不变（metrics 相关仍 gated on `sb-metrics`）
  - 结果是所有 standalone bins 都能访问 `app::tracing_init::init_tracing_once()`

### 2. standalone bins tracing init 收敛

- `app/src/bin/run.rs`
  - 手搓 `tracing_subscriber::fmt()...init()` → `app::tracing_init::init_tracing_once()`
  - 移除了对 `tracing_subscriber::EnvFilter` 的直接依赖

- `app/src/bin/tools.rs`
  - 手搓 `tracing_subscriber::fmt()...init()` → `app::tracing_init::init_tracing_once()`
  - 移除了对 `tracing_subscriber::EnvFilter` 的直接依赖

- `app/src/bin/metrics-serve.rs`
  - 手搓 `tracing_subscriber::fmt()...try_init()` → `app::tracing_init::init_tracing_once()`
  - 手动 `sb_metrics::spawn_http_exporter_from_env()` → `app::tracing_init::install_configured_metrics_exporter()`
  - 结果是 tracing subscriber init + metrics exporter install 都走 canonical contract

### 3. cli/run.rs AppRuntimeDeps 合并

- `app/src/cli/run.rs`
  - 原来有两个独立的 `AppRuntimeDeps::new()` 调用（一个用于 metrics exporter，一个用于 admin_debug），各创建独立 owner 实例
  - 合并为单次构建 + 条件 fallback：当 `dev-cli + observe` 同时启用时只创建一次，admin_debug 复用同一实例
  - 当 `admin_debug` 启用但 `dev-cli` 未启用时，admin 块内自行创建

## 复核后刻意不动的切口

- `app/src/bin/sb-explaind.rs` — 无 tracing init，仅 `eprintln!`；属于 explain feature 专属 bin，不值得为它引入 tracing 依赖
- `app/src/bin/diag.rs` — 使用 `sb_core::log::init()`，是 sb-transport 层面的独立 logging；不属于 app 层 install contract 范畴
- `app/src/bin/probe-outbound.rs` — 无 tracing init，纯 CLI 探测工具；不值得硬加
- `app/src/bin/sb-bench.rs` — 使用 `tracing::warn!` 但无 subscriber init；feature-gated stub，不值得硬改
- `app/src/analyze/registry.rs`、`crates/sb-metrics/src/lib.rs`、`crates/sb-core/src/metrics/registry_ext.rs` — 与上一轮结论一致，registry/query seam 已稳定

## 本轮真实 write-set

- `app/src/lib.rs`
- `app/src/bin/run.rs`
- `app/src/bin/tools.rs`
- `app/src/bin/metrics-serve.rs`
- `app/src/cli/run.rs`
- `app/src/tracing_init.rs` (tests)
- `app/src/logging.rs` (tests)
- `agents-only/{active_context,workpackage_latest,mt_conv_03_inventory}.md`

## 测试 / source pin

- `app/src/tracing_init.rs`
  - `tracing_init_keeps_metrics_exporter_lifecycle_owner_explicit` — 既有 pin 继续通过
  - `standalone_bins_use_canonical_tracing_init` — **新增**，锁住 bin/run、bin/tools、bin/metrics-serve 使用 canonical init
  - `tracing_init_module_always_exposed_in_lib` — **新增**，锁住 lib.rs 无条件暴露 tracing_init
- `app/src/logging.rs`
  - `cli_run_does_not_duplicate_runtime_deps` — **新增**，锁住 cli/run.rs 不重复创建 AppRuntimeDeps

## 验收命令

- `cargo test -p app --all-features --lib -- --test-threads=1` ✅ 286 passed
- `cargo test -p app --all-features --bin app -- --test-threads=1` ✅ 186 passed
- `cargo test -p app --all-features --test admin_auth_contract -- --test-threads=1` ✅ 7 passed
- `cargo test -p app --all-features --test e2e_subs_security -- --test-threads=1` ✅ 23 passed
- `cargo test -p sb-metrics --all-features --lib -- --test-threads=1` ✅ 19 passed
- `cargo test -p sb-core --all-features --lib registry_ext::tests -- --test-threads=1` ✅ 4 passed
- `cargo clippy -p app --all-features --all-targets -- -D warnings` ✅ 0 warnings
- `cargo clippy -p sb-metrics --all-features --all-targets -- -D warnings` ✅ 0 warnings
- `cargo clippy -p sb-core --all-features --all-targets -- -D warnings` ✅ 0 warnings

## 验证结论

- 上述命令全部按当前源码事实通过
- 本卡没有把 maintenance 工作误写成 parity completion
- 本卡没有误推进 `planned.rs`、public `RuntimePlan`、public `PlannedConfigIR`
- 本卡没有把 standalone entrypoint convergence 以外的主题卷进主线
- 本卡没有引入新的 owner/query/lifecycle 混乱

## 收束后剩余 future boundary

- 部分 standalone bins（`sb-explaind`、`diag`、`sb-bench`、`probe-outbound`）仍无 tracing subscriber init 或使用独立路径；这些是功能特化的 dev/debug 工具，强行统一收益不大
- `cli/run.rs` 仍存在 feature-gated conditional deps 创建路径（`dev-cli + observe` vs `observe + admin_debug`），可在未来更高层 entrypoint 统一中消除，但当前已是最小合理状态
- 更高层的 logging owner（`install_logging_owner` vs `init_tracing_once`）统一仍保留为 future boundary：main.rs 用前者（完整 owner with flush/signal/redaction），standalone bins 用后者（轻量 subscriber init），这个分层是有意义的
- 当前阶段应停在这里：standalone bin 入口级重复 bootstrap 已消除，再往下拆只会把稳定的 dev-tool bin 重新 churn 开
