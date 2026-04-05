<!-- tier: S -->
# 当前上下文（Active Context）
> **用途**：高频更新，每次任务结束时维护。**S-tier：每次会话必读。**
> **纪律**：仅保留当前阶段最关键事实。本文件严格 ≤100 行。
---
## 战略状态
**当前阶段**: 维护模式，L1-L25 全部 Closed
**Parity**: 92.9% (52/56)，以 `labs/interop-lab/docs/dual_kernel_golden_spec.md` 为准
**当前维护线**: `MT-CONV-01` runtime / control-plane / observability convergence — 已完成

## 最近完成（2026-04-05）

### MT-CONV-01：runtime / control-plane / observability convergence — 已完成
- 性质：maintenance / convergence quality work，不是 parity completion
- runtime / observability lifecycle 收敛：
  - `tracing_init.rs` 新增共享 `MetricsExporterHandle`
  - `runtime_deps.rs` 新增 `AppObservability`
  - `RuntimeContext` 改用 `start_metrics_exporter(...)`，删除本地 exporter handle 分叉
- admin control-plane query 收敛：
  - `AdminDebugState` 新增 `AdminDebugQuery`
  - `health` / `metrics` / `analyze` 改走 `state.query()`
  - `SecuritySnapshot` 补 `prefetch_queue_high_watermark`，减少 endpoint 额外 query glue
- 复核后刻意不硬改：
  - `app/src/logging.rs`
  - `app/src/run_engine_runtime/admin_start.rs`
  - `app/src/admin_debug/http_server.rs`
  - 这些切口当前 owner/lifecycle 语义已稳定，继续 churn 只会放大噪音
- 验证：
  - `cargo test -p app --all-features --lib -- --test-threads=1` ✅
  - `cargo test -p app --all-features --test admin_auth_contract -- --test-threads=1` ✅
  - `cargo test -p app --all-features --test e2e_subs_security -- --test-threads=1` ✅
  - `cargo test -p sb-metrics --all-features --lib -- --test-threads=1` ✅
  - `cargo test -p sb-core --all-features --lib registry_ext::tests -- --test-threads=1` ✅
  - `cargo clippy -p app --all-features --all-targets -- -D warnings` ✅
  - `cargo clippy -p sb-metrics --all-features --all-targets -- -D warnings` ✅
  - `cargo clippy -p sb-core --all-features --all-targets -- -D warnings` ✅

### MT-CONTRACT-02：transport/session contract convergence — 已完成
- 性质：maintenance / protocol-quality work，不是 parity completion
- ShadowTLS typed wrapper contract：
  - 引入 `StreamCapability` enum (BareTcp/TlsRecordFramed/AuthenticatedTlsRecordFramed)
  - 引入 `WrapperContract` struct 组合 endpoint + capability
  - 新增 `wrapper_contract()` accessor
  - 更新 `connect_detour_stream` doc 引用 `StreamCapability`
  - 更新 `ShadowTlsDetourBridge` doc 明确契约代理语义
  - 新增 4 个 typed contract 测试 (v1/v2/v3/unsupported)
- TUN TCP detached/draining session policy：
  - 引入 `CleanupMode` enum (ClientRst/ClientFin/ServerEof/DrainTimeout/OwnerDrop) + Display
  - 新增 `remove_with_reason()` 方法
  - `DrainPolicy` 新增 `simultaneous_close_grace` 字段
  - 新增 `drain_policy()` accessor
  - `tun_enhanced.rs` RST 分支集成 `CleanupMode::ClientRst`
  - 新增 4 个 typed policy 测试
- 验证：clippy 0 warnings；sb-adapters --lib 216/216 pass

### MT-CONTRACT-01：transport-wrapper + detached-session contract hardening — 已完成
- ShadowTLS：`WrapperEndpoint`、`DetourStreamResult`、`wrapper_endpoint()`
- TUN TCP：`SessionPhase`、`DrainPolicy`、`run_eviction_sweep()`

## 当前验证事实
- 已通过最小充分验证：
  - `app --all-features --lib`、`admin_auth_contract`、`e2e_subs_security` 全部通过
  - `sb-metrics --all-features --lib` 通过
  - `sb-core --all-features --lib registry_ext::tests` 通过
  - `app` / `sb-metrics` / `sb-core` 对应 clippy 全部 0 warnings

## 当前阶段结论
- 当前没有新的基线阻塞或必须立即开卡的质量问题
- runtime / control-plane / observability 当前已收成更清晰的 owner/query/lifecycle seam
- 本轮没有误推进 `RuntimePlan` / `PlannedConfigIR` / generic query API
- 剩余未来工作只保留少数高层 boundary，不恢复细碎 maintenance 卡

## 暂停事项
- 不再恢复细碎 maintenance 排程
- 不把 maintenance work 写成 parity completion
- 不把 `future boundary` 自动等同于"下一卡默认继续做"
