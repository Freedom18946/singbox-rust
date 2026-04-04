<!-- tier: S -->
# 当前上下文（Active Context）
> **用途**：高频更新，每次任务结束时维护。**S-tier：每次会话必读。**
> **纪律**：仅保留当前阶段最关键事实。本文件严格 ≤100 行。
---
## 战略状态
**当前阶段**: 维护模式，L1-L25 全部 Closed
**Parity**: 92.9% (52/56)，以 `labs/interop-lab/docs/dual_kernel_golden_spec.md` 为准
**当前维护线**: `MT-CONTRACT-01` transport-wrapper + detached-session contract hardening — 已完成；`MT-RECAP-01` 已完成；其余旧线保持已完成 / 已归档状态

## 最近完成（2026-04-04）

### MT-CONTRACT-01：transport-wrapper + detached-session contract hardening — 已完成
- 性质：maintenance / protocol-quality work，不是 parity completion
- ShadowTLS wrapper contract：
  - 引入 `WrapperEndpoint` typed struct、`DetourStreamResult` type alias、`wrapper_endpoint()` accessor
  - 重写 module-level 与 `connect_detour_stream` 文档，明确 wrapper-vs-requested endpoint semantics
  - 修复 `shadowtls_e2e.rs` v1 relay `copy_bidirectional` BrokenPipe fixture race
  - 新增 `bridge_stream_simultaneous_shutdown_does_not_panic` 与 `wrapper_endpoint_captures_configured_server` 测试
- TUN TCP detached/draining session policy：
  - 引入 `SessionPhase` enum (`Active`/`Detached`)、`DrainPolicy` struct、`phase`/`detached_at` fields
  - 新增 `run_eviction_sweep()`、`detach_count()`、`with_drain_policy()`、`Display` for `FourTuple`
  - 新增 `packet_loop_simultaneous_close_both_fin_no_rst`、drain eviction 测试
- 验证：clippy 0 warnings；sb-adapters --lib 208/208 pass

## 当前验证事实
- 已通过最小充分跨模块验证：
  - `cargo test -p app --all-features --lib -- --test-threads=1`
  - `cargo test -p sb-core --all-features --lib -- --test-threads=1`
  - `cargo test -p sb-adapters --all-features --lib -- --test-threads=1`
  - `cargo clippy -p app --all-features --all-targets -- -D warnings`
  - `cargo clippy -p sb-core --all-features --all-targets -- -D warnings`
  - `cargo clippy -p sb-adapters --all-features --all-targets -- -D warnings`

## 当前阶段结论
- 当前没有新的“最前置基线阻塞”或必须立即开卡的质量问题；仓库事实更支持“收束下一阶段路线”，而不是继续机械拆 maintenance 细卡
- 可明确视为 archive-safe close-out 的主线：
  - `WP-30` archive baseline / planned seam baseline
  - `MT-SVC-01`
  - `MT-TEST-01`
  - `MT-ADP-01`
- 已 close-out 但仍保留高层 future boundary 的主线：
  - `MT-OBS-01`、`MT-RTC-01/02/03`、`MT-HOT-OBS-01`、`MT-MLOG-01`、`MT-ADM-01`
  - `MT-RD-01`
  - `MT-PERF-01`、`MT-DEEP-01`
- 当前没有需要继续按“单线 still active”维持的旧 maintenance 卡；剩余未来工作只应按跨线高层 boundary regroup

## Next-Stage Gates（只保留高层主题）
- 默认结论：**当前阶段不建议继续拆新的细卡**
- 若未来确需继续推进，只保留 1-3 条高层主题：
  - runtime / control-plane / observability convergence：signal/reload/shutdown manager、`logging` / `security_metrics` / `subs` limiter 等剩余 compat-owner boundary 必须成组推进
  - router / dns / tun / outbound convergence：router/dns mega-file shared-state、TUN/outbound lifecycle/perf、ShadowTLS wrapper contract / detached TCP lifecycle 必须按系统主题成组推进
  - planned/private seam 仅在出现真实稳定 consumer 时再评估；当前明确暂停 public `RuntimePlan` / public `PlannedConfigIR` / generic query API

## 暂停事项
- 不再恢复 `WP-30k` ~ `WP-30as` 式细碎 maintenance 排程
- 不把 maintenance work 写成 parity completion
- 不把 `future boundary` 自动等同于“下一卡默认继续做”
