<!-- tier: S -->
# 工作阶段总览（Workpackage Map）
> **用途**：阶段划分 + 当前位置。S-tier，每次会话必读。
> **纪律**：Phase 关闭后压缩为一行状态。本文件严格 ≤120 行。
> **对比**：本文件管“在哪”；`active_context.md` 管“刚做了什么 / 当前基线”。
---
## 已关闭阶段（一行总结）
| 阶段 | 交付 | 关闭时间 |
|------|------|----------|
| L1-L17 | 架构整固、功能对齐、CI / 发布收口 | 2026-01 ~ 2026-02 |
| MIG-02 / L21 | 隐式回退消除，541 V7 assertions，生产路径零隐式直连回退 | 2026-03-07 |
| L18 Phase 1-4 | 认证替换、证据模型收口、GUI gate 复验、长跑恢复决策门 | 2026-03-11 |
| L22 | dual-kernel parity 52/60 (86.7%)，16 个 both-case，Sniff Phase A+B | 2026-03-15 |
| 后 L22 补丁 | QUIC 多包重组、OverrideDestination、UDP datagram sniff、编译修复 | 2026-03-15 |
| L23 | TUN/Sniff 运行时补全、Provider wiring、T4 Protocol Suite、parity 92.9% | 2026-03-16 |
| L24 | 性能/安全/质量/功能补全，30 任务 (B1-B4)，综合验收 39/41 PASS | 2026-03-17 |
| L25 | 生产加固 + 跨平台补全 + 文档完善，10/10 任务，4 批次全部交付 | 2026-03-17 |

---

## 当前状态：维护模式（L1-L25 全部 Closed）

**全部阶段关闭**。项目处于稳定维护；dual-kernel parity 状态以 `labs/interop-lab/docs/dual_kernel_golden_spec.md` 为准。

### 当前维护线（2026-04-05）

- **MT-CONV-01**: runtime / control-plane / observability convergence — 已完成
  - 性质：maintenance / convergence quality work，不是 parity completion
  - 按当前源码事实确认真正值得收敛的是：
    - exporter lifecycle 在 `RuntimeContext` 与 `tracing_init` 间的平行 owner/install 路径
    - admin read/query path 在 `AdminDebugState`、endpoint glue、`SecuritySnapshot` 间的重复 query 语义
  - 已落地：
    - `tracing_init.rs` 新增共享 `MetricsExporterHandle`
    - `runtime_deps.rs` 新增 `AppObservability`
    - `run_engine_runtime/context.rs` 删除本地 prom exporter handle，改走 `start_metrics_exporter(...)`
    - `admin_debug/mod.rs` 新增 `AdminDebugQuery`
    - `health` / `metrics` / `analyze` 改走 `state.query()`
    - `SecuritySnapshot` 补 `prefetch_queue_high_watermark`
  - 复核后没有硬改：
    - `app/src/logging.rs`
    - `app/src/run_engine_runtime/admin_start.rs`
    - `app/src/admin_debug/http_server.rs`
    - 这些边界当前已稳定，强行动只会增加 churn
  - 最小充分验证通过：
    - `cargo test -p app --all-features --lib -- --test-threads=1`
    - `cargo test -p app --all-features --test admin_auth_contract -- --test-threads=1`
    - `cargo test -p app --all-features --test e2e_subs_security -- --test-threads=1`
    - `cargo test -p sb-metrics --all-features --lib -- --test-threads=1`
    - `cargo test -p sb-core --all-features --lib registry_ext::tests -- --test-threads=1`
    - `cargo clippy -p app --all-features --all-targets -- -D warnings`
    - `cargo clippy -p sb-metrics --all-features --all-targets -- -D warnings`
    - `cargo clippy -p sb-core --all-features --all-targets -- -D warnings`

- **MT-RECAP-01**: maintenance recap and next-stage convergence — 已完成
  - 本卡不是 parity completion；基于当前源码、git 现状与最小充分验证做 maintenance 复盘
  - 复核确认：
    - workspace 当前在 `main...origin/main`，但仍有大量无关在制改动；本卡只触达 `agents-only` 文档，没有回滚或覆盖 unrelated workspace changes
    - `planned.rs` 仍是 staged crate-private seam；当前仍无 public `RuntimePlan`、public `PlannedConfigIR`、generic query API
    - `RuntimeContext` / `AdminDebugState`、`router/{shared_index,runtime_override}`、`dns/upstream_pool`、ShadowTLS wrapper raw-stream seam、TUN detached/draining session seam 均按现有 maintenance 口径稳定存在
  - 最小充分验证通过：
    - `cargo test -p app --all-features --lib -- --test-threads=1`
    - `cargo test -p sb-core --all-features --lib -- --test-threads=1`
    - `cargo test -p sb-adapters --all-features --lib -- --test-threads=1`
    - `cargo clippy -p app --all-features --all-targets -- -D warnings`
    - `cargo clippy -p sb-core --all-features --all-targets -- -D warnings`
    - `cargo clippy -p sb-adapters --all-features --all-targets -- -D warnings`
  - 当前阶段结论：
    - 没有新的最前置 blocker
    - 不建议继续机械拆 maintenance 细卡
    - 若未来确需继续，只保留少数高层 convergence 主题

- **MT-CONTRACT-01**: transport-wrapper + detached-session contract hardening — 已完成
  - 性质：maintenance / protocol-quality work，不是 parity completion
  - ShadowTLS：typed `WrapperEndpoint`、`DetourStreamResult`、wrapper endpoint doc、e2e fixture fix、bridge simultaneous-shutdown test
  - TUN TCP：`SessionPhase` enum、`DrainPolicy` struct、`run_eviction_sweep()`、`phase`/`detached_at` fields、simultaneous-close test
  - 验证：clippy 0 warnings；sb-adapters --lib 208/208 pass；shadowtls e2e 9/9 pass (isolation)

- **MT-CONTRACT-02**: transport/session contract convergence — 已完成
  - 性质：maintenance / protocol-quality work，不是 parity completion
  - ShadowTLS：`StreamCapability` enum、`WrapperContract` struct、`wrapper_contract()` accessor、4 typed contract tests
  - TUN TCP：`CleanupMode` enum + Display、`remove_with_reason()`、`simultaneous_close_grace` in DrainPolicy、`drain_policy()` accessor、4 typed policy tests
  - 集成：`tun_enhanced.rs` RST 分支 → `CleanupMode::ClientRst`；`run_eviction_sweep()` → `CleanupMode::DrainTimeout`
  - 验证：clippy 0 warnings；sb-adapters --lib 216/216 pass

### 维护线分类（按当前仓库事实）

- **archive-safe close-out**
  - `WP-30` archive baseline / planned seam baseline
  - `MT-SVC-01`
  - `MT-TEST-01`
  - `MT-ADP-01`
- **close-out but future boundary remains**
  - `MT-CONV-01`
  - `MT-OBS-01`
  - `MT-RTC-01`
  - `MT-RTC-02`
  - `MT-RTC-03`
  - `MT-HOT-OBS-01`
  - `MT-RD-01`
  - `MT-PERF-01`
  - `MT-MLOG-01`
  - `MT-ADM-01`
  - `MT-DEEP-01`
- **still active / needs regrouping**
  - 无旧 maintenance 线继续维持为单独 active 卡；剩余未来工作只保留跨线 regroup 后的高层 boundary

### 下一阶段路线收束

- **默认结论**：当前阶段应暂停继续拆新的细卡；已完成维护线不再恢复为滚动 backlog
- **若未来继续，只保留 1-3 条高层主题**
  - runtime / control-plane / observability convergence
    - `MT-CONV-01` 已把 exporter lifecycle + admin read/query seam 再收一轮
    - 剩余只保留更高层的 logging/tracing compat install 统一、以及更宽 control-plane read model
  - router / dns / tun / outbound convergence
    - 合并 `MT-RD-01`、`MT-PERF-01`、`MT-DEEP-01` 的剩余边界
    - 只在出现明确结构收益、perf 证据或重复 corner-case 信号时成组推进
  - planned/private seam 维持暂停
    - 不默认继续拆 `planned.rs`
    - 不误推进 public `RuntimePlan`、public `PlannedConfigIR`、generic query API

### 明确暂停事项

- 不恢复 `.github/workflows/*`
- 不把 maintenance 工作误写成 dual-kernel parity completion
- 不再继续 `WP-30k` 风格微卡化排程
- 不把 `future boundary` 直接写成“下一卡默认继续做”
