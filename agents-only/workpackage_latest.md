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

- **MT-CONV-03**: standalone entrypoint logging/tracing convergence — 已完成
  - 性质：maintenance / structural-quality work，不是 parity completion
  - 收敛 standalone bins 的 tracing subscriber / metrics exporter install：
    - `lib.rs` 的 `tracing_init` 从 feature-gated 改为始终 pub 暴露
    - `bin/run.rs`、`bin/tools.rs` 手搓 subscriber → canonical `init_tracing_once()`
    - `bin/metrics-serve.rs` 手搓 subscriber + exporter → canonical `init_tracing_once()` + `install_configured_metrics_exporter()`
    - `cli/run.rs` 两次 `AppRuntimeDeps::new()` → 合并为单次构建
  - 新增 source pin：
    - `standalone_bins_use_canonical_tracing_init`
    - `tracing_init_module_always_exposed_in_lib`
    - `cli_run_does_not_duplicate_runtime_deps`
  - 最小充分验证通过（全部 9 条命令）

- **MT-CONV-02**: logging / tracing install convergence — 已完成
  - app 主路径上的 logging/tracing/exporter install contract 收成 owner-first / compat shell / exporter plan

- **MT-CONV-01**: runtime / control-plane / observability convergence — 已完成
  - exporter lifecycle owner 统一到 `MetricsExporterHandle` + `AppObservability`
  - admin read/query 收成 `AdminDebugQuery`
  - 这是 `MT-CONV-02` 的直接前置，不再恢复为独立 active 卡

- **MT-RECAP-01**: maintenance recap and next-stage convergence — 已完成
  - 当前没有新的最前置 blocker
  - 不建议恢复 `WP-30k` 风格细卡
  - 若未来继续，只保留少数高层 convergence 主题

- **MT-CONTRACT-01 / 02**: transport/session contract hardening + convergence — 已完成
  - ShadowTLS typed contract、TUN detached/draining policy 已稳定

### 维护线分类（按当前仓库事实）

- **archive-safe close-out**
  - `WP-30` archive baseline / planned seam baseline
  - `MT-SVC-01`
  - `MT-TEST-01`
  - `MT-ADP-01`
- **close-out but future boundary remains**
  - `MT-CONV-01`
  - `MT-CONV-02`
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
  - 无旧 maintenance 线继续维持为单独 active 卡；剩余未来工作只保留 regroup 后的高层 boundary

### 下一阶段路线收束

- **默认结论**：当前阶段应暂停继续拆新的细卡；已完成维护线不再恢复为滚动 backlog
- **若未来继续，只保留 1-3 条高层主题**
  - runtime / control-plane / observability convergence
    - `MT-CONV-01` 已收 owner/query/lifecycle
    - `MT-CONV-02` 已收 install contract
    - 剩余只保留更高层的 tracing subscriber / logging bootstrap 统一，以及更宽 control-plane read model
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
