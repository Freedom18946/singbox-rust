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

### 当前维护线（2026-04-03）

- **MT-MLOG-01**: metrics / logging compat-global cleanup — 已完成
  - 当前源码事实下，这条线处理的是 `logging` / `security_metrics` / `sb-metrics` / `registry_ext` 之间仍真实存在的 compat/current/default/query seams，不是 parity completion
  - 本轮收口：
    - `app/src/logging.rs` 新增 `LoggingOwner::install_compat()`，`init_logging(...)` 退成 thin compat shell
    - `app/src/admin_debug/security_metrics.rs` 新增 `snapshot_with_control_plane(...)` 与 `compat_snapshot()`，`app/src/admin_debug/mod.rs` 改走显式 owner-first query seam
    - `app/src/tracing_init.rs` 新增 `spawn_metrics_exporter_if_configured(...)`，把 explicit exporter spawn 与 compat init 壳分开
    - `crates/sb-metrics/src/lib.rs` 新增 `current_registry_handle()` 与 `export_prometheus_active()`，`DEFAULT_REGISTRY` 当前/默认 registry 路径改用更简单的一层 owner query
    - `crates/sb-core/src/metrics/registry_ext.rs` 用 `get_or_insert_metric(...)` 统一 register/fallback helper，不再让 fallback tree 重复散落
  - 本卡明确是 maintenance / observability quality work，不是 dual-kernel parity completion；也没有推进 `planned.rs`、public `RuntimePlan`、public `PlannedConfigIR`、generic query API
  - 验收通过：`cargo test -p sb-metrics --all-features --lib -- --test-threads=1`、`cargo test -p sb-core --all-features --lib registry_ext::tests -- --test-threads=1`、`cargo test -p app --all-features --lib -- --test-threads=1`、`cargo test -p app --all-features --test admin_auth_contract -- --test-threads=1`、`cargo test -p app --all-features --test e2e_subs_security -- --test-threads=1`、`cargo clippy -p app --all-features --all-targets -- -D warnings`、`cargo clippy -p sb-metrics --all-features --all-targets -- -D warnings`、`cargo clippy -p sb-core --all-features --all-targets -- -D warnings`

- **MT-ADP-01**: sb-adapters test baseline stabilization — 已完成
- **MT-PERF-01**: tun / outbound hotspot stabilization — 已完成
- **MT-RD-01**: router / dns structural consolidation — 已完成
- **MT-TEST-01**: patch-plan / test baseline stabilization — 已完成
- **MT-SVC-01**: DERP / services baseline stabilization — 已完成
- **MT-HOT-OBS-01**: hotpath stabilization + metrics/logging consolidation — 已完成

### 已完成维护归档（2026-04-03）

- **MT-RTC-03**: runtime actorization close-out — 已完成
- **MT-RTC-02**: runtime actorization follow-up — 已完成
- **MT-RTC-01**: runtime actor/context consolidation — 已完成
- **MT-OBS-01**: runtime / control-plane / observability ownership consolidation — 已完成
- **WP-30at**: `WP-30k` ~ `WP-30as` maintenance line 总体验收 / 归档收口 — 已完成

### 当前维护重点（高层）

- metrics/logging 这条线当前更合适的表达已经是少数高层 future boundary，而不是继续把 compat/global 尾巴拆成很多小卡：
  - `sb-metrics` 的 metric-family statics / shared merged view
  - exporter lifecycle 在 legacy dev-cli / examples 路径上的 detached compat 语义
  - `admin_debug` 侧 cache / breaker / subs 的更宽 control-plane compat 面
- 配置高层 future boundary 保持不变：不恢复 `WP-30k` 式拆卡，不误推进 public `RuntimePlan` / `PlannedConfigIR`

### 构建基线（2026-04-03）

| 构建 | 状态 |
|------|------|
| `cargo test -p sb-metrics --all-features --lib -- --test-threads=1` | ✅ pass (`MT-MLOG-01`) |
| `cargo test -p sb-core --all-features --lib registry_ext::tests -- --test-threads=1` | ✅ pass (`MT-MLOG-01`) |
| `cargo test -p app --all-features --lib -- --test-threads=1` | ✅ pass (`MT-MLOG-01`) |
| `cargo test -p app --all-features --test admin_auth_contract -- --test-threads=1` | ✅ pass (`MT-MLOG-01`) |
| `cargo test -p app --all-features --test e2e_subs_security -- --test-threads=1` | ✅ pass (`MT-MLOG-01`) |
| `cargo clippy -p app --all-features --all-targets -- -D warnings` | ✅ pass (`MT-MLOG-01`) |
| `cargo clippy -p sb-metrics --all-features --all-targets -- -D warnings` | ✅ pass (`MT-MLOG-01`) |
| `cargo clippy -p sb-core --all-features --all-targets -- -D warnings` | ✅ pass (`MT-MLOG-01`) |
