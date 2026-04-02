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

### 当前维护线（2026-04-02）

- **MT-HOT-OBS-01**: hotpath stabilization + metrics/logging consolidation — 已完成
  - Stage A：`tun/dns/router/outbound optimizations` 聚焦热路径锁热点、panic seam、shared-state lifecycle；`TunInboundService` / DHCP upstream / shared router hot reload / protocol optimization pool 均已做一轮 owner-first 收口
  - Stage B：`logging/sb-metrics` 聚焦 global/compat 收尾；`LoggingOwner` 现已显式拥有 signal task lifecycle，metrics HTTP exporter 现已跟踪 per-connection serve task
  - 本卡明确是 maintenance / quality work，不是 dual-kernel parity completion；也没有推进 `planned.rs`、public `RuntimePlan`、public `PlannedConfigIR`、generic query API
  - 本卡没有把 runtime actor/context close-out 主线重新做大；`MT-RTC-03`、`MT-RTC-02`、`MT-RTC-01` 的稳定 owner/query/lifecycle 边界继续保持
  - 验收通过：`cargo test -p sb-core --all-features inbound::tun::tests -- --test-threads=1`、`cargo test -p sb-core --all-features dns::config_builder::tests -- --test-threads=1`、`cargo test -p sb-core --all-features dns::upstream::tests -- --test-threads=1`、`cargo test -p sb-core --all-features outbound::optimizations::tests -- --test-threads=1`、`cargo test -p sb-core --all-features router::migration_tests -- --test-threads=1`、`cargo test -p sb-metrics --all-features --lib -- --test-threads=1`、`cargo test -p app --all-features --lib -- --test-threads=1`、三条 clippy 全通过
  - 当前基线备注：`cargo test -p sb-core --all-features --tests -- --test-threads=1` 仍被既有 DERP 测试 `services::derp::mesh_test::tests::test_mesh_forwarding` 阻塞，失败点在 `crates/sb-core/src/services/derp/mesh_test.rs:266`

### 已完成维护归档（2026-04-02）

- **MT-RTC-03**: runtime actorization close-out — 已完成
  - `RuntimeContext` / `AdminDebugState` / runtime deps / admin HTTP wiring 当前为稳定基线

- **MT-RTC-02**: runtime actorization follow-up — 已完成
  - watch lifecycle、bootstrap runtime carriers、admin state query helper 已稳定

- **MT-RTC-01**: runtime actor/context consolidation — 已完成
  - `RuntimeContext` / `RuntimeLifecycle` / bootstrap carriers 继续作为 close-out 基线

- **MT-OBS-01**: runtime / control-plane / observability ownership consolidation — 已完成
  - registry owner/query helper、reload signal lifecycle、security snapshot query 已稳定

- **WP-30at**: `WP-30k` ~ `WP-30as` maintenance line 总体验收 / 归档收口 — 已完成
  - `WP-30` 当前定位是 maintenance archive / stabilization baseline，不是 parity completion，也不是新的 runtime 主线实现线

### 当前维护重点（高层）

- runtime actor/context 主线当前已达到维护期可接受 close-out；后续不再按散乱 seam 继续细拆
- 后续更合适的维护主题是：
  - `router/dns` 真实热点与 mega-file 风险
  - `tun/outbound` 生命周期与 perf hotspot
  - metrics/logging 剩余 compat/global 壳
- 配置高层 future boundary 保持不变：不恢复 `WP-30k` 式拆卡，不误推进 public `RuntimePlan` / `PlannedConfigIR`

### 构建基线（2026-04-02）

| 构建 | 状态 |
|------|------|
| `cargo test -p sb-core --all-features inbound::tun::tests -- --test-threads=1` | ✅ pass (`MT-HOT-OBS-01`) |
| `cargo test -p sb-core --all-features dns::config_builder::tests -- --test-threads=1` | ✅ pass (`MT-HOT-OBS-01`) |
| `cargo test -p sb-core --all-features dns::upstream::tests -- --test-threads=1` | ✅ pass (`MT-HOT-OBS-01`) |
| `cargo test -p sb-core --all-features outbound::optimizations::tests -- --test-threads=1` | ✅ pass (`MT-HOT-OBS-01`) |
| `cargo test -p sb-core --all-features router::migration_tests -- --test-threads=1` | ✅ pass (`MT-HOT-OBS-01`) |
| `cargo test -p sb-core --all-features --tests -- --test-threads=1` | ⚠️ 现有 DERP 基线失败：`services::derp::mesh_test::tests::test_mesh_forwarding` |
| `cargo test -p sb-metrics --all-features --lib -- --test-threads=1` | ✅ pass (`MT-HOT-OBS-01`) |
| `cargo test -p app --all-features --lib -- --test-threads=1` | ✅ pass (`MT-HOT-OBS-01`) |
| `cargo clippy -p sb-core --all-features --all-targets -- -D warnings` | ✅ pass (`MT-HOT-OBS-01`) |
| `cargo clippy -p sb-metrics --all-features --all-targets -- -D warnings` | ✅ pass (`MT-HOT-OBS-01`) |
| `cargo clippy -p app --all-features --all-targets -- -D warnings` | ✅ pass (`MT-HOT-OBS-01`) |
