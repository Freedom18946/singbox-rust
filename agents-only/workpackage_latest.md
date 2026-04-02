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

- **MT-RTC-01**: runtime actor/context consolidation — 已完成
  - `app/src/run_engine_runtime/context.rs` 新增 `RuntimeContext` / `RuntimeLifecycle`；`supervisor.rs` 通过 context/lifecycle 显式持有 runtime deps、reload fingerprint/state、prom exporter、admin services、watch handle
  - `admin_start.rs` 新增 `AdminStartContext`，`watch.rs` 新增 `WatchRuntime`，`output.rs` startup 输出改走 `RuntimeContext`，runtime startup/shutdown/orchestration 的 owner/deps/context 路径更清楚
  - `bootstrap_runtime/dns_apply.rs` 新增 `DnsRuntimeEnv::from_config(...).apply()`；`bootstrap_runtime/proxy_registry.rs` 新增 `ProxyRegistryPlan::from_env().install()`；`bootstrap.rs` 继续只是 legacy facade wiring
  - 本卡性质是 maintenance / runtime quality work，不是 dual-kernel parity completion；也没有推进 `planned.rs`、public `RuntimePlan`、public `PlannedConfigIR`、generic query API
  - 验收通过：`cargo test -p app --all-features --lib -- --test-threads=1`、`cargo clippy -p app --all-features --all-targets -- -D warnings`

### 已完成维护归档（2026-04-02）

- **MT-OBS-01**: runtime / control-plane / observability ownership consolidation — 已完成
  - `AdminDebugHandle` / `AdminDebugState` / `AppRuntimeDeps` / metrics registry/query helper 已完成 owner-first 收口
  - reload signal lifecycle、security snapshot query、metrics registry owner path 已稳定

- **WP-30at**: `WP-30k` ~ `WP-30as` maintenance line 总体验收 / 归档收口 — 已完成
  - `crates/sb-config/src/ir/mod.rs` / `validator/v2/mod.rs` 为稳定 facade；`planned.rs` 为 staged crate-private seam；`run_engine.rs` / `bootstrap.rs` 为 app facade / legacy shell
  - `WP-30` 当前定位是 maintenance archive / stabilization baseline，不是 parity completion，也不是新的 `RuntimePlan` 实现线

### 当前维护重点（高层）

- runtime 继续沿显式 context / lifecycle / handle 化方向治理，但不把 `run_engine.rs` / `bootstrap.rs` 重新做大
- 配置高层 future boundary 保持不变：不恢复 `WP-30k` 式拆卡，不误推进 public `RuntimePlan` / `PlannedConfigIR`
- 其他 maintenance 债务继续按主题推进：DNS/router mega-file、TUN 热路径、metrics compat/global 更深层治理

### 构建基线（2026-04-02）

| 构建 | 状态 |
|------|------|
| `cargo test -p app --all-features --lib -- --test-threads=1` | ✅ pass (`MT-RTC-01`) |
| `cargo clippy -p app --all-features --all-targets -- -D warnings` | ✅ pass (`MT-RTC-01`) |
| `cargo test -p sb-config --lib` | ✅ pass (`WP-30at`) |
| `cargo clippy -p sb-config --all-features --all-targets -- -D warnings` | ✅ pass (`WP-30at`) |
| `cargo test -p sb-metrics --lib -- --test-threads=1` | ✅ pass (`MT-OBS-01`) |
| `cargo test -p sb-core --features metrics --lib registry_ext::tests -- --test-threads=1` | ✅ pass (`MT-OBS-01`) |
| `cargo clippy -p sb-metrics --all-targets -- -D warnings` | ✅ pass (`MT-OBS-01`) |
| `cargo clippy -p sb-core --features metrics --lib --tests -- -D warnings` | ✅ pass (`MT-OBS-01`) |
