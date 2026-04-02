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

- **MT-RTC-03**: runtime actorization close-out — 已完成
  - `runtime_deps.rs` 现已复用单一 `AnalyzeRegistry` owner 给 `AppRuntimeDeps` 与 `AdminDebugState`，不再重复拼装 control-plane analyze/query owner
  - `admin_debug/mod.rs` 新增 `AdminDebugState::spawn_http_server(...)` / `spawn_plain_http_server_sync(...)`；`run_engine_runtime/admin_start.rs` 与 `admin_debug::init()` 现在都从 state owner 显式派生 admin HTTP + reload signal wiring
  - `run_engine_runtime/context.rs` 新增 `start_admin_services(...)` / `spawn_watch(...)`；`supervisor.rs` 改成从 `RuntimeContext` 直接派生 admin/watch owner seam，`RuntimeContext` 更明确成为 active runtime owner carrier
  - 经源码复核，`watch.rs`、`output.rs`、`admin_debug/http_server.rs`、`bootstrap_runtime/{runtime_shell,inbounds,router_helpers}.rs`、`run_engine.rs`、`bootstrap.rs` 当前已处于维护期可接受边界，因此本卡没有为凑数继续硬做抽象
  - 本卡性质仍是 maintenance / runtime quality work，不是 dual-kernel parity completion；也没有推进 `planned.rs`、public `RuntimePlan`、public `PlannedConfigIR`、generic query API
  - 验收通过：`cargo test -p app --all-features --lib -- --test-threads=1`、`cargo test -p app --all-features --test admin_auth_contract -- --test-threads=1`、`cargo test -p app --all-features --test e2e_subs_security -- --test-threads=1`、`cargo clippy -p app --all-features --all-targets -- -D warnings`

### 已完成维护归档（2026-04-02）

- **MT-RTC-02**: runtime actorization follow-up — 已完成
  - `RuntimeContext` / `RuntimeLifecycle`、`AdminDebugState` query helper、watch lifecycle、bootstrap runtime carriers 作为 `MT-RTC-03` 的直接基础继续稳定

- **MT-RTC-01**: runtime actor/context consolidation — 已完成
  - `RuntimeContext` / `RuntimeLifecycle`、`AdminStartContext`、`WatchRuntime`、`DnsRuntimeEnv`、`ProxyRegistryPlan` 作为 `MT-RTC-02` 的首批 runtime seam 基线继续稳定

- **MT-OBS-01**: runtime / control-plane / observability ownership consolidation — 已完成
  - `AdminDebugHandle` / `AdminDebugState` / `AppRuntimeDeps` / metrics registry/query helper 已完成 owner-first 收口
  - reload signal lifecycle、security snapshot query、metrics registry owner path 已稳定

- **WP-30at**: `WP-30k` ~ `WP-30as` maintenance line 总体验收 / 归档收口 — 已完成
  - `crates/sb-config/src/ir/mod.rs` / `validator/v2/mod.rs` 为稳定 facade；`planned.rs` 为 staged crate-private seam；`run_engine.rs` / `bootstrap.rs` 为 app facade / legacy shell
  - `WP-30` 当前定位是 maintenance archive / stabilization baseline，不是 parity completion，也不是新的 `RuntimePlan` 实现线

### 当前维护重点（高层）

- runtime actor/context 主线当前已达到维护期可接受 close-out；后续只在出现真实 consumer 时再开高层 maintenance 主题，不继续按散乱 seam 细拆
- `run_engine.rs` / `bootstrap.rs` 继续保持 facade；`RuntimeContext` / `RuntimeLifecycle` / `AdminDebugState` / bootstrap runtime carriers 现已构成 active runtime 的稳定 owner/query/lifecycle 主干
- 配置高层 future boundary 保持不变：不恢复 `WP-30k` 式拆卡，不误推进 public `RuntimePlan` / `PlannedConfigIR`
- 其他 maintenance 债务继续按主题推进：DNS/router mega-file、TUN 热路径、metrics compat/global 更深层治理

### 构建基线（2026-04-02）

| 构建 | 状态 |
|------|------|
| `cargo test -p app --all-features --lib -- --test-threads=1` | ✅ pass (`MT-RTC-02`) |
| `cargo test -p app --all-features --test admin_auth_contract -- --test-threads=1` | ✅ pass (`MT-RTC-02`) |
| `cargo test -p app --all-features --test e2e_subs_security -- --test-threads=1` | ✅ pass (`MT-RTC-02`) |
| `cargo clippy -p app --all-features --all-targets -- -D warnings` | ✅ pass (`MT-RTC-02`) |
| `cargo test -p sb-config --lib` | ✅ pass (`WP-30at`) |
| `cargo clippy -p sb-config --all-features --all-targets -- -D warnings` | ✅ pass (`WP-30at`) |
| `cargo test -p sb-metrics --lib -- --test-threads=1` | ✅ pass (`MT-OBS-01`) |
| `cargo test -p sb-core --features metrics --lib registry_ext::tests -- --test-threads=1` | ✅ pass (`MT-OBS-01`) |
| `cargo clippy -p sb-metrics --all-targets -- -D warnings` | ✅ pass (`MT-OBS-01`) |
| `cargo clippy -p sb-core --features metrics --lib --tests -- -D warnings` | ✅ pass (`MT-OBS-01`) |
