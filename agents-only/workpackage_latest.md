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

- **MT-TEST-01**: patch-plan / test baseline stabilization — 已完成
  - 真实根因已按当前源码事实确认：`crates/sb-core/tests/patch_plan_test.rs::plan_and_apply` 失败不是 tempdir/fixture 生命周期问题，而是 `suffix_shadow_cleanup` 生成 `-exact:...=<TO-BE-REMOVED>` 占位删除
  - `crates/sb-core/src/router/patch_apply.rs` 原先只按整行精确匹配删除，导致 `apply_plan(...)` 无法删除真实 `exact:...=proxy` 行，输出里残留 stale rule
  - 本轮收口：
    - `patch_apply.rs` 新增最小 delete-rule seam，让 `<TO-BE-REMOVED>` 按 `key=` 匹配任意现值，同时保留既有精确删除语义
    - 新增 `router::patch_apply::tests::placeholder_delete_matches_existing_rule_value`
    - `router_rules_suffix_shadow_fix.rs` 新增从 patch 生成到应用的链路回归，直接 pin 住 `suffix_shadow_cleanup -> apply_cli_patch`
  - 本卡明确是 maintenance / test-baseline quality work，不是 dual-kernel parity completion；也没有推进 `planned.rs`、public `RuntimePlan`、public `PlannedConfigIR`、generic query API
  - 验收通过：`cargo test -p sb-core --all-features --test patch_plan_test plan_and_apply -- --test-threads=1`、`cargo test -p sb-core --all-features --test patch_plan_test -- --test-threads=1`、`cargo test -p sb-core --all-features --tests -- --test-threads=1`、`cargo test -p sb-core --all-features --lib -- --test-threads=1`、`cargo clippy -p sb-core --all-features --all-targets -- -D warnings`
  - 当前基线备注：`cargo test -p sb-core --all-features --tests -- --test-threads=1` 在本卡验收时整条通过；另外 `cargo test -p sb-core --all-features patch_plan_test::plan_and_apply -- --test-threads=1` 在当前仓库只会过滤到 0 个集成测试，真实定向命令应使用 `--test patch_plan_test plan_and_apply`

- **MT-SVC-01**: DERP / services baseline stabilization — 已完成
  - 真实根因已按当前源码事实确认：`mesh_forwarding` 失败不是“包转发太慢”，而是 test harness 只跑到 `StartStage::Start`；DERP mesh peer 实际在 `PostStart` 才启动
  - 在补齐完整 lifecycle 后，当前源码还要求 mesh peer fixture 显式配置 outbound TLS；旧 `localhost:port` shorthand 会明文连接 TLS DERP 端口并触发 `InvalidContentType`
  - 本轮收口：
    - `mesh_test.rs` 改成完整 `Initialize -> Start -> PostStart -> Started` 启动 helper，并用 remote-route 就绪等待替代魔法 sleep
    - `server.rs` 的 `close()` 改为 abort 已拥有的 `stun/http/mesh` background task handle，收掉 detached task seam
    - `client_registry.rs` 仅新增最小 crate-local remote-client query seam，供 DERP tests pin 当前 owner/read 路径；没有公共化 services query API
    - 新增 `test_close_aborts_owned_background_tasks` pin 住本卡触达的 lifecycle owner 语义
  - 本卡明确是 maintenance / services quality work，不是 dual-kernel parity completion；也没有推进 `planned.rs`、public `RuntimePlan`、public `PlannedConfigIR`、generic query API
  - 验收通过：`cargo test -p sb-core --all-features services::derp::mesh_test::tests::test_mesh_forwarding -- --test-threads=1`、`cargo test -p sb-core --all-features services::derp -- --test-threads=1`、`cargo test -p sb-core --all-features --lib -- --test-threads=1`、`cargo clippy -p sb-core --all-features --all-targets -- -D warnings`
  - 当前基线备注：`cargo test -p sb-core --all-features --tests -- --test-threads=1` 已不再被 DERP 挡住；在当前 dirty workspace 中，新的首个失败点是与本卡无关的 `crates/sb-core/tests/patch_plan_test.rs::plan_and_apply`

- **MT-HOT-OBS-01**: hotpath stabilization + metrics/logging consolidation — 已完成
  - `tun/dns/router/outbound optimizations` 与 `logging/sb-metrics` owner-first 收口继续保持稳定；本卡不再赘述

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
  - patch/preview 语义里更复杂的 patch kind 应用契约，但只在出现真实 baseline failure 或 consumer 时再继续推进
  - DERP/services 更深层 reconnect/backoff/shutdown 一致性观察
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
| `cargo test -p sb-core --all-features --test patch_plan_test plan_and_apply -- --test-threads=1` | ✅ pass (`MT-TEST-01`) |
| `cargo test -p sb-core --all-features --test patch_plan_test -- --test-threads=1` | ✅ pass (`MT-TEST-01`) |
| `cargo test -p sb-core --all-features services::derp::mesh_test::tests::test_mesh_forwarding -- --test-threads=1` | ✅ pass (`MT-SVC-01`) |
| `cargo test -p sb-core --all-features services::derp -- --test-threads=1` | ✅ pass (`MT-SVC-01`) |
| `cargo test -p sb-core --all-features --lib -- --test-threads=1` | ✅ pass (`MT-TEST-01`) |
| `cargo test -p sb-core --all-features --tests -- --test-threads=1` | ✅ pass (`MT-TEST-01`) |
| `cargo test -p sb-metrics --all-features --lib -- --test-threads=1` | ✅ pass (`MT-HOT-OBS-01`) |
| `cargo test -p app --all-features --lib -- --test-threads=1` | ✅ pass (`MT-HOT-OBS-01`) |
| `cargo clippy -p sb-core --all-features --all-targets -- -D warnings` | ✅ pass (`MT-TEST-01` + `MT-SVC-01` + `MT-HOT-OBS-01`) |
| `cargo clippy -p sb-metrics --all-features --all-targets -- -D warnings` | ✅ pass (`MT-HOT-OBS-01`) |
| `cargo clippy -p app --all-features --all-targets -- -D warnings` | ✅ pass (`MT-HOT-OBS-01`) |
