<!-- tier: S -->
# 当前上下文（Active Context）
> **用途**：高频更新，每次任务结束时维护。**S-tier：每次会话必读。**
> **纪律**：仅保留当前阶段最关键事实。本文件严格 ≤100 行。
---
## 战略状态
**当前阶段**: 维护模式，L1-L25 全部 Closed
**Parity**: 92.9% (52/56)，以 `labs/interop-lab/docs/dual_kernel_golden_spec.md` 为准
**当前维护线**: `MT-SVC-01` DERP / services baseline stabilization — 已完成；`MT-HOT-OBS-01`、`MT-RTC-03`、`MT-RTC-02`、`MT-RTC-01`、`MT-OBS-01` 与 `WP-30` 继续保持已完成 / 已归档状态

## 最近完成（2026-04-02）

### MT-SVC-01：DERP / services baseline stabilization — 已完成
- 本卡按当前源码事实推进，性质明确为 maintenance / services quality work，不是 dual-kernel parity completion，也没有恢复 `.github/workflows/*`
- 真实代码布局与高层候选切口不完全一致：当前直接相关文件主要是 `crates/sb-core/src/services/derp/{server,client_registry,mesh_test}.rs`；不存在可独立治理的 `mesh.rs` / `mesh_forward.rs`
- 已确认并修复的真实根因：
  - `services::derp::mesh_test::tests::test_mesh_forwarding` 原先只调用 `Initialize` + `Start`，但 mesh peer 实际在 `StartStage::PostStart` 才启动；测试把 DERP 服务停在“HTTP/TLS 已起、mesh 未起”的半初始化状态
  - 在补齐 `PostStart` 后，当前源码事实还要求 mesh peer 显式配置 outbound TLS；旧测试使用 `localhost:port` shorthand，实际会明文去敲 TLS DERP 端口并触发 `InvalidContentType`
- 本轮收口：
  - `mesh_test.rs` 改为显式跑完 `Initialize -> Start -> PostStart -> Started`，并把 mesh peer fixture 改成 TLS-accurate config；去掉脆弱魔法 sleep，改为等待 remote route 就绪再发包
  - `server.rs` 的 `close()` 现在会 abort 已拥有的 `stun/http/mesh` task handle，不再仅 `drop(handle)` 留 detached 后台任务
  - `client_registry.rs` 暴露最小 `pub(crate)` remote client query seam，专供 DERP tests pin 当前 owner/read 路径；没有把服务查询面公共化
  - 新增 `test_close_aborts_owned_background_tasks`，pin 住本卡实际触达的 lifecycle owner 语义
- 本轮没有推进 `planned.rs`、public `RuntimePlan`、public `PlannedConfigIR`、generic query API，也没有把维护工作表述成 parity completion

## 当前稳定事实
- `planned.rs` 仍是 staged crate-private seam；当前仓库仍无 public `RuntimePlan`、public `PlannedConfigIR`、generic query API
- `app/src/run_engine.rs`、`app/src/bootstrap.rs`、`crates/sb-config/src/ir/mod.rs`、`crates/sb-config/src/validator/v2/mod.rs` 继续视为稳定 facade / compat shell，不应回灌 owner 巨石
- `MT-RTC-01/02/03` 与 `MT-OBS-01` 的 owner/query/lifecycle 主线仍稳定；`MT-HOT-OBS-01` 与 `MT-SVC-01` 都是 maintenance 收口，不重新打开 runtime actor/context 主线
- 当前工作区仍存在大量无关在制改动；本卡只顺着目标切口做治理，没有回滚或覆盖 unrelated workspace changes

## 当前验证事实
- 已通过：
  - `cargo test -p sb-core --all-features services::derp::mesh_test::tests::test_mesh_forwarding -- --test-threads=1`
  - `cargo test -p sb-core --all-features services::derp::server::tests::test_close_aborts_owned_background_tasks -- --test-threads=1`
  - `cargo test -p sb-core --all-features services::derp -- --test-threads=1`
  - `cargo test -p sb-core --all-features --lib -- --test-threads=1`
  - `cargo clippy -p sb-core --all-features --all-targets -- -D warnings`
  - `cargo test -p sb-core --all-features inbound::tun::tests -- --test-threads=1`
  - `cargo test -p sb-core --all-features dns::config_builder::tests -- --test-threads=1`
  - `cargo test -p sb-core --all-features dns::upstream::tests -- --test-threads=1`
  - `cargo test -p sb-core --all-features outbound::optimizations::tests -- --test-threads=1`
  - `cargo test -p sb-core --all-features router::migration_tests -- --test-threads=1`
  - `cargo test -p sb-metrics --all-features --lib -- --test-threads=1`
  - `cargo test -p app --all-features --lib -- --test-threads=1`
  - `cargo clippy -p sb-metrics --all-features --all-targets -- -D warnings`
  - `cargo clippy -p app --all-features --all-targets -- -D warnings`
- 当前 workspace 的 `cargo test -p sb-core --all-features --tests -- --test-threads=1` 已不再被 DERP 基线失败阻塞；在本卡修复后，新的首个失败点是与本卡无关的 `crates/sb-core/tests/patch_plan_test.rs::plan_and_apply`

## Future Work（高层方向）
- DERP/services 仍可继续观察更深层 reconnect/backoff/shutdown 一致性，但后续只在出现真实 flake / leaked task / mesh owner consumer 时再继续推进
- `router/dns` 仍有 mega-file 级别的 deeper refactor 空间，但后续只按高层主题推进，不回到细碎 seam churn
- `tun` / `outbound` 仍可继续观察更深层 perf hotspot，但应以真实 profiler / 回归信号为前提，而不是为了凑卡继续硬改
- metrics/logging 仍保留少量 compat/global 壳；后续只在出现真实 owner/query consumer 时再继续收口

## 归档判断
- `WP-30` 继续视为 archive baseline，`ef333bb7` 仍是归档基线
- runtime actor/context 主线当前阶段已 close-out；新的维护主题更适合围绕热点链路与 observability debt，而不是继续拆 runtime 主线小卡
