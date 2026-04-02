<!-- tier: S -->
# 当前上下文（Active Context）
> **用途**：高频更新，每次任务结束时维护。**S-tier：每次会话必读。**
> **纪律**：仅保留当前阶段最关键事实。本文件严格 ≤100 行。
---
## 战略状态
**当前阶段**: 维护模式，L1-L25 全部 Closed
**Parity**: 92.9% (52/56)，以 `labs/interop-lab/docs/dual_kernel_golden_spec.md` 为准
**当前维护线**: `MT-HOT-OBS-01` hotpath stabilization + metrics/logging consolidation — 已完成；`MT-RTC-03`、`MT-RTC-02`、`MT-RTC-01`、`MT-OBS-01` 与 `WP-30` 继续保持已完成 / 已归档状态

## 最近完成（2026-04-02）

### MT-HOT-OBS-01：hotpath stabilization + metrics/logging consolidation — 已完成
- 本卡按当前源码事实推进，性质明确为 maintenance / quality work，不是 dual-kernel parity completion，也没有恢复 `.github/workflows/*`
- Stage A 聚焦 `router/dns/tun` 热路径：
  - `crates/sb-core/src/inbound/tun.rs` 将 session / owner 读写切到 `parking_lot::RwLock`，减少热路径 poison / `unwrap()` 面；bridge task 现在有明确 `JoinHandle` owner，session 回收和 service 退出都会 abort 掉桥接任务
  - `crates/sb-core/src/dns/upstream.rs` / `dns/config_builder.rs` 去掉 DHCP upstream 构建阶段对 Tokio runtime 的隐式依赖；无 runtime 时延后到 query/exchange/health_check 按需启动，收掉构建期 panic seam
  - `crates/sb-core/src/router/mod.rs` 只在存在 runtime 且启用了真实 hot-reload 配置时才启动 shared rules reload，避免 query 路径白拉后台任务
  - `crates/sb-core/src/outbound/optimizations.rs` 将 buffer/connection/cache 热点锁切到 `parking_lot::Mutex`，缩小 global surface，把 protocol buffer pool 收成 crate-local helper
- Stage B 聚焦 metrics/logging 收尾：
  - `app/src/logging.rs` 现在由 `LoggingOwner` 显式持有 signal task；flush 会先 cancel/join 再刷日志，兼容路径继续保留，但 signal lifecycle 不再是无主后台任务
  - `crates/sb-metrics/src/lib.rs` 的 HTTP exporter 改为 `JoinSet` 跟踪 per-connection serve task，不再无主 `tokio::spawn`
- 本轮没有把 `planned.rs`、public `RuntimePlan`、public `PlannedConfigIR`、generic query API 或已归档的 runtime actor/context 主线重新做大

## 当前稳定事实
- `planned.rs` 仍是 staged crate-private seam；当前仓库仍无 public `RuntimePlan`、public `PlannedConfigIR`、generic query API
- `app/src/run_engine.rs`、`app/src/bootstrap.rs`、`crates/sb-config/src/ir/mod.rs`、`crates/sb-config/src/validator/v2/mod.rs` 继续视为稳定 facade / compat shell，不应回灌 owner 巨石
- `MT-RTC-01/02/03` 与 `MT-OBS-01` 的 owner/query/lifecycle 主线仍稳定；`MT-HOT-OBS-01` 只是围绕热点链路与 observability compat/global 做进一步 maintenance 收口
- 当前工作区仍存在大量无关在制改动；本卡只顺着目标切口做治理，没有回滚或覆盖 unrelated workspace changes

## 当前验证事实
- 已通过：
  - `cargo test -p sb-core --all-features inbound::tun::tests -- --test-threads=1`
  - `cargo test -p sb-core --all-features dns::config_builder::tests -- --test-threads=1`
  - `cargo test -p sb-core --all-features dns::upstream::tests -- --test-threads=1`
  - `cargo test -p sb-core --all-features outbound::optimizations::tests -- --test-threads=1`
  - `cargo test -p sb-core --all-features router::migration_tests -- --test-threads=1`
  - `cargo test -p sb-core --all-features --tests -- --test-threads=1` 除现有 DERP 基线失败外其余通过
  - `cargo test -p sb-metrics --all-features --lib -- --test-threads=1`
  - `cargo test -p app --all-features --lib -- --test-threads=1`
  - `cargo clippy -p sb-core --all-features --all-targets -- -D warnings`
  - `cargo clippy -p sb-metrics --all-features --all-targets -- -D warnings`
  - `cargo clippy -p app --all-features --all-targets -- -D warnings`
- 当前仓库仍有一个与本卡无关的 sb-core 既有失败：
  - `services::derp::mesh_test::tests::test_mesh_forwarding`
  - 失败位置：`crates/sb-core/src/services/derp/mesh_test.rs:266`
  - 现象：`timeout waiting for RecvPacket`

## Future Work（高层方向）
- `router/dns` 仍有 mega-file 级别的 deeper refactor 空间，但后续只按高层主题推进，不回到细碎 seam churn
- `tun` / `outbound` 仍可继续观察更深层 perf hotspot，但应以真实 profiler / 回归信号为前提，而不是为了凑卡继续硬改
- metrics/logging 仍保留少量 compat/global 壳；后续只在出现真实 owner/query consumer 时再继续收口

## 归档判断
- `WP-30` 继续视为 archive baseline，`ef333bb7` 仍是归档基线
- runtime actor/context 主线当前阶段已 close-out；新的维护主题更适合围绕热点链路与 observability debt，而不是继续拆 runtime 主线小卡
