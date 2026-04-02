<!-- tier: S -->
# 当前上下文（Active Context）
> **用途**：高频更新，每次任务结束时维护。**S-tier：每次会话必读。**
> **纪律**：仅保留当前阶段最关键事实。本文件严格 ≤100 行。
---
## 战略状态
**当前阶段**: 维护模式，L1-L25 全部 Closed
**Parity**: 92.9% (52/56)，以 `labs/interop-lab/docs/dual_kernel_golden_spec.md` 为准
**当前维护线**: `MT-RD-01` router / dns structural consolidation — 已完成；`MT-TEST-01`、`MT-SVC-01`、`MT-HOT-OBS-01`、`MT-RTC-03`、`MT-RTC-02`、`MT-RTC-01`、`MT-OBS-01` 与 `WP-30` 继续保持已完成 / 已归档状态

## 最近完成（2026-04-02）

### MT-RD-01：router / dns structural consolidation — 已完成
- 本卡按当前源码事实推进，性质明确为 maintenance / structural quality work，不是 dual-kernel parity completion，也没有恢复 `.github/workflows/*`
- 当前最值得收口的真实结构债不是继续细拆所有 mega-file，而是两层混杂 owner / shared-state seam：
  - `crates/sb-core/src/router/mod.rs` 同时承载 shared index owner、ENV cache、hot-reload 入口、runtime override query seam
  - `crates/sb-core/src/dns/upstream.rs` 同时承载 DHCP / resolved 的 file-backed upstream pool、watcher、reload、fallback、metrics helper
- 本轮收口：
  - 新增 `crates/sb-core/src/router/shared_index.rs`，收走 `SHARED_INDEX`、ENV cache、`shared_index()`、`router_index_from_env_with_reload()`、empty unresolved index helper
  - 新增 `crates/sb-core/src/router/runtime_override.rs`，收走 runtime override parse/cache/query seam；`explain_util.rs` 改为复用该 query seam，而不是单独再解析一次 override
  - `crates/sb-core/src/router/engine.rs` 改为复用 `empty_router_index(...)`，不再在 compat 路径重复拼空索引
  - 新增 `crates/sb-core/src/dns/upstream_pool.rs`，统一 file-backed upstream pool 的 watcher / reload / fallback / round-robin / metrics helper
  - `crates/sb-core/src/dns/upstream.rs` 中 DHCP / resolved 改为持有 `FileBackedUpstreamPool`，不再各自堆同类 shared state
  - `crates/sb-core/src/dns/config_builder.rs` 保持 builder owner 不扩散，只补 source pin，确认特殊 upstream 仍留在专门 helper
- 本轮新增 / 迁移的关键 pin：
  - `router::migration_tests::shared_index_refreshes_when_router_rules_env_changes`
  - `router::migration_tests::router_shared_state_owner_lives_in_dedicated_modules`
  - `router::explain_util::tests::try_override_uses_runtime_override_query_seam`
  - `dns::upstream::tests::file_backed_upstream_pool_owner_lives_in_upstream_pool_module`
  - `dns::config_builder::tests::builder_keeps_special_upstream_wiring_in_specialized_helpers`
- 本轮没有推进 `planned.rs`、public `RuntimePlan`、public `PlannedConfigIR`、generic query API，也没有扩散到 runtime actor/context、DERP/services、tun/outbound、metrics/logging 主线

## 当前稳定事实
- `planned.rs` 仍是 staged crate-private seam；当前仓库仍无 public `RuntimePlan`、public `PlannedConfigIR`、generic query API
- runtime actor/context 主线当前仍保持 close-out；`MT-RD-01` 只触达 `sb-core` 的 router/dns 结构边界，没有重新打开 runtime 主线
- 当前 workspace 仍存在大量无关在制改动；本卡只顺着 router/dns 目标切口推进，没有回滚或覆盖 unrelated workspace changes
- `router/mod.rs` 与 `dns/upstream.rs` 仍各自保留更深层实现体量，但当前最混乱的一层 shared-state / helper wiring 已收成独立 owner seam

## 当前验证事实
- 已通过：
  - `cargo test -p sb-core --all-features router::migration_tests -- --test-threads=1`
  - `cargo test -p sb-core --all-features dns::config_builder::tests -- --test-threads=1`
  - `cargo test -p sb-core --all-features dns::upstream::tests -- --test-threads=1`
  - `cargo test -p sb-core --all-features --lib -- --test-threads=1`
  - `cargo test -p sb-core --all-features --tests -- --test-threads=1`
  - `cargo clippy -p sb-core --all-features --all-targets -- -D warnings`
- 增量修正后再次复核：
  - `dns::upstream::tests` 通过
  - `clippy -p sb-core --all-features --all-targets -D warnings` 通过

## Future Work（高层方向）
- `router/mod.rs` 后续仍可继续观察更深层 rule-build / match / summarize 体量，但下一轮应按更高层 owner 面收，不再回到 shared index / override seam
- `dns/upstream.rs` 后续仍可继续观察 protocol implementation bulk 与 resolver selection / normalization 的边界，但 file-backed pool owner 已独立，不必再围绕 watcher/reload 小修小补
- `router/dns` 后续若再推进，应压成少数高层 boundary，而不是重新展开细碎 seam churn

## 归档判断
- `WP-30` 继续视为 archive baseline，`ef333bb7` 仍是归档基线
- 当前最适合继续推进的维护主题已从 patch-plan / DERP baseline 转到 router/dns 结构治理；本卡完成后，这条主线已收掉最值得优先处理的一层结构债
