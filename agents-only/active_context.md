<!-- tier: S -->
# 当前上下文（Active Context）
> **用途**：高频更新，每次任务结束时维护。**S-tier：每次会话必读。**
> **纪律**：仅保留当前阶段最关键事实。本文件严格 ≤100 行。
---
## 战略状态
**当前阶段**: 维护模式，L1-L25 全部 Closed
**Parity**: 92.9% (52/56)，以 `labs/interop-lab/docs/dual_kernel_golden_spec.md` 为准
**当前维护线**: `MT-TEST-01` patch-plan / test baseline stabilization — 已完成；`MT-SVC-01`、`MT-HOT-OBS-01`、`MT-RTC-03`、`MT-RTC-02`、`MT-RTC-01`、`MT-OBS-01` 与 `WP-30` 继续保持已完成 / 已归档状态

## 最近完成（2026-04-02）

### MT-TEST-01：patch-plan / test baseline stabilization — 已完成
- 本卡按当前源码事实推进，性质明确为 maintenance / test-baseline quality work，不是 dual-kernel parity completion，也没有恢复 `.github/workflows/*`
- 真实代码布局比高层候选切口更集中：当前直接 owner 在 `crates/sb-core/src/router/patch_apply.rs`，回归链路落在 `crates/sb-core/tests/{patch_plan_test,router_rules_suffix_shadow_fix}.rs`
- 已确认并修复的真实根因：
  - `crates/sb-core/tests/patch_plan_test.rs::plan_and_apply` 失败不是 fixture / tempdir / sleep 问题，而是 `suffix_shadow_cleanup` 生成 `-exact:...=<TO-BE-REMOVED>` 占位删除行
  - `router::patch_apply::apply_cli_patch(...)` 原先只按整行精确匹配删除；因此删除规则永远打不中真实 `exact:...=proxy` 文本，`apply_plan(...)` 会留下 stale exact 行
- 本轮收口：
  - `patch_apply.rs` 新增最小 delete-rule seam，支持 `<TO-BE-REMOVED>` 占位删除按 `key=` 匹配任意现值；保留原有精确删除语义
  - 新增 `router::patch_apply::tests::placeholder_delete_matches_existing_rule_value`
  - `router_rules_suffix_shadow_fix.rs` 新增 `suffix_shadow_cleanup_patch_applies_placeholder_delete`，pin 住 patch 生成到应用的真实链路
- 本轮没有推进 `planned.rs`、public `RuntimePlan`、public `PlannedConfigIR`、generic query API，也没有扩散到 router/dns/tun/runtime actor 主线

## 当前稳定事实
- `planned.rs` 仍是 staged crate-private seam；当前仓库仍无 public `RuntimePlan`、public `PlannedConfigIR`、generic query API
- `app/src/run_engine.rs`、`app/src/bootstrap.rs`、`crates/sb-config/src/ir/mod.rs`、`crates/sb-config/src/validator/v2/mod.rs` 继续视为稳定 facade / compat shell，不应回灌 owner 巨石
- `MT-RTC-01/02/03` 与 `MT-OBS-01` 的 owner/query/lifecycle 主线仍稳定；`MT-HOT-OBS-01`、`MT-SVC-01`、`MT-TEST-01` 都是 maintenance 收口，不重新打开 runtime actor/context 主线
- 当前工作区仍存在大量无关在制改动；本卡只顺着目标切口做治理，没有回滚或覆盖 unrelated workspace changes

## 当前验证事实
- 已通过：
  - `cargo test -p sb-core --all-features --lib patch_apply::tests::placeholder_delete_matches_existing_rule_value -- --test-threads=1`
  - `cargo test -p sb-core --all-features --test router_rules_suffix_shadow_fix -- --test-threads=1`
  - `cargo test -p sb-core --all-features --test patch_plan_test plan_and_apply -- --test-threads=1`
  - `cargo test -p sb-core --all-features --test patch_plan_test -- --test-threads=1`
  - `cargo test -p sb-core --all-features --tests -- --test-threads=1`
  - `cargo test -p sb-core --all-features --lib -- --test-threads=1`
  - `cargo clippy -p sb-core --all-features --all-targets -- -D warnings`
- 当前 workspace 的 `cargo test -p sb-core --all-features --tests -- --test-threads=1` 已不再被 DERP 或 patch-plan 基线失败阻塞；本卡验收时整条命令通过
- 补充事实：`cargo test -p sb-core --all-features patch_plan_test::plan_and_apply -- --test-threads=1` 在当前仓库只会把集成测试过滤成 0 个；真实定向命令应使用 `--test patch_plan_test plan_and_apply`

## Future Work（高层方向）
- patch-plan / preview-plan 后续仍可继续观察更复杂 patch kind（如 `rule[n]` 级 lint autofix）的应用语义，但只在出现真实 consumer 或新的 baseline failure 时再推进
- DERP/services 仍可继续观察更深层 reconnect/backoff/shutdown 一致性，但后续只在出现真实 flake / leaked task / mesh owner consumer 时再继续推进
- `router/dns` 仍有 mega-file 级别的 deeper refactor 空间，但后续只按高层主题推进，不回到细碎 seam churn
- `tun` / `outbound` 仍可继续观察更深层 perf hotspot，但应以真实 profiler / 回归信号为前提，而不是为了凑卡继续硬改
- metrics/logging 仍保留少量 compat/global 壳；后续只在出现真实 owner/query consumer 时再继续收口

## 归档判断
- `WP-30` 继续视为 archive baseline，`ef333bb7` 仍是归档基线
- runtime actor/context 主线当前阶段已 close-out；新的维护主题更适合围绕热点链路与 observability debt，而不是继续拆 runtime 主线小卡
