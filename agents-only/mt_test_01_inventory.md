# MT-TEST-01 inventory

## 定位

- 主题：patch-plan / test baseline stabilization
- 性质：maintenance / test-baseline quality work
- 形式：10 合 1 的高层维护卡，但实际实现严格按当前源码事实收口
- 非目标：dual-kernel parity completion、恢复 `.github/workflows/*`、推进 `planned.rs` 公共化、public `RuntimePlan`、public `PlannedConfigIR`、generic query API、扩散到 router/dns/tun/runtime actor 主线

## 本轮复核结论

- 当前真实代码布局比高层候选切口更集中：
  - 直接 apply owner 在 `crates/sb-core/src/router/patch_apply.rs`
  - 当前失败入口固定复现在 `crates/sb-core/tests/patch_plan_test.rs`
  - 共享同类 patch fixture / generator pin 主要在 `crates/sb-core/tests/router_rules_suffix_shadow_fix.rs`
- `crates/sb-core/tests/patch_plan_test.rs::plan_and_apply` 的真实根因不是排序、sleep、tempdir、teardown 或文件系统残留，而是 patch 生成与 patch 应用语义不一致：
  - `suffix_shadow_cleanup` 会生成 `-exact:a.example.com=<TO-BE-REMOVED>` 这种占位删除行
  - `apply_cli_patch(...)` 原先只按整行精确匹配删除
  - 因此补丁应用时不会删掉真实 `exact:a.example.com=proxy` 行，`apply_plan(...)` 会把 `portset` 追加成功，但留下 stale exact rule
- 这条 root cause 同时影响 `sb-core` 的 `patch_plan` 链路和 `sb-subscribe` 的 preview dry-run apply consumer，因此修复点应落在共用 apply seam，而不是只改单测断言

## 本轮源码收口

### `crates/sb-core/src/router/patch_apply.rs`

- 新增最小 `DeleteRule` seam：
  - `Exact(String)` 保持原有整行精确删除
  - `MatchAnyValue { key_prefix }` 只为 `<TO-BE-REMOVED>` 占位删除服务
- `parse_delete_rule(...)` 会把 `foo=<TO-BE-REMOVED>` 解析成 `foo=` 前缀匹配，而不是把占位文本当成真实值
- `delete_rule_matches(...)` 明确区分精确删除与“同 key 任意现值删除”
- 没有引入更大的 generic patch AST，也没有把 patch kind/preview API 公共化
- 新增单测：
  - `router::patch_apply::tests::placeholder_delete_matches_existing_rule_value`

### `crates/sb-core/tests/router_rules_suffix_shadow_fix.rs`

- 保留原有 patch text 生成 pin
- 新增：
  - `suffix_shadow_cleanup_patch_applies_placeholder_delete`
- 该测试直接覆盖 `analyze -> build_suffix_shadow_cleanup_patch -> apply_cli_patch` 真实链路，确保生成器与应用器的契约不再漂移

### `crates/sb-core/tests/patch_plan_test.rs`

- 无需放宽断言；现有 `plan_and_apply` 在 root cause 修复后直接恢复通过
- 本卡刻意没有靠改断言、加 sleep、改宽匹配来“让测试过去”

## 本轮测试 / pins

- `router::patch_apply::tests::placeholder_delete_matches_existing_rule_value`
- `router_rules_suffix_shadow_fix::suffix_shadow_cleanup_patch_applies_placeholder_delete`
- `patch_plan_test::plan_and_apply`

## 验收命令

- `cargo test -p sb-core --all-features --lib patch_apply::tests::placeholder_delete_matches_existing_rule_value -- --test-threads=1`
- `cargo test -p sb-core --all-features --test router_rules_suffix_shadow_fix -- --test-threads=1`
- `cargo test -p sb-core --all-features --test patch_plan_test plan_and_apply -- --test-threads=1`
- `cargo test -p sb-core --all-features --test patch_plan_test -- --test-threads=1`
- `cargo test -p sb-core --all-features --tests -- --test-threads=1`
- `cargo test -p sb-core --all-features --lib -- --test-threads=1`
- `cargo clippy -p sb-core --all-features --all-targets -- -D warnings`

## 当前验证结论

- 上述命令已按当前 workspace 事实通过
- `cargo test -p sb-core --all-features --tests -- --test-threads=1` 在本卡验收时整条通过，不再被 `patch_plan_test::plan_and_apply` 阻塞
- 补充事实：
  - `cargo test -p sb-core --all-features patch_plan_test::plan_and_apply -- --test-threads=1` 在当前仓库只会过滤到 0 个集成测试
  - 真实定向命令应使用 `cargo test -p sb-core --all-features --test patch_plan_test plan_and_apply -- --test-threads=1`

## 当前边界

- 本卡没有把 maintenance 工作误写成 parity completion
- 本卡没有推进 `planned.rs`、public `RuntimePlan`、public `PlannedConfigIR`
- 本卡没有为了让测试过而单纯放宽断言、增加 sleep、扩大模糊匹配范围
- 本卡没有引入新的 tempdir / fixture shared-state / cleanup 缺口
- 本卡没有卷入当前工作区的 unrelated app / config / metrics / audit 变更

## Future Work（高层方向）

- patch/preview 链路后续若再出现真实基线失败，可继续观察：
  - `lint_autofix` 中 `rule[n]` 风格 patch 的可应用语义
  - 更复杂 patch kind 是否需要显式 unsupported/error reporting，而不是静默忽略
- 除此之外，本线暂不继续细拆；剩余高层维护债务应回到：
  - 其他未来出现的独立 test baseline blocker
  - `router/dns` mega-file 风险
  - `tun/outbound` lifecycle / perf hotspot
