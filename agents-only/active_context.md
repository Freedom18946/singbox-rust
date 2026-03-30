<!-- tier: S -->
# 当前上下文（Active Context）

> **用途**：高频更新，每次任务结束时维护。**S-tier：每次会话必读。**
> **纪律**：仅保留当前阶段最关键事实。本文件严格 ≤100 行。

---

## 战略状态

**当前阶段**: 维护模式，L1-L25 全部 Closed
**Parity**: 92.9% (52/56)

## 最近完成（2026-03-31）

### WP-30s：minimize seam owner 迁移 — 已完成

- `crates/sb-config/src/ir/minimize.rs` 现在是 minimization 的实际 owner
  - 收纳全部 post-validated optimization 逻辑（`MinimizeAction`、`minimize_config`、`fold_domains`、`fold_cidrs`、CIDR helpers）
  - 声明为 `pub(crate)`，`ir/mod.rs` 中 `pub(crate) mod minimize`
- `crates/sb-config/src/minimize.rs` 现在是 thin compat shell（pure delegate）
  - 保留 `pub enum MinimizeAction` / `pub fn minimize_config` 的 public surface
  - 不含任何逻辑，只转发到 `crate::ir::minimize`
- minimize 仍是 post-validated optimization，不是 planned contract
- negation-aware skip 语义保持不变（`SkippedByNegation` / `Applied`）
- 仍先调用 normalization（via `ir::normalize`），再决定是否继续 fold
- **这是 minimize seam 的 owner 迁移卡，不是 planning 语义扩张卡**
- 新增 pin tests：
  - `wp30s_pin_owner_is_ir_minimize` — owner 在 ir/minimize.rs
  - `wp30s_pin_minimize_is_not_planned` — minimize 不是 planned contract
  - `wp30s_pin_negation_only_normalizes` — negation 存在时只做 normalization
  - `wp30s_pin_compat_shell_is_pure_delegate` — compat shell 只是转发
  - `wp30s_pin_compat_shell_minimize_config_delegates` — minimize_config 通过 compat shell 正常工作
  - `apply_when_no_neg` — 无 negation 时 fold/dedup 正常执行

### WP-30r：normalize seam owner 迁移 — 已完成（earlier）
### WP-30q：DNS server / service namespace uniqueness — 已完成（earlier）
### WP-30p ~ WP-30k：planned seam 系列 — 已完成（earlier）

## 剩余 Maintenance 债务（非阻塞）

- `logging.rs` public compat 壳：为 Rust API 兼容保留
- `security_metrics.rs` public compat wrapper：已瘦身为单行委托
- `sb-metrics` LazyLock 指标静态：不继续做全量去全局化

## 后续战场（未启动）

- **WP-30 Phase 3 后续**：
  - 所有 config-facing strict input boundary 已 Raw 化（WP-30a ~ WP-30j）
  - planned.rs fact graph 已完成 collect-phase completeness（WP-30k ~ WP-30q）
  - normalize seam owner 已迁移到 ir/normalize.rs（WP-30r）
  - minimize seam owner 已迁移到 ir/minimize.rs（WP-30s）
  - 下一步若继续 IR 分层，可考虑：
    - `PlannedFacts` 暴露 namespace 查询方法供 crate 内其他模块使用
    - 将 `PlannedFacts` 升级为 public `RuntimePlan`（需要先有稳定外部消费者）
  - 仍不是 `RuntimePlan` public 实作卡，也不是 crate-internal query API 卡
- validator/v2 mod.rs 进一步瘦身（仍 4630 行）
- bootstrap.rs / run_engine.rs 职责收口
