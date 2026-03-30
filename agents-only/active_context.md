<!-- tier: S -->
# 当前上下文（Active Context）

> **用途**：高频更新，每次任务结束时维护。**S-tier：每次会话必读。**
> **纪律**：仅保留当前阶段最关键事实。本文件严格 ≤100 行。

---

## 战略状态

**当前阶段**: 维护模式，L1-L25 全部 Closed
**Parity**: 92.9% (52/56)

## 最近完成（2026-03-30）

### WP-30r：normalize seam owner 迁移 — 已完成

- `crates/sb-config/src/ir/normalize.rs` 现在是 normalization 的实际 owner
  - 收纳全部 rule token canonicalization 逻辑（`normalize_rule`、`normalize_config`、helper）
  - 声明为 `pub(crate)`，`ir/mod.rs` 中 `pub(crate) mod normalize`
- `crates/sb-config/src/normalize.rs` 现在是 thin compat shell（pure delegate）
  - 保留 `pub fn normalize_rule` / `pub fn normalize_config` 的 public surface
  - 不含任何逻辑，只转发到 `crate::ir::normalize`
- `crates/sb-config/src/minimize.rs` import 已更新为 `crate::ir::normalize::normalize_config`
- normalize 仍只做 token canonicalization，不碰 planned references
- **这是 normalize seam 的 owner 迁移卡，不是 planning 语义扩张卡**
- 新增 pin tests：
  - `wp30r_pin_normalize_only_rewrites_rule_tokens` — normalize 不碰 planned references
  - `wp30r_pin_owner_is_ir_normalize` — owner 在 ir/normalize.rs
  - `wp30r_pin_compat_shell_is_pure_delegate` — compat shell 只是转发
  - `wp30r_pin_compat_shell_normalize_config_delegates` — normalize_config 通过 compat shell 正常工作
- 旧 pin `planned_preflight_pin_current_owner_normalize_only_rewrites_rule_tokens` 已被 `wp30r_pin_normalize_only_rewrites_rule_tokens` 取代

### WP-30q：DNS server / service namespace uniqueness — 已完成（earlier）
### WP-30p：inbound uniqueness absorption — 已完成（earlier）
### WP-30o/n/m/l/k：planned seam 系列 — 已完成（earlier）

## 剩余 Maintenance 债务（非阻塞）

- `logging.rs` public compat 壳：为 Rust API 兼容保留
- `security_metrics.rs` public compat wrapper：已瘦身为单行委托
- `sb-metrics` LazyLock 指标静态：不继续做全量去全局化

## 后续战场（未启动）

- **WP-30 Phase 3 后续**：
  - 所有 config-facing strict input boundary 已 Raw 化（WP-30a ~ WP-30j）
  - planned.rs fact graph 已完成 collect-phase completeness（WP-30k ~ WP-30q）
  - normalize seam owner 已迁移到 ir/normalize.rs（WP-30r）
  - 下一步若继续 IR 分层，可考虑：
    - minimize.rs owner 迁移到 ir/ 下
    - `PlannedFacts` 暴露 namespace 查询方法供 crate 内其他模块使用
    - 将 `PlannedFacts` 升级为 public `RuntimePlan`（需要先有稳定外部消费者）
  - 仍不是 `RuntimePlan` public 实作卡，也不是 crate-internal query API 卡
- validator/v2 mod.rs 进一步瘦身（仍 4630 行）
- bootstrap.rs / run_engine.rs 职责收口
