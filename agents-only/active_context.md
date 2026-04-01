<!-- tier: S -->
# 当前上下文（Active Context）

> **用途**：高频更新，每次任务结束时维护。**S-tier：每次会话必读。**
> **纪律**：仅保留当前阶段最关键事实。本文件严格 ≤100 行。

---

## 战略状态

**当前阶段**: 维护模式，L1-L25 全部 Closed
**Parity**: 92.9% (52/56)

## 最近完成（2026-04-01）

### WP-30aa：deprecation detection owner 迁移 — 已完成

- `crates/sb-config/src/validator/v2/deprecation.rs` 现在是 deprecation detection 的实际 owner
  - `check_deprecations()`、`resolve_deprecation_pattern()`、`resolve_pattern_recursive()` 已迁入
  - 通过 `super::emit_issue` 引用共享 helper
  - 依赖 `crate::deprecation::{deprecation_directory, DeprecationSeverity}` 数据源
- `validator/v2/mod.rs` 中 `validate_v2()` 对 deprecation 只做一行委托：`deprecation::check_deprecations(doc)`
- mod.rs 从 1607 → 1204 行（-403），deprecation.rs 427 行
- **这是 validator/v2 deprecation detection owner 迁移卡，不是 RuntimePlan 卡**
- 不改 inbound/outbound/endpoint/service/dns/route validation/lowering owner
- 不改 planning / RuntimePlan / query API
- 不改 deprecation directory 数据源、issue 文案、匹配语义
- 迁移 8 个 deprecation 测试 + 2 个 pins：
  - `wp30aa_pin_deprecation_owner_is_deprecation_rs` — deprecation detection owner 在 deprecation.rs
  - `wp30aa_pin_validate_v2_delegates_deprecation` — validate_v2() 对 deprecation 只做委托

### WP-30z：outbound lowering owner 迁移 — 已完成（earlier）
### WP-30y：route lowering owner 迁移 — 已完成（earlier）
### WP-30x：DNS lowering owner 迁移 — 已完成（earlier）
### WP-30w ~ WP-30k：service/endpoint/inbound/planned seam 系列 — 已完成（earlier）

## 剩余 Maintenance 债务（非阻塞）

- `logging.rs` public compat 壳：为 Rust API 兼容保留
- `security_metrics.rs` public compat wrapper：已瘦身为单行委托
- `sb-metrics` LazyLock 指标静态：不继续做全量去全局化

## 后续战场（未启动）

- **WP-30 Phase 3 后续**：
  - validator/v2 mod.rs 进一步瘦身（1204 行，deprecation + inbound + outbound + endpoint + service + dns + route 已拆出）
  - `PlannedFacts` 暴露 namespace 查询方法供 crate 内其他模块使用
  - 将 `PlannedFacts` 升级为 public `RuntimePlan`（需要先有稳定外部消费者）
  - 仍不是 `RuntimePlan` public 实作卡，也不是 crate-internal query API 卡
- bootstrap.rs / run_engine.rs 职责收口
