<!-- tier: S -->
# 当前上下文（Active Context）

> **用途**：高频更新，每次任务结束时维护。**S-tier：每次会话必读。**
> **纪律**：仅保留当前阶段最关键事实。本文件严格 ≤100 行。

---

## 战略状态

**当前阶段**: 维护模式，L1-L25 全部 Closed
**Parity**: 92.9% (52/56)

## 最近完成（2026-04-01）

### WP-30ac：top-level lowering owner 迁移 — 已完成

- `crates/sb-config/src/validator/v2/top_level.rs` 现在是 experimental/log/ntp/certificate lowering 的实际 owner
  - `lower_top_level_blocks(doc, ir)` 统一入口
  - 通过 `super::parse_seconds_field_to_millis` / `super::parse_millis_field` 引用共享 helper
- `validator/v2/mod.rs` 中 `to_ir_v1()` 对 top-level lowering 只做一行委托：`top_level::lower_top_level_blocks(doc, &mut ir)`
- mod.rs 从 975 → 819 行（-156），top_level.rs 347 行（含测试）
- **这是 validator/v2 top-level lowering owner 迁移卡，不是 RuntimePlan 卡**
- 不改 inbound/outbound/endpoint/service/dns/route validation/lowering owner
- 不改 deprecation / security / TLS capability pass owner
- 不改 planning / RuntimePlan / query API
- 共享 helper（`parse_seconds_field_to_millis` / `parse_millis_field`）+ `normalize_credentials()` 保留在 mod.rs
- 迁移 3 个既有测试 + 8 个新测试 + 2 个 pins：
  - `wp30ac_pin_top_level_lowering_owner_is_top_level_rs` — top-level lowering owner 在 top_level.rs
  - `wp30ac_pin_to_ir_v1_delegates_top_level_lowering` — to_ir_v1() 对 top-level lowering 只做委托
- 修正 `route.rs` 中 `wp30y_pin_mod_rs_to_ir_v1_delegates_route` 的源码标记（适配新注释）

### WP-30ab：security warning owner 迁移 — 已完成（earlier）
### WP-30aa ~ WP-30k：deprecation/outbound/route/dns/service/endpoint/inbound/planned seam 系列 — 已完成（earlier）

## 剩余 Maintenance 债务（非阻塞）

- `logging.rs` public compat 壳：为 Rust API 兼容保留
- `security_metrics.rs` public compat wrapper：已瘦身为单行委托
- `sb-metrics` LazyLock 指标静态：不继续做全量去全局化

## 后续战场（未启动）

- **WP-30 Phase 3 后续**：
  - validator/v2 mod.rs 进一步瘦身（819 行，deprecation + security + inbound + outbound + endpoint + service + dns + route + top-level 已拆出）
  - 剩余 mod.rs 内容：TLS capability matrix pass、schema validation core、`to_ir_v1()` 入口 + 通用 helper、`normalize_credentials()`
  - `PlannedFacts` 暴露 namespace 查询方法供 crate 内其他模块使用
  - 将 `PlannedFacts` 升级为 public `RuntimePlan`（需要先有稳定外部消费者）
  - 仍不是 `RuntimePlan` public 实作卡，也不是 crate-internal query API 卡
- bootstrap.rs / run_engine.rs 职责收口
