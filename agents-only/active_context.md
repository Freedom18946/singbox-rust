<!-- tier: S -->
# 当前上下文（Active Context）

> **用途**：高频更新，每次任务结束时维护。**S-tier：每次会话必读。**
> **纪律**：仅保留当前阶段最关键事实。本文件严格 ≤100 行。

---

## 战略状态

**当前阶段**: 维护模式，L1-L25 全部 Closed
**Parity**: 92.9% (52/56)

## 最近完成（2026-04-01）

### WP-30ae：root schema core owner 迁移 — 已完成

- `crates/sb-config/src/validator/v2/schema_core.rs` 现在是 root schema validation 的实际 owner
  - `validate_root_schema(doc, allow_unknown, issues) -> bool` pub(super) 入口
  - 收纳 schema load + fallback、`schema_version` 检查、root unknown field 检查（含 `$schema` 例外）
- `validator/v2/mod.rs` 中 `validate_v2()` 对 root schema validation 只做一行委托：`schema_core::validate_root_schema(doc, allow_unknown, &mut issues)`
- mod.rs 从 793 → 742 行（-51），schema_core.rs 263 行（含测试）
- **这是 validator/v2 root schema core owner 迁移卡，不是 RuntimePlan 卡**
- 不改 inbound/outbound/endpoint/service/dns/route/top_level validation/lowering owner
- 不改 deprecation / security / TLS capability / credentials pass owner
- 不改 `to_ir_v1()` / lowering 语义
- 不引入 planning / RuntimePlan / query API
- 9 个测试（7 功能 + 2 pins）：
  - `wp30ae_pin_schema_core_owner_is_schema_core_rs` — root schema validation owner 在 schema_core.rs
  - `wp30ae_pin_validate_v2_delegates_root_schema` — validate_v2() 对 root schema validation 只做委托

### WP-30ad：credential normalization owner 迁移 — 已完成（earlier）
### WP-30ac ~ WP-30k：top-level/security/deprecation/outbound/route/dns/service/endpoint/inbound/planned seam 系列 — 已完成（earlier）

## 剩余 Maintenance 债务（非阻塞）

- `logging.rs` public compat 壳：为 Rust API 兼容保留
- `security_metrics.rs` public compat wrapper：已瘦身为单行委托
- `sb-metrics` LazyLock 指标静态：不继续做全量去全局化

## 后续战场（未启动）

- **WP-30 Phase 3 后续**：
  - validator/v2 mod.rs 进一步瘦身（742 行，deprecation + security + credentials + schema_core + inbound + outbound + endpoint + service + dns + route + top-level 已拆出）
  - 剩余 mod.rs 内容：TLS capability matrix pass（re-export `check_tls_capabilities`）、`validate_v2()` / `to_ir_v1()` 入口 + 通用 shared helper
  - `PlannedFacts` 暴露 namespace 查询方法供 crate 内其他模块使用
  - 将 `PlannedFacts` 升级为 public `RuntimePlan`（需要先有稳定外部消费者）
  - 仍不是 `RuntimePlan` public 实作卡，也不是 crate-internal query API 卡
- bootstrap.rs / run_engine.rs 职责收口
