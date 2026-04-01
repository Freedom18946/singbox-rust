<!-- tier: S -->
# 当前上下文（Active Context）

> **用途**：高频更新，每次任务结束时维护。**S-tier：每次会话必读。**
> **纪律**：仅保留当前阶段最关键事实。本文件严格 ≤100 行。

---

## 战略状态

**当前阶段**: 维护模式，L1-L25 全部 Closed
**Parity**: 92.9% (52/56)

## 最近完成（2026-04-01）

### WP-30ab：security warning owner 迁移 — 已完成

- `crates/sb-config/src/validator/v2/security.rs` 现在是 non-localhost binding security warning 的实际 owner
  - `check_non_localhost_binding_warnings()` + `is_localhost_addr()` 已迁入
  - 通过 `super::emit_issue` 引用共享 helper
  - 覆盖：`experimental.clash_api.external_controller` 无 secret 绑定检测 + `services[*].listen` 无 auth_token 绑定检测
- `validator/v2/mod.rs` 中 `validate_v2()` 对 security warning 只做一行委托：`security::check_non_localhost_binding_warnings(doc)`
- mod.rs 从 1204 → 975 行（-229），security.rs 262 行
- **这是 validator/v2 security warning owner 迁移卡，不是 RuntimePlan 卡**
- 不改 deprecation / TLS capability / parse-time lowering / domain validation/lowering owner
- 不改 planning / RuntimePlan / query API
- 迁移 5 个 security warning 测试 + 1 个 integration 测试 + 2 个 pins：
  - `wp30ab_pin_security_warning_owner_is_security_rs` — security warning owner 在 security.rs
  - `wp30ab_pin_validate_v2_delegates_security_warnings` — validate_v2() 对 security warning 只做委托

### WP-30aa：deprecation detection owner 迁移 — 已完成（earlier）
### WP-30z ~ WP-30k：outbound/route/dns/service/endpoint/inbound/planned seam 系列 — 已完成（earlier）

## 剩余 Maintenance 债务（非阻塞）

- `logging.rs` public compat 壳：为 Rust API 兼容保留
- `security_metrics.rs` public compat wrapper：已瘦身为单行委托
- `sb-metrics` LazyLock 指标静态：不继续做全量去全局化

## 后续战场（未启动）

- **WP-30 Phase 3 后续**：
  - validator/v2 mod.rs 进一步瘦身（975 行，deprecation + security + inbound + outbound + endpoint + service + dns + route 已拆出）
  - 剩余 mod.rs 内容：TLS capability matrix pass、schema validation core、`to_ir_v1()` 入口 + 通用 helper、experimental/ntp/certificate lowering
  - `PlannedFacts` 暴露 namespace 查询方法供 crate 内其他模块使用
  - 将 `PlannedFacts` 升级为 public `RuntimePlan`（需要先有稳定外部消费者）
  - 仍不是 `RuntimePlan` public 实作卡，也不是 crate-internal query API 卡
- bootstrap.rs / run_engine.rs 职责收口
