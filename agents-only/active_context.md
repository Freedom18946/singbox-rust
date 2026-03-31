<!-- tier: S -->
# 当前上下文（Active Context）

> **用途**：高频更新，每次任务结束时维护。**S-tier：每次会话必读。**
> **纪律**：仅保留当前阶段最关键事实。本文件严格 ≤100 行。

---

## 战略状态

**当前阶段**: 维护模式，L1-L25 全部 Closed
**Parity**: 92.9% (52/56)

## 最近完成（2026-04-01）

### WP-30y：route lowering owner 迁移 — 已完成

- `crates/sb-config/src/validator/v2/route.rs` 现在是 route validation + lowering 的实际 owner
  - 新增 `pub(super) fn lower_route(doc, ir)` — 承接 `to_ir_v1()` 中全部 route lowering
  - `parse_rule_entry()` 已迁入 `route.rs`，当前只由 route lowering 使用
  - 继续复用既有 `rule_set_format_from_path/url`
  - 覆盖：`route.geoip` / `route.geosite`、`rules[*] -> RuleIR`、logical rule lowering、`rule_set[*] -> RuleSetIR`、`default/final/final_outbound`、`find_process` / `override_android_vpn` / `auto_detect_interface` / `default_interface` / `mark`、`default_domain_resolver` / `default_resolver`、`default_network_strategy` / `network_strategy`、`default_network_type` / `default_fallback_network_type` / `default_fallback_delay` / `fallback_delay`
- `validator/v2/mod.rs` 中 `to_ir_v1()` 对 route 只做一行委托：`route::lower_route(doc, &mut ir)`
- mod.rs 从 3391 → 3093 行（-298），route.rs 从验证 owner 扩展为 validation + lowering owner
- **这是 validator/v2 route lowering owner 迁移卡，不是 RuntimePlan 卡**
- 不改 inbound/endpoint/service/dns/outbound lowering owner
- 不改 parse-time defaults / alias / ENV resolution 的现有语义
- 不引入 planning / RuntimePlan / query API
- 新增 9 个 lowering 测试 + 2 个 pins（validation 13 个测试保留）：
  - `wp30y_pin_route_lowering_owner_is_route_rs` — lowering owner 在 route.rs
  - `wp30y_pin_mod_rs_to_ir_v1_delegates_route` — to_ir_v1() 对 route 只做委托，mod.rs 不再持有 route 实现

### WP-30w：service lowering owner 迁移 — 已完成（earlier）
### WP-30v：endpoint lowering owner 迁移 — 已完成（earlier）
### WP-30u ~ WP-30k：inbound/planned seam 系列 — 已完成（earlier）

## 剩余 Maintenance 债务（非阻塞）

- `logging.rs` public compat 壳：为 Rust API 兼容保留
- `security_metrics.rs` public compat wrapper：已瘦身为单行委托
- `sb-metrics` LazyLock 指标静态：不继续做全量去全局化

## 后续战场（未启动）

- **WP-30 Phase 3 后续**：
  - validator/v2 mod.rs 进一步瘦身（3093 行，inbound + endpoint + service + dns + route lowering 已拆出）
  - 可考虑 outbound lowering owner 迁移
  - `PlannedFacts` 暴露 namespace 查询方法供 crate 内其他模块使用
  - 将 `PlannedFacts` 升级为 public `RuntimePlan`（需要先有稳定外部消费者）
  - 仍不是 `RuntimePlan` public 实作卡，也不是 crate-internal query API 卡
- bootstrap.rs / run_engine.rs 职责收口
