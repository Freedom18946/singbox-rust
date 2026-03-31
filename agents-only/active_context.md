<!-- tier: S -->
# 当前上下文（Active Context）

> **用途**：高频更新，每次任务结束时维护。**S-tier：每次会话必读。**
> **纪律**：仅保留当前阶段最关键事实。本文件严格 ≤100 行。

---

## 战略状态

**当前阶段**: 维护模式，L1-L25 全部 Closed
**Parity**: 92.9% (52/56)

## 最近完成（2026-03-31）

### WP-30v：endpoint lowering owner 迁移 — 已完成

- `crates/sb-config/src/validator/v2/endpoint.rs` 现在是 endpoint validation + lowering 的实际 owner
  - 新增 `pub(crate) fn lower_endpoints(doc, ir)` — 承接 `to_ir_v1()` 中全部 endpoint lowering
  - `extract_string_list` 从 `fn` 升级为 `pub(super) fn`（共享 helper，仍在 mod.rs）
  - 覆盖：type→EndpointType 映射、peers→WireGuardPeerIR、tag/network/system_interface/interface_name/mtu/address/private_key/listen_port/udp_timeout/workers、tailscale 全部字段
- `validator/v2/mod.rs` 中 `to_ir_v1()` 对 endpoint 只做一行委托：`endpoint::lower_endpoints(doc, &mut ir)`
- mod.rs 从 4269 → 4168 行（-101 行），endpoint.rs 从 195 → 536 行
- **这是 validator/v2 endpoint lowering owner 迁移卡，不是 RuntimePlan 卡**
- 不改 inbound/outbound/dns/service/route lowering owner
- 不改 parse-time defaults / alias / ENV resolution 的现有语义
- 不引入 planning / RuntimePlan / query API
- 新增 15 个测试（含 2 个 pins）：
  - `wp30v_pin_endpoint_lowering_owner_is_endpoint_rs` — lowering owner 在 endpoint.rs
  - `wp30v_pin_mod_rs_to_ir_v1_delegates_endpoint` — to_ir_v1() 对 endpoint 只做委托
  - 覆盖：type 映射（wireguard/tailscale/default/unknown fallback）、wireguard 顶层字段、tailscale 顶层字段、peers lowering、空 peers、无 peers key、无 endpoints、network listable string、advertise_routes listable string、多 endpoint

### WP-30u：inbound lowering owner 迁移 — 已完成（earlier）
### WP-30t：inbound validation owner 迁移 — 已完成（earlier）
### WP-30s ~ WP-30k：planned seam 系列 — 已完成（earlier）

## 剩余 Maintenance 债务（非阻塞）

- `logging.rs` public compat 壳：为 Rust API 兼容保留
- `security_metrics.rs` public compat wrapper：已瘦身为单行委托
- `sb-metrics` LazyLock 指标静态：不继续做全量去全局化

## 后续战场（未启动）

- **WP-30 Phase 3 后续**：
  - validator/v2 mod.rs 进一步瘦身（4168 行，inbound + endpoint 已拆出）
  - 可考虑 route/dns/service/outbound lowering owner 迁移
  - `PlannedFacts` 暴露 namespace 查询方法供 crate 内其他模块使用
  - 将 `PlannedFacts` 升级为 public `RuntimePlan`（需要先有稳定外部消费者）
  - 仍不是 `RuntimePlan` public 实作卡，也不是 crate-internal query API 卡
- bootstrap.rs / run_engine.rs 职责收口
