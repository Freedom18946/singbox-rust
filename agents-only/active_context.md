<!-- tier: S -->
# 当前上下文（Active Context）

> **用途**：高频更新，每次任务结束时维护。**S-tier：每次会话必读。**
> **纪律**：仅保留当前阶段最关键事实。本文件严格 ≤100 行。

---

## 战略状态

**当前阶段**: 维护模式，L1-L25 全部 Closed
**Parity**: 92.9% (52/56)

## 最近完成（2026-04-01）

### WP-30x：DNS lowering owner 迁移 — 已完成

- `crates/sb-config/src/validator/v2/dns.rs` 现在是 DNS validation + lowering 的实际 owner
  - 新增 `pub(super) fn lower_dns(doc, ir)` — 承接 `to_ir_v1()` 中全部 DNS lowering
  - 1 个 DNS-only helper 迁入：`infer_dns_server_type_from_address`
  - 1 个共享 helper 升级为 `pub(super)`：`parse_u32_field`
  - 覆盖：servers（tag/name alias、type/server/address compat、TLS extras sni/ca_paths/ca_pem/skip_cert_verify、address_resolver/service/detour/strategy、resolved type 无 address 兼容）、rules（server/action/priority、index fallback to server tag、string list matchers、matching fields、action fields）、global knobs（default/final/disable_cache/reverse_mapping/strategy/client_subnet/independent_cache/disable_expire/timeout_ms）、ttl block、fakeip block、pool block、static hosts（hosts_ttl + static_ttl alias）
- `validator/v2/mod.rs` 中 `to_ir_v1()` 对 DNS 只做一行委托：`dns::lower_dns(doc, &mut ir)`
- mod.rs 从 3864 → 3391 行（-473 行），dns.rs 从 221 → 1108 行
- **这是 validator/v2 DNS lowering owner 迁移卡，不是 RuntimePlan 卡**
- 不改 inbound/outbound/endpoint/service/route lowering owner
- 不改 parse-time defaults / alias / ENV resolution 的现有语义
- 不引入 planning / RuntimePlan / query API
- 新增 22 个 lowering 测试 + 2 个 pins（validation 8 个测试保留）：
  - `wp30x_pin_dns_lowering_owner_is_dns_rs` — lowering owner 在 dns.rs
  - `wp30x_pin_mod_rs_to_ir_v1_delegates_dns` — to_ir_v1() 对 DNS 只做委托

### WP-30w：service lowering owner 迁移 — 已完成（earlier）
### WP-30v：endpoint lowering owner 迁移 — 已完成（earlier）
### WP-30u ~ WP-30k：inbound/planned seam 系列 — 已完成（earlier）

## 剩余 Maintenance 债务（非阻塞）

- `logging.rs` public compat 壳：为 Rust API 兼容保留
- `security_metrics.rs` public compat wrapper：已瘦身为单行委托
- `sb-metrics` LazyLock 指标静态：不继续做全量去全局化

## 后续战场（未启动）

- **WP-30 Phase 3 后续**：
  - validator/v2 mod.rs 进一步瘦身（3391 行，inbound + endpoint + service + dns 已拆出）
  - 可考虑 route/outbound lowering owner 迁移
  - `PlannedFacts` 暴露 namespace 查询方法供 crate 内其他模块使用
  - 将 `PlannedFacts` 升级为 public `RuntimePlan`（需要先有稳定外部消费者）
  - 仍不是 `RuntimePlan` public 实作卡，也不是 crate-internal query API 卡
- bootstrap.rs / run_engine.rs 职责收口
