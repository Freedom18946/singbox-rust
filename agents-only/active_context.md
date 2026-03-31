<!-- tier: S -->
# 当前上下文（Active Context）

> **用途**：高频更新，每次任务结束时维护。**S-tier：每次会话必读。**
> **纪律**：仅保留当前阶段最关键事实。本文件严格 ≤100 行。

---

## 战略状态

**当前阶段**: 维护模式，L1-L25 全部 Closed
**Parity**: 92.9% (52/56)

## 最近完成（2026-03-31）

### WP-30w：service lowering owner 迁移 — 已完成

- `crates/sb-config/src/validator/v2/service.rs` 现在是 service validation + lowering 的实际 owner
  - 新增 `pub(crate) fn lower_services(doc, ir)` — 承接 `to_ir_v1()` 中全部 service lowering
  - 3 个 service-only helpers 迁入：`parse_derp_verify_client_urls`、`parse_derp_mesh_with`、`parse_derp_stun_options`
  - 5 个共享 helper 升级为 `pub(super)`：`parse_u16_field`、`parse_fwmark_field`、`parse_inbound_tls_options`、`extract_listable_strings`、`parse_listable`
  - 覆盖：type→ServiceType 映射（resolved/ssm-api/ssmapi/derp）、legacy listen alias（resolved_listen/ssmapi_listen/derp_listen + 对应 listen_port）、通用字段 lowering（bind_interface/routing_mark/reuse_addr/netns/tcp_fast_open/tcp_multi_path/udp_fragment/udp_timeout/detour/sniff/sniff_override_destination/sniff_timeout/domain_strategy/udp_disable_domain_unmapping）、tls lowering、SSM API 专属字段（legacy tls paths/cache_path/servers）、DERP 专属字段（legacy tls paths/config_path/verify_client_endpoint/verify_client_url/home/mesh_psk/mesh_psk_file/mesh_with/stun + legacy stun fields）
- `validator/v2/mod.rs` 中 `to_ir_v1()` 对 service 只做一行委托：`service::lower_services(doc, &mut ir)`
- mod.rs 从 4168 → 3864 行（-304 行），service.rs 从 136 → 788 行
- **这是 validator/v2 service lowering owner 迁移卡，不是 RuntimePlan 卡**
- 不改 inbound/outbound/dns/endpoint/route lowering owner
- 不改 parse-time defaults / alias / ENV resolution 的现有语义
- 不引入 planning / RuntimePlan / query API
- 新增 25 个测试（含 2 个 pins）：
  - `wp30w_pin_service_lowering_owner_is_service_rs` — lowering owner 在 service.rs
  - `wp30w_pin_mod_rs_to_ir_v1_delegates_service` — to_ir_v1() 对 service 只做委托

### WP-30v：endpoint lowering owner 迁移 — 已完成（earlier）
### WP-30u ~ WP-30k：inbound/planned seam 系列 — 已完成（earlier）

## 剩余 Maintenance 债务（非阻塞）

- `logging.rs` public compat 壳：为 Rust API 兼容保留
- `security_metrics.rs` public compat wrapper：已瘦身为单行委托
- `sb-metrics` LazyLock 指标静态：不继续做全量去全局化

## 后续战场（未启动）

- **WP-30 Phase 3 后续**：
  - validator/v2 mod.rs 进一步瘦身（3864 行，inbound + endpoint + service 已拆出）
  - 可考虑 route/dns/outbound lowering owner 迁移
  - `PlannedFacts` 暴露 namespace 查询方法供 crate 内其他模块使用
  - 将 `PlannedFacts` 升级为 public `RuntimePlan`（需要先有稳定外部消费者）
  - 仍不是 `RuntimePlan` public 实作卡，也不是 crate-internal query API 卡
- bootstrap.rs / run_engine.rs 职责收口
