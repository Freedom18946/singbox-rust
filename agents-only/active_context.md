<!-- tier: S -->
# 当前上下文（Active Context）

> **用途**：高频更新，每次任务结束时维护。**S-tier：每次会话必读。**
> **纪律**：仅保留当前阶段最关键事实。本文件严格 ≤100 行。

---

## 战略状态

**当前阶段**: 维护模式，L1-L25 全部 Closed
**Parity**: 92.9% (52/56)

## 最近完成（2026-03-31）

### WP-30u：inbound lowering owner 迁移 — 已完成

- `crates/sb-config/src/validator/v2/inbound.rs` 现在是 inbound validation + lowering 的实际 owner
  - 新增 `pub(crate) fn lower_inbounds(doc, ir)` — 承接 `to_ir_v1()` 中全部 inbound lowering
  - `parse_listen_host_port()` 从 mod.rs 迁入（仅被 inbound lowering 使用）
  - 覆盖：type→InboundType 映射、listen/port/listen_port 优先级、host:port 解析、sniff/sniff_override_destination/udp、basicAuth、direct-only override、set_system_proxy/allow_private_network、ssh_host_key_path 等全部 inbound IR 字段
- `validator/v2/mod.rs` 中 `to_ir_v1()` 对 inbound 只做一行委托：`inbound::lower_inbounds(doc, &mut ir)`
- mod.rs 从 4497 → 4269 行（-228 行），inbound.rs 从 372 → 906 行
- **这是 validator/v2 inbound lowering owner 迁移卡，不是 RuntimePlan 卡**
- 不改 outbound/dns/service/endpoint lowering owner
- 不改 parse-time defaults / alias / ENV resolution 的现有语义
- 不引入 planning / RuntimePlan / query API
- 新增 29 个测试（含 3 个 parse_listen_host_port 单元测试），含 pins：
  - `wp30u_pin_inbound_lowering_owner_is_inbound_rs` — lowering owner 在 inbound.rs
  - `wp30u_pin_mod_rs_to_ir_v1_delegates_inbound` — to_ir_v1() 对 inbound 只做委托
  - 覆盖：type 映射、listen_port/port 优先级、host:port 解析、IPv6 解析、默认端口、direct override、non-direct 无 override、override_host alias、basicAuth/env、sniff、udp via network/flag、set_system_proxy、allow_private_network、ssh_host_key_path

### WP-30t：inbound validation owner 迁移 — 已完成（earlier）

### WP-30s：minimize seam owner 迁移 — 已完成（earlier）
### WP-30r：normalize seam owner 迁移 — 已完成（earlier）
### WP-30q ~ WP-30k：planned seam 系列 — 已完成（earlier）

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
- validator/v2 mod.rs 进一步瘦身（4497 行，inbound 已拆出）
- bootstrap.rs / run_engine.rs 职责收口
