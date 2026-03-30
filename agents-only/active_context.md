<!-- tier: S -->
# 当前上下文（Active Context）

> **用途**：高频更新，每次任务结束时维护。**S-tier：每次会话必读。**
> **纪律**：仅保留当前阶段最关键事实。本文件严格 ≤100 行。

---

## 战略状态

**当前阶段**: 维护模式，L1-L25 全部 Closed
**Parity**: 92.9% (52/56)

## 最近完成（2026-03-31）

### WP-30t：inbound validation owner 迁移 — 已完成

- `crates/sb-config/src/validator/v2/inbound.rs` 现在是 inbound validation 的实际 owner
  - 收纳 `/inbounds` schema/type/required/unknown-field 校验逻辑
  - 导出 `pub(crate) fn validate_inbounds(doc, allow_unknown, issues)`
  - `allowed_inbound_keys()` 基于 `object_keys(InboundIR::default())` + raw-only extras
- `validator/v2/mod.rs` 中 `validate_v2()` 通过 `inbound::validate_inbounds()` 委托
- mod.rs 从 4630 → 4497 行（-133 行）
- **这是 validator/v2 inbound 子模块拆分卡，不是 inbound lowering 卡**
- 不迁移 `to_ir_v1()` 里的 inbound lowering
- 不改 parse-time defaults / alias / ENV resolution
- 不引入 planning / RuntimePlan / query API
- 新增 15 个测试，含 pin：
  - `wp30t_pin_inbound_validation_owner_is_inbound_rs` — owner 在 inbound.rs
  - 覆盖：非数组、非 object、type 缺失/非 string、非 tun 缺 listen、listen 非 string、port/listen_port 非数字、unknown field strict/allow_unknown、ptr 精度、valid passes

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
