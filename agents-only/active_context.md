<!-- tier: S -->
# 当前上下文（Active Context）

> **用途**：高频更新，每次任务结束时维护。**S-tier：每次会话必读。**
> **纪律**：仅保留当前阶段最关键事实。本文件严格 ≤100 行。

---

## 战略状态

**当前阶段**: 维护模式，L1-L25 全部 Closed
**Parity**: 92.9% (52/56)

## 最近完成（2026-03-29）

### WP-30p：inbound uniqueness absorption seam — 已完成

- 将 inbound tag uniqueness 从 `Config::validate()` (lib.rs) 吸收入 `PlannedFacts::collect()`
- `InboundNamespace::scan()` 现在返回 `Result`，检查 inbound tag 唯一性
- `Config::validate()` 现在是 **thin entry point**，不再持有任何自己的校验逻辑
- inbound 与 outbound/endpoint 仍是**独立 namespace**（Go parity）
- 错误文案 `duplicate inbound tag: {tag}` 保持不变
- lib.rs 中 `HashSet` import 已移除（不再需要）
- 迁移 pin: `wp30l_pin_inbound_duplicate_tag_still_in_lib_validate` → `wp30p_pin_inbound_duplicate_tag_owned_by_fact_graph`
- 迁移 pin: `planned_pin_inbound_uniqueness_not_in_fact_graph` → `planned_pin_fact_graph_owns_inbound_uniqueness`
- 新增 pin: `planned_pin_validate_is_thin_entry_point` + `planned_pin_inbound_outbound_independent_namespaces`
- **仍然不是 public `RuntimePlan` / `PlannedConfigIR` / builder / crate-internal query API**
- **runtime-facing DNS env bridge 仍在 `app::run_engine`**

### WP-30o：crate-private planned fact graph seam — 已完成（earlier）
### WP-30n/m/l/k：planned seam 三刀 — 已完成（earlier）
### WP-30j ~ WP-30a：Raw boundary + seam inventory — 已完成（earlier）

## 剩余 Maintenance 债务（非阻塞）

- `logging.rs` public compat 壳：为 Rust API 兼容保留
- `security_metrics.rs` public compat wrapper：已瘦身为单行委托
- `sb-metrics` LazyLock 指标静态：不继续做全量去全局化

## 后续战场（未启动）

- **WP-30 Phase 3 后续**：
  - 所有 config-facing strict input boundary 已 Raw 化（WP-30a ~ WP-30j）
  - `WP-30k` 已完成前置 seam inventory
  - `WP-30l/m/n` 三刀已落地 private planned seam
  - `WP-30o` 已将离散 helper 收成 crate-private `PlannedFacts` fact graph
  - 下一步若继续 planned.rs，可考虑：
    - ~~抽取 inbound tag uniqueness 进 `PlannedFacts`~~ ✅ WP-30p 已完成
    - 让 `PlannedFacts` 暴露 namespace 查询方法供 crate 内其他模块使用（需要先有稳定 crate 内消费者）
    - 将 `PlannedFacts` 升级为 public `RuntimePlan`（需要先有稳定外部消费者）
    - DNS server / service namespace 唯一性检查（目前仅收集，不检查唯一性）
  - 仍不是 `RuntimePlan` public 实作卡，也不是 crate-internal query API 卡
  - `normalize.rs` 接入 IR-level normalization
- validator/v2 mod.rs 进一步瘦身（仍 4630 行）
- bootstrap.rs / run_engine.rs 职责收口
