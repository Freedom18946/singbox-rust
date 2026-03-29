<!-- tier: S -->
# 当前上下文（Active Context）

> **用途**：高频更新，每次任务结束时维护。**S-tier：每次会话必读。**
> **纪律**：仅保留当前阶段最关键事实。本文件严格 ≤100 行。

---

## 战略状态

**当前阶段**: 维护模式，L1-L25 全部 Closed
**Parity**: 92.9% (52/56)

## 最近完成（2026-03-29）

### WP-30o：crate-private planned fact graph seam — 已完成

- 将 WP-30l/m/n 的离散 helper 收成 **crate-private structured fact graph** `PlannedFacts`
- `PlannedFacts::collect(&ConfigIR)` 扫描全部 4 个 namespace（outbound/endpoint、inbound、DNS server、service）
- `PlannedFacts::validate(&self, &ConfigIR)` 校验全部 11 类引用关系
- 单一入口 `validate_planned_facts()` 替代之前的 `validate_outbound_references()` + `validate_cross_references()`
- `Config::validate()` 现在只调用一次 planned seam
- **仍然不是 public `RuntimePlan` / `PlannedConfigIR` / builder**
- **runtime-facing DNS env bridge 仍在 `app::run_engine`**
- **inbound tag uniqueness 仍留在 `Config::validate()` (lib.rs)**
- **validator/v2、normalize、minimize、present 职责仍未搬**
- 新增/重写 38 个 planned.rs unit tests + 6 个 pin tests，lib.rs integration tests 全部保留不变

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
    - 抽取 inbound tag uniqueness 进 `PlannedFacts`（目前故意留在 lib.rs）
    - 让 `PlannedFacts` 暴露 namespace 查询方法供 crate 内其他模块使用
    - 将 `PlannedFacts` 升级为 public `RuntimePlan`（需要先有稳定外部消费者）
  - 仍不是 `RuntimePlan` public 实作卡
  - `normalize.rs` 接入 IR-level normalization
- validator/v2 mod.rs 进一步瘦身（仍 4630 行）
- bootstrap.rs / run_engine.rs 职责收口
