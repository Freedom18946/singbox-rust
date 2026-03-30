<!-- tier: S -->
# 当前上下文（Active Context）

> **用途**：高频更新，每次任务结束时维护。**S-tier：每次会话必读。**
> **纪律**：仅保留当前阶段最关键事实。本文件严格 ≤100 行。

---

## 战略状态

**当前阶段**: 维护模式，L1-L25 全部 Closed
**Parity**: 92.9% (52/56)

## 最近完成（2026-03-30）

### WP-30q：DNS server / service namespace uniqueness — 已完成

- `DnsServerNamespace::scan()` 现在返回 `Result`，检查 DNS server tag 唯一性
- `ServiceNamespace::scan()` 现在返回 `Result`，检查 service tag 唯一性
- `PlannedFacts::collect()` 现在对**全部 4 个 namespace** 做唯一性校验
- 错误文案 `duplicate dns server tag: {tag}` / `duplicate service tag: {tag}` 已 pin
- `Config::validate()` 仍是 **thin entry point**
- 新增 unit tests: 7 个（collect reject/pass/edge-case + 2 pin tests）
- 新增 integration tests: 5 个（via Config::validate() 的 wp30q 系列）
- **仍然不是 public `RuntimePlan` / `PlannedConfigIR` / builder / crate-internal query API**
- **这是 planned fact graph collect-phase completeness 的 maintenance 卡**

### WP-30p：inbound uniqueness absorption — 已完成（2026-03-29）
### WP-30o：crate-private planned fact graph — 已完成（earlier）
### WP-30n/m/l/k：planned seam 三刀 — 已完成（earlier）

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
  - `WP-30p` 已吸收 inbound uniqueness
  - `WP-30q` 已补齐 DNS server / service uniqueness（collect-phase completeness）
  - 下一步若继续 planned.rs，可考虑：
    - 让 `PlannedFacts` 暴露 namespace 查询方法供 crate 内其他模块使用（需要先有稳定 crate 内消费者）
    - 将 `PlannedFacts` 升级为 public `RuntimePlan`（需要先有稳定外部消费者）
  - 仍不是 `RuntimePlan` public 实作卡，也不是 crate-internal query API 卡
  - `normalize.rs` 接入 IR-level normalization
- validator/v2 mod.rs 进一步瘦身（仍 4630 行）
- bootstrap.rs / run_engine.rs 职责收口
