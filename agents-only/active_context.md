<!-- tier: S -->
# 当前上下文（Active Context）

> **用途**：高频更新，每次任务结束时维护。**S-tier：每次会话必读。**
> **纪律**：仅保留当前阶段最关键事实。本文件严格 ≤100 行。

---

## 战略状态

**当前阶段**: 维护模式，L1-L25 全部 Closed
**Parity**: 92.9% (52/56)

## 最近完成（2026-03-29）

### WP-30l：private planned tag/reference inventory seam — 已完成

- 在 `crates/sb-config/src/ir/planned.rs` 落地了 **crate-private** tag/reference inventory seam
- `Config::validate()` 现在把四类 outbound/endpoint/reference 检查委托给 `planned::validate_outbound_references()`
- seam 结构：`TagNamespace`（tag 扫描）+ `ReferenceValidator`（引用校验）+ `validate_outbound_references()`（入口）
- 承接了四类责任：tag namespace uniqueness, selector/urltest members, rule outbound, route.default
- **inbound tag uniqueness 故意留在 `Config::validate()` 原位**
- **没有新增 public `RuntimePlan` / `PlannedConfigIR` / builder API**
- 新增 10 个 planned.rs unit tests + 6 个 lib.rs integration tests
- 错误文案完全不变

### WP-30k：planned.rs preflight seam inventory — 已完成（earlier）

### WP-30j：Masquerade shared helper Raw closure — 已完成（earlier）
### WP-30i：Outbound nested Raw boundary pilot — 已完成（earlier）
### WP-30h ~ WP-30a — 已完成（earlier）

## 剩余 Maintenance 债务（非阻塞）

- `logging.rs` public compat 壳：为 Rust API 兼容保留
- `security_metrics.rs` public compat wrapper：已瘦身为单行委托
- `sb-metrics` LazyLock 指标静态：不继续做全量去全局化

## 后续战场（未启动）

- **WP-30 Phase 3 后续**：
  - 所有 config-facing strict input boundary 已 Raw 化（WP-30a ~ WP-30j）
  - `WP-30k` 已完成前置 seam inventory
  - `WP-30l` 已落地 first-cut private planned seam（tag/reference inventory）
  - 下一步若继续 planned.rs，推荐第二刀：DNS/service detour cross-reference expansion
  - 或可考虑：将 planned seam 扩展为 full planned fact graph（含 address_resolver, dns detour 等）
  - 仍不是 `RuntimePlan` public 实作卡
  - `normalize.rs` 接入 IR-level normalization
- validator/v2 mod.rs 进一步瘦身（仍 4630 行）
- bootstrap.rs / run_engine.rs 职责收口
