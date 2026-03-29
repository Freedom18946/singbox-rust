<!-- tier: S -->
# 当前上下文（Active Context）

> **用途**：高频更新，每次任务结束时维护。**S-tier：每次会话必读。**
> **纪律**：仅保留当前阶段最关键事实。本文件严格 ≤100 行。

---

## 战略状态

**当前阶段**: 维护模式，L1-L25 全部 Closed
**Parity**: 92.9% (52/56)

## 最近完成（2026-03-29）

### WP-30m：private planned cross-reference expansion seam — 已完成

- 在 `crates/sb-config/src/ir/planned.rs` 把 private seam 从"单 namespace"扩展为"多 namespace cross-reference inventory"
- `Config::validate()` 现在额外调用 `planned::validate_cross_references()` 承接四类新增检查：
  - `DnsServerIR.detour` → outbound/endpoint shared tag namespace
  - `DnsServerIR.address_resolver` → DNS server tag namespace
  - `DnsServerIR.service` → service tag namespace
  - `ServiceIR.detour` → inbound tag namespace
- 新增 crate-private 类型：`InboundNamespace`、`DnsServerNamespace`、`ServiceNamespace`、`CrossReferenceValidator`
- WP-30l 原有四类检查（`validate_outbound_references`）完全不变
- **inbound tag uniqueness 仍留在 `Config::validate()` 原位**
- **没有新增 public `RuntimePlan` / `PlannedConfigIR` / builder API**
- **runtime-facing DNS env bridge 仍在 `app::run_engine`，未搬进 planned.rs**
- 新增 13 个 planned.rs unit tests + 6 个 lib.rs integration tests
- 更新了 WP-30k pin test（dns.detour 现在被校验，但仍不做 env binding）

### WP-30l：private planned tag/reference inventory seam — 已完成（earlier）

- first-cut private seam：`TagNamespace` + `ReferenceValidator` + `validate_outbound_references()`
- 承接四类责任：tag namespace uniqueness, selector/urltest members, rule outbound, route.default

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
  - `WP-30m` 已落地 second-cut cross-reference expansion（DNS/service detour + address_resolver + service ref）
  - 下一步若继续 planned.rs，推荐第三刀：DNS rule `server` reference + DnsIR `default`/`final_server` reference
  - 或可考虑：将 planned seam 扩展为 full planned fact graph
  - 仍不是 `RuntimePlan` public 实作卡
  - `normalize.rs` 接入 IR-level normalization
- validator/v2 mod.rs 进一步瘦身（仍 4630 行）
- bootstrap.rs / run_engine.rs 职责收口
