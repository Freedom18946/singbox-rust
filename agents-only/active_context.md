<!-- tier: S -->
# 当前上下文（Active Context）

> **用途**：高频更新，每次任务结束时维护。**S-tier：每次会话必读。**
> **纪律**：仅保留当前阶段最关键事实。本文件严格 ≤100 行。

---

## 战略状态

**当前阶段**: 维护模式，L1-L25 全部 Closed
**Parity**: 92.9% (52/56)

## 最近完成（2026-03-29）

### WP-30k：planned.rs preflight seam inventory — 已完成

- 新增 `agents-only/planned_preflight_inventory.md`，把 planned-layer 候选职责的当前 owner 钉成仓库事实表
- `crates/sb-config/src/ir/planned.rs` 从泛 skeleton 升级为 **前置契约注释**
- **没有实现 `RuntimePlan`**
- **没有新增 public planned API / builder**
- 当前推荐 first cut：
  - 先从 `Config::validate()` 现有检查里抽出 private tag/reference inventory
  - 仅覆盖 outbound/endpoint tag namespace、selector/urltest members、`rule.outbound`、`route.default`
- 明确暂不搬：
  - `validator/v2` 的 parse-time defaults / alias fill / ENV resolution
  - `normalize.rs` / `minimize.rs` / `present.rs`
  - `bootstrap.rs` selector/urltest 二次绑定
  - `run_engine.rs` DNS env bridge
- 新增 3 个 planned preflight pin tests：
  - `validated.rs` pin `ConfigIR::validate()` 仍负责 selector/urltest member 形状校验
  - `normalize.rs` pin `normalize_config()` 只改 token，不改 reference strings
  - `lib.rs` substitute pin `dns.detour` today 仍只 parse/保留，不在 `sb-config` 内绑定

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
  - `WP-30k` 已完成前置 seam inventory；下一步才是第一刀 private planned seam
  - 推荐下一卡：围绕 `Config::validate()` 现有 tag/reference 检查抽 private inventory helper
  - 仍不是 `RuntimePlan` public 实作卡
  - `normalize.rs` 接入 IR-level normalization
- validator/v2 mod.rs 进一步瘦身（仍 4630 行）
- bootstrap.rs / run_engine.rs 职责收口
