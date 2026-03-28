<!-- tier: S -->
# 当前上下文（Active Context）

> **用途**：高频更新，每次任务结束时维护。**S-tier：每次会话必读。**
> **纪律**：仅保留当前阶段最关键事实。本文件严格 ≤100 行。

---

## 战略状态

**当前阶段**: 维护模式，L1-L25 全部 Closed
**Parity**: 92.9% (52/56)

## 最近完成（2026-03-28）

### WP-30i：Outbound nested Raw boundary pilot — 已完成

- `crates/sb-config/src/ir/raw.rs` 新增 5 个 Raw 类型，全部 `#[serde(deny_unknown_fields)]`：
  - `RawOutboundIR`、`RawHeaderEntry`、`RawCredentials`、`RawBrutalIR`、`RawMultiplexOptionsIR`
- 以下 validated 类型现在通过 Raw bridge 反序列化（不再 derive `Deserialize`）：
  - `OutboundIR`、`HeaderEntry`（在 `outbound.rs`）
  - `Credentials`、`MultiplexOptionsIR`、`BrutalIR`（在 `mod.rs`）
- `RawConfigRoot.outbounds` 从 `Vec<OutboundIR>` 改为 `Vec<RawOutboundIR>`
- outbound 子树 unknown fields 现在会被严格拒绝
- **`OutboundType` 仍保持 validated enum（lowercase serde + `ty_str()` 不变）**
- **`validate_reality()` 行为保持不变**
- **`planned.rs` / `normalize.rs` 仍然只是 skeleton**
- 新增 30 个 outbound boundary tests（raw.rs `#[test]` 从 104→134）

**验证**:
- `cargo fmt --all` ✅
- `cargo check -p sb-config` ✅
- `cargo check -p app --features parity` ✅
- `cargo test -p sb-config --lib ir` ✅ (261 passed)
- `cargo test -p sb-config` ✅ (386 passed, 0 failed)
- `cargo clippy -p sb-config --all-features --all-targets -- -D warnings` ✅

### WP-30h：Inbound nested Raw boundary pilot — 已完成（earlier）

### WP-30g / WP-30f / WP-30e / WP-30d / WP-30c / WP-30b / WP-30a — 已完成

- WP-30g：Service nested Raw boundary
- WP-30f：Endpoint nested Raw boundary
- WP-30e：Route nested Raw boundary
- WP-30d：DNS nested Raw boundary
- WP-30c：Root-owned leaf strictness
- WP-30b：`RawConfigRoot` root boundary
- WP-30a：`validated.rs` / `raw.rs` / `planned.rs` / `normalize.rs` skeleton

## 剩余 Maintenance 债务（非阻塞）

- `logging.rs` public compat 壳：为 Rust API 兼容保留
- `security_metrics.rs` public compat wrapper：已瘦身为单行委托
- `sb-metrics` LazyLock 指标静态：不继续做全量去全局化

## 后续战场（未启动）

- **WP-30 Phase 3 后续**：
  - 剩余零散 shared helper（`MasqueradeIR` 及子类型）仍未 Raw 化
  - 评估 `planned.rs` 前置卡，再决定是否推进 `RuntimePlan` builder
  - `normalize.rs` 接入 IR-level normalization
- validator/v2 mod.rs 进一步瘦身（仍 4630 行）
- bootstrap.rs / run_engine.rs 职责收口
