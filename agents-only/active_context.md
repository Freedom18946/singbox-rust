<!-- tier: S -->
# 当前上下文（Active Context）

> **用途**：高频更新，每次任务结束时维护。**S-tier：每次会话必读。**
> **纪律**：仅保留当前阶段最关键事实。本文件严格 ≤100 行。

---

## 战略状态

**当前阶段**: 维护模式，L1-L25 全部 Closed
**Parity**: 92.9% (52/56)

## 最近完成（2026-03-28）

### WP-30h：Inbound nested Raw boundary pilot — 已完成

- `crates/sb-config/src/ir/raw.rs` 新增 12 个 Raw 类型，全部 `#[serde(deny_unknown_fields)]`：
  - `RawInboundIR`、`RawTunOptionsIR`
  - `RawShadowsocksUserIR`、`RawVmessUserIR`、`RawVlessUserIR`、`RawTrojanUserIR`
  - `RawShadowTlsUserIR`、`RawShadowTlsHandshakeIR`、`RawAnyTlsUserIR`
  - `RawHysteria2UserIR`、`RawTuicUserIR`、`RawHysteriaUserIR`
- 以下 validated 类型现在通过 Raw bridge 反序列化（不再 derive `Deserialize`）：
  - `InboundIR`、`TunOptionsIR`
  - `ShadowsocksUserIR`、`VmessUserIR`、`VlessUserIR`、`TrojanUserIR`
  - `ShadowTlsUserIR`、`ShadowTlsHandshakeIR`、`AnyTlsUserIR`
  - `Hysteria2UserIR`、`TuicUserIR`、`HysteriaUserIR`
- `RawConfigRoot.inbounds` 从 `Vec<InboundIR>` 改为 `Vec<RawInboundIR>`
- inbound 子树 unknown fields 现在会被严格拒绝
- **`InboundType` 仍保持 validated enum（lowercase serde 不变）**
- **`OutboundIR` 仍未进入 nested Raw**
- **`planned.rs` / `normalize.rs` 仍然只是 skeleton**
- 新增 28 个 inbound boundary tests（raw.rs `#[test]` 从 76→104）

**验证**:
- `cargo check -p sb-config` ✅
- `cargo check -p app --features parity` ✅
- `cargo test -p sb-config --lib ir` ✅ (231 passed)
- `cargo test -p sb-config` ✅ (356 passed, 0 failed)
- `cargo clippy -p sb-config --all-features --all-targets -- -D warnings` ✅
- `cargo fmt --all` ✅

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
  - 继续扩 nested Raw（`RawOutbound` / 其他未覆盖子树）
  - 评估 `planned.rs` 前置卡，再决定是否推进 `RuntimePlan` builder
  - `normalize.rs` 接入 IR-level normalization
- validator/v2 mod.rs 进一步瘦身（仍 4630 行）
- bootstrap.rs / run_engine.rs 职责收口
