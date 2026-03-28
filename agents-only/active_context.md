<!-- tier: S -->
# 当前上下文（Active Context）

> **用途**：高频更新，每次任务结束时维护。**S-tier：每次会话必读。**
> **纪律**：仅保留当前阶段最关键事实。本文件严格 ≤100 行。

---

## 战略状态

**当前阶段**: 维护模式，L1-L25 全部 Closed
**Parity**: 92.9% (52/56)

## 最近完成（2026-03-28）

### WP-30j：Masquerade shared helper Raw closure — 已完成

- `crates/sb-config/src/ir/raw.rs` 新增 4 个 Raw 类型，全部 `#[serde(deny_unknown_fields)]`：
  - `RawMasqueradeIR`、`RawMasqueradeFileIR`、`RawMasqueradeProxyIR`、`RawMasqueradeStringIR`
- 以下 validated 类型现在通过 Raw bridge 反序列化（不再 derive `Deserialize`）：
  - `MasqueradeIR`、`MasqueradeFileIR`、`MasqueradeProxyIR`、`MasqueradeStringIR`（在 `mod.rs`）
- `RawInboundIR.masquerade` 从 `Option<MasqueradeIR>` 改为 `Option<RawMasqueradeIR>`
- inbound/Hysteria2 masquerade 子树 unknown fields 现在会被严格拒绝
- `MasqueradeProxyIR.rewrite_host` 默认值语义（false）保持不变
- `MasqueradeStringIR.status_code` 默认值语义（0）保持不变
- **`planned.rs` / `normalize.rs` 仍然只是 skeleton**
- **这是 WP-30 输入边界小收尾，不是 `planned.rs` 推进**
- 新增 16 个 masquerade boundary tests（raw.rs `#[test]` 从 134→150）

**验证**:
- `cargo fmt --all` ✅
- `cargo check -p sb-config` ✅
- `cargo check -p app --features parity` ✅
- `cargo test -p sb-config --lib ir` ✅ (277 passed)
- `cargo test -p sb-config` ✅ (402 passed, 0 failed)
- `cargo clippy -p sb-config --all-features --all-targets -- -D warnings` ✅

### WP-30i：Outbound nested Raw boundary pilot — 已完成（earlier）

### WP-30h ~ WP-30a — 已完成（earlier）

## 剩余 Maintenance 债务（非阻塞）

- `logging.rs` public compat 壳：为 Rust API 兼容保留
- `security_metrics.rs` public compat wrapper：已瘦身为单行委托
- `sb-metrics` LazyLock 指标静态：不继续做全量去全局化

## 后续战场（未启动）

- **WP-30 Phase 3 后续**：
  - 所有 config-facing strict input boundary 已 Raw 化（WP-30a ~ WP-30j）
  - 评估 `planned.rs` 前置卡，再决定是否推进 `RuntimePlan` builder
  - `normalize.rs` 接入 IR-level normalization
- validator/v2 mod.rs 进一步瘦身（仍 4630 行）
- bootstrap.rs / run_engine.rs 职责收口
