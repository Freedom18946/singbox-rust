<!-- tier: S -->
# 当前上下文（Active Context）

> **用途**：高频更新，每次任务结束时维护。**S-tier：每次会话必读。**
> **纪律**：仅保留当前阶段最关键事实。本文件严格 ≤100 行。

---

## 战略状态

**当前阶段**: 维护模式，L1-L25 全部 Closed
**Parity**: 92.9% (52/56)

## 最近完成（2026-03-28）

### WP-30f：Endpoint nested Raw boundary pilot — 已完成

- `crates/sb-config/src/ir/raw.rs` 新增 `RawWireGuardPeerIR` / `RawEndpointIR`，全部 `#[serde(deny_unknown_fields)]`
- `crates/sb-config/src/ir/endpoint.rs`：`EndpointIR` / `WireGuardPeerIR` 不再 `derive(Deserialize)`，改为手写 `impl Deserialize` 走 Raw bridge
- `RawConfigRoot.endpoints` 从 `Vec<EndpointIR>` 改为 `Vec<RawEndpointIR>`；`From<RawConfigRoot> for ConfigIR` 通过 `.into_iter().map(Into::into).collect()` 桥接 endpoint raw → validated
- `crates/sb-config/src/ir/mod.rs` 新增 `pub use raw::{RawEndpointIR, RawWireGuardPeerIR}`，`crate::ir::Endpoint*` / `WireGuardPeerIR` 路径保持稳定
- 新增 13 个 endpoint boundary tests：Raw unknown-field rejection ×2、validated bridge rejection ×2、合法 roundtrip ×3（WireGuardPeer / WireGuard endpoint / Tailscale endpoint）、EndpointType lowercase serde 验证、ConfigIR endpoint subtree 解析、ConfigIR endpoint nested unknown rejection ×2（endpoint 级 + peer 级）、boundary doc 更新
- **Endpoint nested unknown fields 现在会被严格拒绝**
- **`EndpointType` 仍保持现有 validated enum 形态（lowercase serde 不变）**
- **`InboundIR/OutboundIR/ServiceIR` 仍未进入 nested Raw**
- **`planned.ps` / `normalize.rs` 仍然只是 skeleton**

**验证**:
- `cargo fmt --all` ✅
- `cargo check -p sb-config` ✅
- `cargo check -p app --features parity` ✅
- `cargo test -p sb-config --lib ir` ✅ (182 passed)
- `cargo test -p sb-config` ✅ (all unit + integration + doc-tests, 0 failed)
- `cargo clippy -p sb-config --all-features --all-targets -- -D warnings` ✅

### WP-30e / WP-30d / WP-30c / WP-30b / WP-30a — 已完成

- WP-30e：Route nested Raw boundary pilot（`RawRuleIR` / `RawDomainResolveOptionsIR` / `RawRuleSetIR` / `RawRouteIR`）
- WP-30d：DNS nested Raw boundary pilot（`RawDnsServerIR` / `RawDnsRuleIR` / `RawDnsHostIR` / `RawDnsIR`）
- WP-30c：`RawLogIR` / `RawNtpIR` / `RawCertificateIR` root-owned leaf strictness
- WP-30b：`RawConfigRoot` root boundary，未知 top-level 字段严格拒绝
- WP-30a：`validated.rs` / `raw.rs` / `planned.rs` / `normalize.rs` skeleton 与 `ir/mod.rs` 第一轮拆分

## 剩余 Maintenance 债务（非阻塞）

- `logging.rs` public compat 壳：为 Rust API 兼容保留
- `security_metrics.rs` public compat wrapper：已瘦身为单行委托
- `sb-metrics` LazyLock 指标静态：不继续做全量去全局化

## 后续战场（未启动）

- **WP-30 Phase 3 后续**：
  - 继续扩 nested Raw（`RawInbound` / `RawOutbound` / `RawService` / 其他未覆盖子树）
  - 评估 `planned.rs` 前置卡，再决定是否推进 `RuntimePlan` builder
  - `normalize.rs` 接入 IR-level normalization
- validator/v2 mod.rs 进一步瘦身（仍 4630 行）
- bootstrap.rs / run_engine.rs 职责收口
