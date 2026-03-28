<!-- tier: S -->
# 当前上下文（Active Context）

> **用途**：高频更新，每次任务结束时维护。**S-tier：每次会话必读。**
> **纪律**：仅保留当前阶段最关键事实。本文件严格 ≤100 行。

---

## 战略状态

**当前阶段**: 维护模式，L1-L25 全部 Closed
**Parity**: 92.9% (52/56)

## 最近完成（2026-03-28）

### WP-30e：Route nested Raw boundary pilot — 已完成

- `crates/sb-config/src/ir/raw.rs` 新增 `RawRuleIR` / `RawDomainResolveOptionsIR` / `RawRuleSetIR` / `RawRouteIR`，全部 `#[serde(deny_unknown_fields)]`
- `crates/sb-config/src/ir/route.rs`：`RuleIR` / `DomainResolveOptionsIR` / `RuleSetIR` / `RouteIR` 不再 `derive(Deserialize)`，改为手写 `impl Deserialize` 走 Raw bridge
- `RawConfigRoot.route` 从 `RouteIR` 改为 `RawRouteIR`；`From<RawConfigRoot> for ConfigIR` 通过 `.into()` 桥接 route raw → validated
- `crates/sb-config/src/ir/mod.rs` 新增 `pub use raw::{RawDomainResolveOptionsIR, RawRouteIR, RawRuleIR, RawRuleSetIR}`，`crate::ir::Route*` / `Rule*` 路径保持稳定
- 新增 16 个 route boundary tests：Raw unknown-field rejection ×4、validated bridge rejection ×4、合法 roundtrip ×4、RuleAction 行为验证、ConfigIR route subtree 解析、ConfigIR route nested unknown rejection ×2
- **Route nested unknown fields 现在会被严格拒绝**
- **`RuleAction` 仍保持现有 validated enum 形态（kebab-case serde / `as_str()` / `from_str_opt()` 不变）**
- **`InboundIR/OutboundIR/EndpointIR/ServiceIR` 仍未进入 nested Raw**
- **`planned.rs` / `normalize.rs` 仍然只是 skeleton**

**验证**:
- `cargo fmt --all` ✅
- `cargo check -p sb-config` ✅
- `cargo check -p app --features parity` ✅
- `cargo test -p sb-config --lib ir` ✅ (171 passed)
- `cargo test -p sb-config` ✅ (296 unit + integration + doc-tests, 0 failed)
- `cargo clippy -p sb-config --all-features --all-targets -- -D warnings` ✅

### WP-30d / WP-30c / WP-30b / WP-30a — 已完成

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
  - 继续扩 nested Raw（`RawInbound` / `RawOutbound` / 其他未覆盖子树）
  - 评估 `planned.rs` 前置卡，再决定是否推进 `RuntimePlan` builder
  - `normalize.rs` 接入 IR-level normalization
- validator/v2 mod.rs 进一步瘦身（仍 4630 行）
- bootstrap.rs / run_engine.rs 职责收口
