<!-- tier: S -->
# 当前上下文（Active Context）

> **用途**：高频更新，每次任务结束时维护。**S-tier：每次会话必读。**
> **纪律**：仅保留当前阶段最关键事实。本文件严格 ≤100 行。

---

## 战略状态

**当前阶段**: 维护模式，L1-L25 全部 Closed
**Parity**: 92.9% (52/56)

## 最近完成（2026-03-27）

### WP-30d：DNS nested Raw boundary pilot — 已完成

- `crates/sb-config/src/ir/raw.rs` 新增 `RawDnsServerIR` / `RawDnsRuleIR` / `RawDnsHostIR` / `RawDnsIR`，全部 `#[serde(deny_unknown_fields)]`
- `crates/sb-config/src/ir/dns.rs`：`DnsServerIR` / `DnsRuleIR` / `DnsHostIR` / `DnsIR` 不再 `derive(Deserialize)`，改为手写 `impl Deserialize` 走 Raw bridge
- `RawConfigRoot.dns` 从 `Option<DnsIR>` 改为 `Option<RawDnsIR>`；`From<RawConfigRoot> for ConfigIR` 通过 `.map(Into::into)` 桥接 DNS raw → validated
- `crates/sb-config/src/ir/mod.rs` 新增 `pub use raw::{RawDnsHostIR, RawDnsIR, RawDnsRuleIR, RawDnsServerIR}`，`crate::ir::Dns*` 路径保持稳定
- 新增/扩充 DNS boundary tests：Raw unknown-field rejection ×4、validated bridge rejection ×4、合法 server/rule/host/top-level roundtrip、`ConfigIR` 合法 DNS subtree 解析、`ConfigIR` DNS nested unknown rejection
- **DNS nested unknown fields 现在会被严格拒绝**
- **`RouteIR/InboundIR/OutboundIR/EndpointIR/ServiceIR` 仍未进入 nested Raw**
- **`planned.rs` / `normalize.rs` 仍然只是 skeleton**

**验证**:
- `cargo fmt --all` ✅
- `cargo check -p sb-config` ✅
- `cargo check -p app --features parity` ✅
- `cargo test -p sb-config --lib ir` ✅ (155 passed)
- `cargo test -p sb-config` ✅ (280 unit + integration + doc-tests, 0 failed)
- `cargo clippy -p sb-config --all-features --all-targets -- -D warnings` ✅

### WP-30c / WP-30b / WP-30a — 已完成

- WP-30c：`RawLogIR` / `RawNtpIR` / `RawCertificateIR` root-owned leaf strictness 已完成
- WP-30b：`RawConfigRoot` root boundary 已完成，未知 top-level 字段严格拒绝
- WP-30a：`validated.rs` / `raw.rs` / `planned.rs` / `normalize.rs` skeleton 与 `ir/mod.rs` 第一轮拆分已完成

## 剩余 Maintenance 债务（非阻塞）

- `logging.rs` public compat 壳：为 Rust API 兼容保留
- `security_metrics.rs` public compat wrapper：已瘦身为单行委托
- `sb-metrics` LazyLock 指标静态：不继续做全量去全局化

## 后续战场（未启动）

- **WP-30 Phase 3 后续**：
  - 继续扩 nested Raw（`RawRoute` / `RawInbound` / `RawOutbound` / 其他未覆盖子树）
  - 评估 `planned.rs` 前置卡，再决定是否推进 `RuntimePlan` builder
  - `normalize.rs` 接入 IR-level normalization
- validator/v2 mod.rs 进一步瘦身（仍 4630 行）
- bootstrap.rs / run_engine.rs 职责收口
