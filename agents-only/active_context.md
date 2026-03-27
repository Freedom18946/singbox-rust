<!-- tier: S -->
# 当前上下文（Active Context）

> **用途**：高频更新，每次任务结束时维护。**S-tier：每次会话必读。**
> **纪律**：仅保留当前阶段最关键事实。本文件严格 ≤100 行。

---

## 战略状态

**当前阶段**: 维护模式，L1-L25 全部 Closed
**Parity**: 92.9% (52/56)

## 最近完成（2026-03-27）

### WP-30c：root-owned leaf Raw strictness — 已完成

- `raw.rs` 新增 `RawLogIR` / `RawNtpIR` / `RawCertificateIR`，全部 `#[serde(deny_unknown_fields)]`
- `validated.rs`：`LogIR` / `NtpIR` / `CertificateIR` 不再 `derive(Deserialize)`，各自手写 `impl Deserialize` 走 Raw bridge
- `RawConfigRoot` 的 `log` / `ntp` / `certificate` 字段改用 Raw leaf types
- `From<RawConfigRoot> for ConfigIR` 通过 `.map(Into::into)` 桥接 raw leaf → validated leaf
- `ir/mod.rs` 新增 `pub use raw::{RawCertificateIR, RawLogIR, RawNtpIR}`
- 13 个新增测试：Raw leaf unknown field rejection × 3、validated bridge rejection × 3、roundtrip × 3、ConfigIR nested leaf rejection × 3、experimental passthrough、non-leaf boundary doc
- **`ExperimentalIR` 刻意不动**——保持 forward-compatible passthrough，不加 `deny_unknown_fields`
- **`InboundIR/OutboundIR/RouteIR/DnsIR/EndpointIR/ServiceIR` 仍未进入 nested Raw**
- **`planned.rs` / `normalize.rs` 仍然只是 skeleton**

**验证**:
- `cargo fmt --all` ✅
- `cargo check -p sb-config` ✅
- `cargo check -p app --features parity` ✅
- `cargo test -p sb-config --lib ir` ✅ (144 passed, +13 vs WP-30b)
- `cargo test -p sb-config` ✅ (269 lib + integration + doc-tests, 0 failed)
- `cargo clippy -p sb-config --all-features --all-targets -- -D warnings` ✅

### WP-30b：RawConfigRoot root boundary — 已完成

- `RawConfigRoot` struct with `deny_unknown_fields`
- `ConfigIR` 反序列化走 `RawConfigRoot` bridge
- 8 个测试

### WP-30a skeleton — 已完成（2026-03-26）

- ir namespace 骨架：validated.rs / raw.rs / planned.rs / normalize.rs
- ir/mod.rs 六刀结构拆分 + validator/v2 第一轮子域拆分

## 剩余 Maintenance 债务（非阻塞）

- `logging.rs` public compat 壳：为 Rust API 兼容保留
- `security_metrics.rs` public compat wrapper：已瘦身为单行委托
- `sb-metrics` LazyLock 指标静态：不继续做全量去全局化

## 后续战场（未启动）

- **WP-30 Phase 3 后续**：
  - nested Raw types（RawInbound / RawOutbound / RawRoute / RawDns 等，配合各自 deny_unknown_fields）
  - `planned.rs` 定义 `RuntimePlan` builder
  - `normalize.rs` 接入 IR-level normalization
- validator/v2 mod.rs 进一步瘦身（仍 4630 行）
- bootstrap.rs / run_engine.rs 职责收口
