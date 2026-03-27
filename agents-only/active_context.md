<!-- tier: S -->
# 当前上下文（Active Context）

> **用途**：高频更新，每次任务结束时维护。**S-tier：每次会话必读。**
> **纪律**：仅保留当前阶段最关键事实。本文件严格 ≤100 行。

---

## 战略状态

**当前阶段**: 维护模式，L1-L25 全部 Closed
**Parity**: 92.9% (52/56)

## 最近完成（2026-03-27）

### WP-30b：RawConfigRoot root boundary pilot — 已完成

- `crates/sb-config/src/ir/raw.rs`：从 22 行 skeleton 扩展为真实模块，新增 `RawConfigRoot` struct
  - `#[serde(deny_unknown_fields)]` 严格拒绝未知 top-level 字段
  - 字段集合与 `ConfigIR` 顶层严格对齐（inbounds/outbounds/route/log/ntp/certificate/dns/endpoints/services/experimental）
  - `impl From<RawConfigRoot> for ConfigIR` 提供 raw → validated 桥接
- `crates/sb-config/src/ir/validated.rs`：`ConfigIR` 不再 `derive(Deserialize)`，改为手写 `impl<'de> Deserialize<'de>` 走 `RawConfigRoot` bridge
- `crate::ir::RawConfigRoot` 通过 `pub use raw::RawConfigRoot` 暴露
- 8 个新增测试（raw.rs）：unknown field rejection（RawConfigRoot + ConfigIR）、minimal empty config、raw→ir conversion、valid root config parsing、experimental roundtrip、default semantics、validate() 行为、nested boundary doc test
- **nested child types 仍复用 validated IR（InboundIR/OutboundIR/RouteIR/DnsIR 等），这是有意为之**
- **planned.rs / normalize.rs 仍然只是 skeleton**
- **这张卡是 root-level strict boundary pilot，不是完整 Raw/Validated/Planned 重构**

**验证**:
- `cargo fmt --all` ✅
- `cargo check -p sb-config` ✅
- `cargo check -p app --features parity` ✅
- `cargo test -p sb-config --lib ir` ✅ (131 passed)
- `cargo test -p sb-config` ✅ (256 lib + integration + doc-tests, 0 failed)
- `cargo clippy -p sb-config --all-features --all-targets -- -D warnings` ✅

### WP-30a skeleton — 已完成（2026-03-26）

- ir namespace 骨架：validated.rs / raw.rs / planned.rs / normalize.rs
- mod.rs 从 1104 行瘦身至 600 行
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
