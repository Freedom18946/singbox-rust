<!-- tier: S -->
# 当前上下文（Active Context）

> **用途**：高频更新，每次任务结束时维护。**S-tier：每次会话必读。**
> **纪律**：仅保留当前阶段最关键事实。本文件严格 ≤100 行。

---

## 战略状态

**当前阶段**: 维护模式，L1-L25 全部 Closed
**Parity**: 92.9% (52/56)

## 最近完成（2026-03-26）

### WP-30a skeleton：ir phase-3 namespace 骨架 — 已完成

- 新增 `crates/sb-config/src/ir/validated.rs`（544 行）：承接 `ConfigIR`, `CertificateIR`, `LogIR`, `NtpIR`, `impl ConfigIR`（validate + has_any_negation + 全部 helper）+ 9 个迁移测试
- 新增 `crates/sb-config/src/ir/raw.rs`（22 行）：doc-first skeleton，未来承接 serde-facing Raw 层（deny_unknown_fields）
- 新增 `crates/sb-config/src/ir/planned.rs`（29 行）：doc-first skeleton，未来承接 RuntimePlan 层
- 新增 `crates/sb-config/src/ir/normalize.rs`（25 行）：doc-first skeleton，未来承接 IR normalize 入口（不影响现有 `src/normalize.rs`）
- **mod.rs 从 1104 行瘦身至 600 行**（-504 行）
- public API 通过 `pub use validated::{ConfigIR, CertificateIR, LogIR, NtpIR}` 保持稳定
- `ConfigIR::validate()` 及全部 helper 行为冻结
- serde 语义完全冻结
- **raw.rs / planned.rs / normalize.rs 当前只是 skeleton，不是完成态**
- **这张卡不是完整三相模型重构，下一步才是 Raw/Validated/Planned 实质接线**

**验证**:
- `cargo fmt --all` ✅
- `cargo check -p sb-config` ✅
- `cargo check -p app --features parity` ✅
- `cargo test -p sb-config --lib ir` ✅ (123 passed)
- `cargo test -p sb-config` ✅ (248 lib + 58 integration + 2 doc-tests)
- `cargo clippy -p sb-config --all-features --all-targets -- -D warnings` ✅

### ir/mod.rs 六刀结构拆分 — 已完成（earlier today）

- endpoint → service → dns → route → inbound → outbound 全部拆出
- mod.rs 从 3755→1104 行

### validator/v2 第一轮子域拆分 — 全部完成（earlier today）

- outbound + route + dns + service + endpoint 五个子域拆分

## 剩余 Maintenance 债务（非阻塞）

- `logging.rs` public compat 壳：为 Rust API 兼容保留
- `security_metrics.rs` public compat wrapper：已瘦身为单行委托
- `sb-metrics` LazyLock 指标静态：不继续做全量去全局化

## 后续战场（未启动）

- **WP-30 Phase 3 实质接线**：Raw → Validated → Planned 三相管道
  - `raw.rs` 需要定义 `RawConfigRoot` + `deny_unknown_fields`
  - `planned.rs` 需要定义 `RuntimePlan` builder
  - `normalize.rs` 需要接入 IR-level normalization
- validator/v2 mod.rs 进一步瘦身（仍 4630 行）
- bootstrap.rs / run_engine.rs 职责收口
