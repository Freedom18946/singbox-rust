<!-- tier: S -->
# 工作阶段总览（Workpackage Map）

> **用途**：阶段划分 + 当前位置。S-tier，每次会话必读。
> **纪律**：Phase 关闭后压缩为一行状态。本文件严格 ≤120 行。
> **对比**：本文件管"在哪"；`active_context.md` 管"刚做了什么 / 下一步"。

---

## 已关闭阶段（一行总结）

| 阶段 | 交付 | 关闭时间 |
|------|------|----------|
| L1-L17 | 架构整固、功能对齐、CI / 发布收口 | 2026-01 ~ 2026-02 |
| MIG-02 / L21 | 隐式回退消除，541 V7 assertions，生产路径零隐式直连回退 | 2026-03-07 |
| L18 Phase 1-4 | 认证替换、证据模型收口、GUI gate 复验、长跑恢复决策门 | 2026-03-11 |
| L22 | dual-kernel parity 52/60 (86.7%)，16 个 both-case，Sniff Phase A+B | 2026-03-15 |
| 后 L22 补丁 | QUIC 多包重组、OverrideDestination、UDP datagram sniff、编译修复 | 2026-03-15 |
| L23 | TUN/Sniff 运行时补全、Provider wiring、T4 Protocol Suite、parity 92.9% | 2026-03-16 |
| L24 | 性能/安全/质量/功能补全，30 任务 (B1-B4)，综合验收 39/41 PASS | 2026-03-17 |
| L25 | 生产加固 + 跨平台补全 + 文档完善，10/10 任务，4 批次全部交付 | 2026-03-17 |

---

## 当前状态：维护模式（L1-L25 全部 Closed）

**全部阶段关闭**。项目进入稳定维护。

### 维护卡（2026-04-01）

- **WP-30ah**: `ir/inbound.rs` masquerade owner 收口 — 已完成
  - `MasqueradeIR` + 3 个 leaf 类型迁入 `ir/inbound.rs`；`ir/mod.rs` 改为 `pub use inbound::{...}` 薄壳
  - `ir/mod.rs` 从 406 → 321 行（-85）；`raw.rs` 继续持有 strict Raw bridge，语义不变
  - `MultiplexOptionsIR` / `BrutalIR` / `Credentials` / `Listable<T>` / `StringOrObj<T>` 仍留在 `ir/mod.rs` 作为跨域共享类型
  - 这是 `ir/inbound.rs` owner 收口卡，不是 RuntimePlan 卡
  - 自验证：inbound/masquerade 定点测试 + raw bridge 定点测试 + `cargo test -p sb-config --lib ir::inbound` + `cargo test -p sb-config --lib` + `cargo clippy -p sb-config --all-features --all-targets -- -D warnings`
- **WP-30ag**: `ir/service.rs` service/DERP owner 收口 — 已完成
  - `InboundTlsOptionsIR` + 6 个 `Derp*` 类型迁入 `ir/service.rs`；`ir/mod.rs` 改为 `pub use service::{...}` 薄壳
  - `ir/mod.rs` 从 703 → 406 行（-297），`ir/service.rs` 从 331 → 694 行（含测试）
  - `Listable<T>` / `StringOrObj<T>` / `Credentials` 仍留在 `ir/mod.rs` 作为跨域共享类型
  - 这是 `ir/service.rs` owner 收口卡，不是 RuntimePlan 卡
  - 自验证：service/DERP 定点测试 + raw bridge 定点测试 + `cargo test -p sb-config --lib` + `cargo clippy -p sb-config --all-features --all-targets -- -D warnings`
- **WP-30af**: validator/v2 facade owner 迁移 — 已完成
  - 新增 `validator/v2/facade.rs`，收纳 `validate_v2()` / `to_ir_v1()` / `pack_output()` 实际 owner
  - `validator/v2/mod.rs` 改成 thin delegate + shared helper + TLS re-export
  - mod.rs 从 742 → 260 行（-482），`facade.rs` 759 行（含测试）
  - 这是 validator/v2 facade owner 迁移卡，不是 RuntimePlan 卡
  - 17 个 facade 定点测试（含 2 个 facade pins）
- **WP-30ae**: root schema core owner 迁移 — 已完成
  - `validator/v2/schema_core.rs` 现在是 root schema validation 的实际 owner
  - `validate_v2()` 对 root schema validation 只做一行委托 `schema_core::validate_root_schema()`
  - mod.rs 从 793 → 742 行（-51）
  - 这是 validator/v2 root schema core owner 迁移卡，不是 RuntimePlan 卡
  - 9 个测试（7 功能 + 2 pins）
- **WP-30ad**: credential normalization owner 迁移 — 已完成（earlier）
- **WP-30ac**: top-level lowering owner 迁移 — 已完成（earlier）
- **WP-30ab**: security warning owner 迁移 — 已完成（earlier）
- **WP-30aa**: deprecation detection owner 迁移 — 已完成（earlier）
- **WP-30z ~ WP-30q**: outbound/route/dns/service/endpoint/inbound/planned seam 系列 — 已完成（earlier）

### 构建基线（2026-04-01，WP-30ah 后）

| 构建 | 状态 |
|------|------|
| `cargo clippy -p sb-config --all-features --all-targets -- -D warnings` | ✅ pass |
| `cargo test -p sb-config --lib` | ✅ 643 passed |
