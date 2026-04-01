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

- **WP-30ab**: security warning owner 迁移 — 已完成
  - `validator/v2/security.rs` 现在是 non-localhost binding security warning 的实际 owner
  - `validate_v2()` 对 security warning 只做一行委托 `security::check_non_localhost_binding_warnings(doc)`
  - `check_non_localhost_binding_warnings()` + `is_localhost_addr()` 已迁入
  - mod.rs 从 1204 → 975 行（-229）
  - 这是 validator/v2 security warning owner 迁移卡，不是 RuntimePlan 卡
  - 7 个 security 子模块测试（5 域测试 + 2 pins），含 pins `wp30ab_pin_security_warning_owner_is_security_rs` + `wp30ab_pin_validate_v2_delegates_security_warnings`
- **WP-30aa**: deprecation detection owner 迁移 — 已完成（earlier）
- **WP-30z ~ WP-30q**: outbound/route/dns/service/endpoint/inbound/planned seam 系列 — 已完成（earlier）

### 构建基线（2026-03-17，L25 后）

| 构建 | 状态 |
|------|------|
| `cargo clippy --workspace --all-features --all-targets -- -D warnings` | ✅ pass |
| `cargo test -p sb-core --lib` | ✅ 509 passed |
| `cargo test -p sb-api` | ✅ pass |
| `cargo test -p sb-subscribe --all-features --lib` | ✅ 16 passed |
| `cargo test -p sb-adapters` | ✅ 144 non-ignored passed |
