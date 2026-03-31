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

- **WP-30y**: route lowering owner 迁移 — 已完成
  - `validator/v2/route.rs` 现在是 route validation + lowering 的实际 owner
  - `to_ir_v1()` 对 route 只做一行委托 `route::lower_route(doc, &mut ir)`
  - route-only helper `parse_rule_entry()` 已迁入 `route.rs`，既有 `rule_set_format_from_path/url` 继续复用
  - 覆盖：geoip/geosite、rules/logical rules、rule_set lowering、default/final、resolver、mark、network strategy/fallback 等 route 专属 lowering
  - mod.rs 从 3391 → 3093 行（-298）
  - 这是 validator/v2 route lowering owner 迁移卡，不是 RuntimePlan 卡
  - 24 个 route 子模块测试（13 validation + 9 lowering + 2 pins），含 pins `wp30y_pin_route_lowering_owner_is_route_rs` + `wp30y_pin_mod_rs_to_ir_v1_delegates_route`
- **WP-30x**: DNS lowering owner 迁移 — 已完成
  - `validator/v2/dns.rs` 现在是 DNS validation + lowering 的实际 owner
  - `to_ir_v1()` 对 DNS 只做一行委托 `dns::lower_dns(doc, &mut ir)`
  - 1 个 DNS-only helper 迁入，1 个共享 helper 升级为 `pub(super)`
  - mod.rs 从 3864 → 3391 行（-473 行）
  - 这是 validator/v2 DNS lowering owner 迁移卡，不是 RuntimePlan 卡
  - 30 个测试（8 validation + 22 lowering），含 pins `wp30x_pin_dns_lowering_owner_is_dns_rs` + `wp30x_pin_mod_rs_to_ir_v1_delegates_dns`
- **WP-30w**: service lowering owner 迁移 — 已完成（earlier）
- **WP-30v**: endpoint lowering owner 迁移 — 已完成（earlier）
- **WP-30u**: inbound lowering owner 迁移 — 已完成（earlier）
- **WP-30t**: inbound validation owner 迁移 — 已完成（earlier）
- **WP-30s**: minimize seam owner 迁移 — 已完成（earlier）
- **WP-30r**: normalize seam owner 迁移 — 已完成（earlier）
- **WP-30q**: DNS server / service namespace uniqueness — 已完成（earlier）

### 构建基线（2026-03-17，L25 后）

| 构建 | 状态 |
|------|------|
| `cargo clippy --workspace --all-features --all-targets -- -D warnings` | ✅ pass |
| `cargo test -p sb-core --lib` | ✅ 509 passed |
| `cargo test -p sb-api` | ✅ pass |
| `cargo test -p sb-subscribe --all-features --lib` | ✅ 16 passed |
| `cargo test -p sb-adapters` | ✅ 144 non-ignored passed |
