<!-- tier: S -->
# 当前上下文（Active Context）

> **用途**：高频更新，每次任务结束时维护。**S-tier：每次会话必读。**
> **纪律**：仅保留当前阶段最关键事实。本文件严格 ≤100 行。

---

## 战略状态

**当前阶段**: 维护模式，L1-L25 全部 Closed
**Parity**: 92.9% (52/56)

## 最近完成（2026-04-01）

### WP-30ad：credential normalization owner 迁移 — 已完成

- `crates/sb-config/src/validator/v2/credentials.rs` 现在是 credential ENV normalization 的实际 owner
  - `resolve_cred(c)` private helper + `normalize_credentials(ir)` pub(super) 入口
  - 处理 outbound `credentials` + inbound `basic_auth` 的 `username_env` / `password_env` 解析写回
- `validator/v2/mod.rs` 中 `to_ir_v1()` 对 credential normalization 只做一行委托：`credentials::normalize_credentials(&mut ir)`
- mod.rs 从 819 → 793 行（-26），credentials.rs 238 行（含测试）
- **这是 validator/v2 credential normalization owner 迁移卡，不是 RuntimePlan 卡**
- 不改 inbound/outbound/endpoint/service/dns/route/top_level validation/lowering owner
- 不改 deprecation / security / TLS capability pass owner
- 不改 ENV 优先级语义：仍是 `username_env/password_env` 命中时写回明文字段
- 不引入 planning / RuntimePlan / query API
- 10 个测试（8 功能 + 2 pins）：
  - `wp30ad_pin_credential_normalization_owner_is_credentials_rs` — credential normalization owner 在 credentials.rs
  - `wp30ad_pin_to_ir_v1_delegates_credential_normalization` — to_ir_v1() 对 credential normalization 只做委托

### WP-30ac：top-level lowering owner 迁移 — 已完成（earlier）
### WP-30ab ~ WP-30k：security/deprecation/outbound/route/dns/service/endpoint/inbound/planned seam 系列 — 已完成（earlier）

## 剩余 Maintenance 债务（非阻塞）

- `logging.rs` public compat 壳：为 Rust API 兼容保留
- `security_metrics.rs` public compat wrapper：已瘦身为单行委托
- `sb-metrics` LazyLock 指标静态：不继续做全量去全局化

## 后续战场（未启动）

- **WP-30 Phase 3 后续**：
  - validator/v2 mod.rs 进一步瘦身（793 行，deprecation + security + credentials + inbound + outbound + endpoint + service + dns + route + top-level 已拆出）
  - 剩余 mod.rs 内容：TLS capability matrix pass、schema validation core、`to_ir_v1()` 入口 + 通用 shared helper
  - `PlannedFacts` 暴露 namespace 查询方法供 crate 内其他模块使用
  - 将 `PlannedFacts` 升级为 public `RuntimePlan`（需要先有稳定外部消费者）
  - 仍不是 `RuntimePlan` public 实作卡，也不是 crate-internal query API 卡
- bootstrap.rs / run_engine.rs 职责收口
