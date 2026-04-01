<!-- tier: S -->
# 当前上下文（Active Context）

> **用途**：高频更新，每次任务结束时维护。**S-tier：每次会话必读。**
> **纪律**：仅保留当前阶段最关键事实。本文件严格 ≤100 行。

---

## 战略状态

**当前阶段**: 维护模式，L1-L25 全部 Closed
**Parity**: 92.9% (52/56)

## 最近完成（2026-04-01）

### WP-30ai：ir/multiplex.rs multiplex/brutal owner 收口 — 已完成

- 新增 `crates/sb-config/src/ir/multiplex.rs`，现在收纳 `MultiplexOptionsIR` / `BrutalIR` 的实际 owner 与 `Deserialize` impl
- `crates/sb-config/src/ir/mod.rs` 删除上述实现，改为 `mod multiplex;` + `pub use multiplex::{BrutalIR, MultiplexOptionsIR};` 薄壳兼容面；public type path 继续保持 `crate::ir::*`
- `crates/sb-config/src/ir/inbound.rs` / `outbound.rs` / `raw.rs` 的引用与 owner 注释已显式对齐 `super::multiplex::{...}`；raw bridge 语义不变
- `ir/mod.rs` 从 321 → 252 行（-69）；新增 `ir/multiplex.rs` 199 行；`Credentials` / `Listable<T>` / `StringOrObj<T>` 仍留在 `ir/mod.rs` 作为更宽的跨域共享类型；**这张卡不是 generic shared.rs 卡**
- 新增 6 个 multiplex 定点测试（2 raw-bridge/roundtrip + 2 inbound/outbound 行为 + 2 owner pins）；既有 raw/integration multiplex 定点测试继续保留并通过
- 不改 `validator/v2` facade / pass 语义；不改 `planned.rs` / `PlannedFacts`；不引入 `RuntimePlan` / query API
- 全量自验证：`cargo test -p sb-config --lib ir::multiplex` ✅ 6 passed；`cargo test -p sb-config --lib multiplex` ✅ 10 passed；`cargo test -p sb-config --test outbound_raw_boundary_test multiplex` ✅ 2 passed；`cargo test -p sb-config --lib` ✅ 649 passed；`cargo clippy -p sb-config --all-features --all-targets -- -D warnings` ✅ pass
- **这是 ir/multiplex.rs owner 收口卡，不是 RuntimePlan 卡**

### WP-30ah：ir/inbound.rs masquerade owner 收口 — 已完成

- `crates/sb-config/src/ir/inbound.rs` 现在收纳 `MasqueradeIR`、`MasqueradeFileIR`、`MasqueradeProxyIR`、`MasqueradeStringIR` 的实际 owner，与 Hysteria2 inbound 字段局部性对齐
- `crates/sb-config/src/ir/mod.rs` 删除上述实现，改为 `pub use inbound::{...}` 薄壳兼容面；public type path 继续保持 `crate::ir::*`
- `crates/sb-config/src/ir/raw.rs` 继续作为 masquerade strict Raw bridge owner，但类型引用现在显式指向 `super::inbound::{...}`；raw bridge 语义不变
- `ir/mod.rs` 从 406 → 321 行（-85）；`MultiplexOptionsIR` / `BrutalIR` / `Credentials` / `Listable<T>` / `StringOrObj<T>` 仍留在 `ir/mod.rs` 作为跨域共享类型；**这张卡不是 generic shared.rs 卡**
- 新增 8 个 inbound/masquerade 定点测试（5 个行为/默认值 + 1 个 ConfigIR 正向 bridge + 2 个 owner pins）；raw bridge 负向定点测试继续保留并通过
- 不改 `validator/v2` facade / pass 语义；不改 `planned.rs` / `PlannedFacts`；不引入 `RuntimePlan` / query API
- 全量自验证：`cargo test -p sb-config --lib ir::inbound` ✅ 29 passed；`cargo test -p sb-config --lib` ✅ 643 passed；`cargo clippy -p sb-config --all-features --all-targets -- -D warnings` ✅ pass
- **这是 ir/inbound.rs masquerade owner 收口卡，不是 RuntimePlan 卡**

### WP-30ag：ir/service.rs service/DERP owner 收口 — 已完成

- `crates/sb-config/src/ir/service.rs` 现在收纳 `InboundTlsOptionsIR`、`DerpStunOptionsIR`、`DerpDomainResolverIR`、`DerpDialOptionsIR`、`DerpVerifyClientUrlIR`、`DerpOutboundTlsOptionsIR`、`DerpMeshPeerIR` 的实际 owner
- `crates/sb-config/src/ir/mod.rs` 删除上述实现，改为 `pub use service::{...}` 薄壳兼容面；public type path 继续保持 `crate::ir::*`
- `ir/mod.rs` 从 703 → 406 行（-297）；`ir/service.rs` 从 331 → 694 行（+363，含 owner pins / shorthand tests）
- `Listable<T>` / `StringOrObj<T>` / `Credentials` 仍留在 `ir/mod.rs` 作为跨域共享类型；**这张卡不是 generic shared.rs 卡**
- `validator/v2` service pass/facade 语义不变；`planned.rs` / `PlannedFacts` 不变；不引入 `RuntimePlan` / query API
- 新增 4 个 service 定点测试（2 shorthand + 2 pins），连同既有 service 行为测试共 10 个通过
- 补跑 raw bridge 定点测试：`inbound_tls_options_rejects_unknown_via_raw_bridge`、`raw_derp_verify_client_url_inlines_dial_fields`、`raw_derp_mesh_peer_from_string_host_port`
- 全量自验证：`cargo test -p sb-config --lib` ✅ 641 passed；`cargo clippy -p sb-config --all-features --all-targets -- -D warnings` ✅ pass
- **这是 ir/service.rs owner 收口卡，不是 RuntimePlan 卡**

### WP-30af：validator/v2 facade owner 迁移 — 已完成

- 新增 `crates/sb-config/src/validator/v2/facade.rs`，现在收纳 `validate_v2()` / `to_ir_v1()` / `pack_output()` 的实际 owner
- `validator/v2/mod.rs` 新增 `mod facade;`，对外 API 改成 thin delegate，继续保留 shared helper 与 `pub use outbound::check_tls_capabilities;`
- `validate_v2()` 现在继续只做 facade 装配：root schema + inbound/outbound/route/dns/service/endpoint validation + deprecation + security + TLS capability
- `to_ir_v1()` 现在继续只做 facade 装配：inbound/outbound/endpoint/route/top_level/dns/service lowering + credentials normalization
- `pack_output()` 继续只是 facade 层输出打包；外部 API 签名与行为不变
- `validator/v2/mod.rs` 从 742 → 260 行（-482），shared helper 仍留在 mod.rs；`facade.rs` 759 行（含测试）
- 17 个 facade 定点测试（功能 + pins）：
  - `validate_v2_assembles_validation_facade_passes`
  - `to_ir_v1_assembles_lowering_facade_and_credentials_normalization`
  - `pack_output_preserves_output_shape`
  - `wp30af_pin_facade_owner_is_facade_rs`
  - `wp30af_pin_mod_rs_facade_api_is_delegate_only`
- 兼容更新旧 pins：`credentials.rs` / `outbound.rs` / `route.rs` 的 source pin 现改为接受 “mod.rs -> facade.rs -> owner module” 的新委托链
- **这是 validator/v2 facade owner 迁移卡，不是 RuntimePlan 卡**
- 不改 inbound/outbound/endpoint/service/dns/route/top_level/deprecation/security/schema_core/credentials owner
- 不改 shared helper 语义
- 不引入 planning / RuntimePlan / query API

### WP-30ae：root schema core owner 迁移 — 已完成（earlier）
- `crates/sb-config/src/validator/v2/schema_core.rs` 现在是 root schema validation 的实际 owner，收纳 `validate_root_schema()` 入口、schema load + fallback、`schema_version` 检查与 root unknown field 检查（含 `$schema` 例外）
- `validator/v2/mod.rs` 中 `validate_v2()` 对 root schema validation 只做一行委托：`schema_core::validate_root_schema(doc, allow_unknown, &mut issues)`
- mod.rs 从 793 → 742 行（-51），schema_core.rs 263 行（含测试）
- **这是 validator/v2 root schema core owner 迁移卡，不是 RuntimePlan 卡**
- 不改 inbound/outbound/endpoint/service/dns/route/top_level validation/lowering owner；不改 deprecation / security / TLS capability / credentials pass owner；不改 `to_ir_v1()` / lowering 语义；不引入 planning / RuntimePlan / query API
- 9 个测试（7 功能 + 2 pins），包括 `wp30ae_pin_schema_core_owner_is_schema_core_rs` 与 `wp30ae_pin_validate_v2_delegates_root_schema`

### WP-30ad：credential normalization owner 迁移 — 已完成（earlier）
### WP-30ac ~ WP-30k：top-level/security/deprecation/outbound/route/dns/service/endpoint/inbound/planned seam 系列 — 已完成（earlier）

## 剩余 Maintenance 债务（非阻塞）

- `logging.rs` public compat 壳：为 Rust API 兼容保留
- `security_metrics.rs` public compat wrapper：已瘦身为单行委托
- `sb-metrics` LazyLock 指标静态：不继续做全量去全局化

## 后续战场（未启动）

- **WP-30 Phase 3 后续**：
  - validator/v2 facade seam 已收口；`mod.rs` 现 260 行，主剩余是 shared helper + TLS capability re-export
  - `ir/service.rs` / `ir/inbound.rs` / `ir/multiplex.rs` owner 已收口；`ir/mod.rs` 现 252 行，主剩余是 `Credentials` / `Listable<T>` / `StringOrObj<T>` + experimental / compat 暴露，而不是 service/DERP / masquerade / multiplex owner
  - 若继续细拆，应明确是 helper seam / compat seam 卡，而不是再把 facade 迁移误写成 RuntimePlan 卡
  - `PlannedFacts` 暴露 namespace 查询方法供 crate 内其他模块使用
  - 将 `PlannedFacts` 升级为 public `RuntimePlan`（需要先有稳定外部消费者）
  - 仍不是 `RuntimePlan` public 实作卡，也不是 crate-internal query API 卡
- bootstrap.rs / run_engine.rs 职责收口
