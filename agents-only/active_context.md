<!-- tier: S -->
# 当前上下文（Active Context）

> **用途**：高频更新，每次任务结束时维护。**S-tier：每次会话必读。**
> **纪律**：仅保留当前阶段最关键事实。本文件严格 ≤100 行。

---

## 战略状态

**当前阶段**: 维护模式，L1-L25 全部 Closed
**Parity**: 92.9% (52/56)

## 最近完成（2026-03-26）

### ir/mod.rs endpoint + service IR 子模块拆分 — 已完成

- 新增 `crates/sb-config/src/ir/endpoint.rs`（174 行）：`EndpointType`, `EndpointIR`, `WireGuardPeerIR` + 3 个迁移测试
- 新增 `crates/sb-config/src/ir/service.rs`（322 行）：`ServiceType`, `ServiceIR` + 7 个迁移测试
- **mod.rs 从 3755 行瘦身至 3283 行**（-472 行）
- 服务相关共享类型（`InboundTlsOptionsIR`, `DerpStunOptionsIR`, `Listable`, `StringOrObj`, `DerpVerifyClientUrlIR`, `DerpMeshPeerIR` 等）仍留在 `mod.rs`，子模块通过 `super::` 引用
- public API 通过 `pub use` 保持稳定：`sb_config::ir::EndpointIR` / `EndpointType` / `WireGuardPeerIR` / `ServiceIR` / `ServiceType`
- serde 语义完全冻结，roundtrip 不变
- **注意**：这是 `ir/mod.rs` 的第一刀结构拆分。`dns` IR 和更大的 raw/validated/planned/normalize 三相设计仍未动。

**验证**:
- `cargo fmt --all` ✅
- `cargo check -p sb-config` ✅
- `cargo check -p app --features parity` ✅
- `cargo test -p sb-config --lib ir` ✅ (42 passed)
- `cargo test -p sb-config` ✅ (167 lib + 58 integration + 2 doc-tests)
- `cargo clippy -p sb-config --all-features --all-targets -- -D warnings` ✅
- `bash scripts/ci/tasks/inbound-errors.sh` ✅

### validator/v2 第一轮子域拆分 — 全部完成

- outbound（610 行）+ route（362 行）+ dns（221 行）+ service + endpoint（195 行）五个子域拆分
- mod.rs 从 5384 行瘦身至 4630 行
- 语义冻结，所有验证通过

### outbound/ssh.rs / anytls.rs / http_server / prefetch / geoip / http_client — 已完成

- 详见本文件历史快照

## Compat 债务评估结论

| 项目 | 残留 | 决策 |
|------|------|------|
| http_client | weak-owner only，hard global 已删 | **完成** |
| geoip | weak-owner only，hard global 已删 | **完成** |
| prefetch | weak-owner only，hard global 已删，worker lifecycle tracked | **完成** |
| http_server | accept/conn lifecycle tracked，runtime shutdown 已接入 | **完成** |
| logging compat | `ACTIVE_RUNTIME` 薄壳 | **保留** — public API |
| security_metrics compat | public wrapper + legacy boundary | **保留** — public API |
| sb-metrics LazyLock | registry plumbing 已收口 | **部分完成** |

## 剩余 Maintenance 债务（非阻塞）

- ~~`http_client` hard global~~ → **已收口**
- ~~`geoip` hard global~~ → **已收口**
- ~~`prefetch` hard global + lifecycle~~ → **已收口**
- ~~`http_server` accept loop 裸 spawn~~ → **已收口**
- `logging.rs` public compat 壳：为 Rust API 兼容保留
- `security_metrics.rs` public compat wrapper：已瘦身为单行委托
- `sb-metrics` LazyLock 指标静态：不继续做全量去全局化
- ~~`outbound/anytls.rs`~~ → **已收口**
- ~~`outbound/ssh.rs`~~ → **已收口**
