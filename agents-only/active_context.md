<!-- tier: S -->
# 当前上下文（Active Context）

> **用途**：高频更新，每次任务结束时维护。**S-tier：每次会话必读。**
> **纪律**：仅保留当前阶段最关键事实。本文件严格 ≤100 行。

---

## 战略状态

**当前阶段**: 维护模式，L1-L25 全部 Closed
**Parity**: 92.9% (52/56)

## 最近完成（2026-03-26）

### ir/mod.rs inbound IR 子模块拆分 — 已完成

- 新增 `crates/sb-config/src/ir/inbound.rs`（1145 行）：`InboundType`, `InboundIR`, `TunOptionsIR` + 10 个 inbound user struct + 22 个迁移测试
- **mod.rs 从 2440 行瘦身至 1905 行**（-535 行）
- public API 通过 `pub use inbound::{InboundType, InboundIR, TunOptionsIR, ShadowsocksUserIR, VmessUserIR, VlessUserIR, TrojanUserIR, ShadowTlsUserIR, ShadowTlsHandshakeIR, AnyTlsUserIR, Hysteria2UserIR, TuicUserIR, HysteriaUserIR}` 保持稳定
- serde 语义完全冻结（字段名、rename、default、`default = "default_true"`、类型全部不变）
- `InboundType::ty_str()` 行为不变
- 共享类型（`Credentials`, `MultiplexOptionsIR`, `BrutalIR`, `MasqueradeIR`）仍留在 `mod.rs`，因为同时服务 inbound/outbound
- **注意**：这是 `ir/mod.rs` 结构拆分的第五刀（endpoint → service → dns → route → inbound）。更大的 raw/validated/planned/normalize 三相边界治理仍未启动，是后续战场。下一步可考虑拆 `OutboundIR`，但 outbound 贴着更复杂的协议字段和 `validate_reality()` 行为，风险更高。

**验证**:
- `cargo fmt --all` ✅
- `cargo check -p sb-config` ✅
- `cargo check -p app --features parity` ✅
- `cargo test -p sb-config --lib ir` ✅ (104 passed)
- `cargo test -p sb-config` ✅ (229 lib + 58 integration + 2 doc-tests)
- `cargo clippy -p sb-config --all-features --all-targets -- -D warnings` ✅

### ir/mod.rs endpoint + service + dns + route IR 子模块拆分 — 已完成（earlier）

- `ir/endpoint.rs`（174 行）+ `ir/service.rs`（322 行）+ `ir/dns.rs`（615 行）+ `ir/route.rs`（1087 行）
- mod.rs 从 3755→2440 行

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
