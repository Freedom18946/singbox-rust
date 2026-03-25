<!-- tier: S -->
# 当前上下文（Active Context）

> **用途**：高频更新，每次任务结束时维护。**S-tier：每次会话必读。**
> **纪律**：仅保留当前阶段最关键事实。本文件严格 ≤100 行。

---

## 战略状态

**当前阶段**: 维护模式，L1-L25 全部 Closed
**Parity**: 92.9% (52/56)

## 最近完成（2026-03-25）

### geoip hard global fallback 收口 — 已完成

- `crates/sb-core/src/geoip/mod.rs`:
  - 删除 `GEOIP_SERVICE` (`OnceLock<GeoIpService>`) — hard global singleton
  - 删除 `init()` / `service()` — hard global API
  - `lookup_country_code()` 只走 weak-owner lookup（`DEFAULT_GEOIP_SERVICE`），不再回落 hard global
  - 新增 `clear_default_for_test()` 测试工具
  - 模块文档更新为 weak-owner model 描述
- Router-local provider 路径（`enhanced_geoip_lookup`）不受影响

**保留的 compat**: `DEFAULT_GEOIP_SERVICE` weak-owner 机制不变，`install_default_geoip_service()` 仍是唯一安装入口。

**不需要补 owner 安装承接**：生产路径通过 router-local GeoIP provider（`RouterHandle::geoip_mux` / `geoip_db`），`init()` 和 `service()` 在生产代码中零调用方。

**验证**:
- `cargo check -p sb-core` ✅
- `cargo check -p app --features "admin_debug sbcore_rules_tool dev-cli prefetch"` ✅
- `cargo test -p sb-core --lib weak_default_registry_uses_explicit_owner` ✅
- `cargo test -p sb-core --lib --features geoip_mmdb enhanced_geoip_lookup_uses_router_local_provider_without_global_service` ✅
- `cargo clippy -p sb-core --features geoip_mmdb --all-targets -- -D warnings` ✅
- `cargo test -p sb-core` ✅ (512 tests)
- `bash scripts/ci/tasks/inbound-errors.sh` ✅

### geoip docs alignment follow-up — 已完成

- `重构package相关/` 两份文档中"第一波 blocker"列表已移除 `geoip`，与代码收口状态对齐

### http_client hard global fallback 收口 — 已完成（earlier）

- 删除 `GLOBAL_HTTP_CLIENT` + `install_http_client()` / `global_http_client()`
- `http_execute()` 只走 weak-owner

## Compat 债务评估结论（四项）

| 项目 | 残留 | 决策 |
|------|------|------|
| http_client | weak-owner only，hard global 已删 | **完成** — 仅 `install_default_http_client()` 入口 |
| geoip | weak-owner only，hard global 已删 | **完成** — 仅 `install_default_geoip_service()` 入口 |
| logging compat | `ACTIVE_RUNTIME` 薄壳 | **保留** — public API |
| security_metrics compat | public wrapper + legacy boundary 单次 owner upgrade | **保留** — public API / legacy default-owner 兼容 |
| sb-metrics LazyLock | registry plumbing 已收口；指标静态仍保留 | **部分完成** — 不继续全量去全局化 |

## 构建基线（2026-03-24）

| 构建 | 状态 |
|------|------|
| `cargo test -p sb-metrics --lib -- --nocapture` | ✅ |
| `cargo clippy -p sb-metrics --all-features --all-targets -- -D warnings` | ✅ |
| `cargo check -p sb-metrics --example serve` | ✅ |
| `cargo test -p sb-core --lib metrics_body_with_registry_exports_owned_metric_without_shared_registry -- --nocapture` | ✅ |
| `cargo clippy -p app --all-features --all-targets -- -D warnings` | ✅ |
| `cargo test -p app --lib --features "admin_debug sbcore_rules_tool dev-cli admin_tests"` | ✅ 152 passed |
| `cargo test -p app --lib default_metrics_owner_records_breaker_reopen_via_legacy_mark_failure --features "admin_debug sbcore_rules_tool dev-cli admin_tests prefetch" -- --nocapture` | ✅ |
| `cargo test -p app --lib legacy_subs_entrypoints_use_default_metrics_owner_when_installed --features "admin_debug sbcore_rules_tool dev-cli admin_tests prefetch" -- --nocapture` | ✅ |
| `bash scripts/ci/tasks/inbound-errors.sh` | ✅ |

## 剩余 Maintenance 债务（非阻塞）

- ~~`http_client` hard global~~ → **已收口**（2026-03-25），仅剩 weak-owner compat
- ~~`geoip` hard global~~ → **已收口**（2026-03-25），仅剩 weak-owner compat
- `logging.rs` public compat 壳：为 Rust API 兼容保留
- `security_metrics.rs` public compat wrapper：已瘦身为单行委托；legacy public 边界保留默认 owner compat 语义
- `sb-metrics` LazyLock 指标静态：registry plumbing 和部分 helper 已收口；不继续做全量去全局化
