<!-- tier: S -->
# 当前上下文（Active Context）

> **用途**：高频更新，每次任务结束时维护。**S-tier：每次会话必读。**
> **纪律**：仅保留当前阶段最关键事实。本文件严格 ≤100 行。

---

## 战略状态

**当前阶段**: 维护模式，L1-L25 全部 Closed
**Parity**: 92.9% (52/56)

## 最近完成（2026-03-24）

### security_metrics compat 壳收口 — review follow-up 已修正

**Commit 1** `ebe9db4b` — 内部调用面脱钩（+92/-137, 4 files）:
- `prefetch.rs`: 5 个 helper 删 else 分支，不再回落 compat wrapper
- `security_async.rs`: `resolve_checked` / `forbid_private_*` 合并为共用 inner 函数，消除 5 个 compat 调用
- `breaker.rs`: `record_breaker_reopen` 删 else
- `subs.rs`: 17 个 local wrapper 删 else + 清理 15 个 compat use 导入
- 新增 2 个回归测试（prefetch owner-aware + breaker explicit metrics）

**Commit 2** `88efb216` — security_metrics.rs 本体瘦身（+47/-183, 1 file）:
- 新增 `with_current()` / `map_current()` 私有 helper
- 40 个 pub fn compat wrapper 从 3-4 行 if-let 块收成单行委托
- public API 不变，仅内部实现精简

**Review fix**:
- 恢复 legacy `HostBreaker::mark_failure()` 在默认 `SecurityMetricsState` 已安装时的 reopen 记账语义
- 恢复 legacy `/subs` public API（`fetch_with_limits()` / `fetch_with_limits_to_cache()` / `handle()`）在默认 owner 已安装时的 metrics 记账
- 修法是仅在 legacy public 边界单次 `current_owner()` upgrade；内部 helper 仍保持 owner-first，不重新回到满地 compat wrapper

**Grep 验收**: `rg "crate::admin_debug::security_metrics::(inc_|record_|set_|mark_|prefetch_|init_prefetch|get_prefetch_)" app/src` → **零匹配**

### logging.rs public compat API 恢复 — review follow-up

- 针对 `6c88a027` 的 review，恢复 `init_logging()` / `flush_logs()` public compat
- 保留 2 个 flaky test 修复：`HIGH_WATERMARK` 重置、`runtime_deps` serial + cleanup

## Compat 债务评估结论（三项）

| 项目 | 残留 | 决策 |
|------|------|------|
| logging compat | `ACTIVE_RUNTIME` 薄壳 | **保留** — public API |
| security_metrics compat | public wrapper + legacy boundary 单次 owner upgrade | **保留** — public API / legacy default-owner 兼容 |
| sb-metrics LazyLock | 56 LazyLock + 40 便捷函数 | **不做** — prometheus 惯用范式 |

## 构建基线（2026-03-24）

| 构建 | 状态 |
|------|------|
| `cargo clippy -p app --all-features --all-targets -- -D warnings` | ✅ |
| `cargo test -p app --lib --features "admin_debug sbcore_rules_tool dev-cli admin_tests"` | ✅ 152 passed |
| `cargo test -p app --lib default_metrics_owner_records_breaker_reopen_via_legacy_mark_failure --features "admin_debug sbcore_rules_tool dev-cli admin_tests prefetch" -- --nocapture` | ✅ |
| `cargo test -p app --lib legacy_subs_entrypoints_use_default_metrics_owner_when_installed --features "admin_debug sbcore_rules_tool dev-cli admin_tests prefetch" -- --nocapture` | ✅ |
| `bash scripts/ci/tasks/inbound-errors.sh` | ✅ |

## 剩余 Maintenance 债务（非阻塞）

- `logging.rs` public compat 壳：为 Rust API 兼容保留
- `security_metrics.rs` public compat wrapper：已瘦身为单行委托；legacy public 边界保留默认 owner compat 语义
- `sb-metrics` LazyLock：不碰，prometheus crate 惯用范式
- `geoip/mod.rs` compat 全局注册点：已收敛为弱默认 owner 优先
