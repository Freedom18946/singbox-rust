<!-- tier: S -->
# 当前上下文（Active Context）

> **用途**：高频更新，每次任务结束时维护。**S-tier：每次会话必读。**
> **纪律**：仅保留当前阶段最关键事实。本文件严格 ≤100 行。

---

## 战略状态

**当前阶段**: 维护模式，L1-L25 全部 Closed
**Parity**: 92.9% (52/56)

## 最近完成（2026-03-24）

### sb-metrics registry plumbing 收口 — 已完成

- `crates/sb-metrics/src/lib.rs`
  - 补 2 个 characterization tests：`owner_drop_cleans_up_without_residual_metrics`、`shared_register_after_owner_install_lands_in_owner_registry`
  - 给 3 个 owner-installing tests 加 `#[serial]`，锁住默认 owner 安装/释放的并行测试干扰
  - 删除冗余 `registration_registry_ref()`；`RegistryRef` 新增 `as_registry()`，把重复 match 臂收口
  - 新增 `registered_int_gauge()` / `registered_int_counter()` / `registered_counter_vec()` / `registered_histogram()` 4 个私有 helper
  - `legacy` 模块 8 个静态里，6 个收成一行 helper 调用；2 个 `GaugeVec` 因自定义 fallback 保持原写法
- `crates/sb-metrics/Cargo.toml` / `Cargo.lock`
  - 新增 `serial_test` dev-dependency，承接 registry owner 测试隔离

**验证**:
- `cargo test -p sb-metrics --lib -- --nocapture` ✅
- `cargo clippy -p sb-metrics --all-features --all-targets -- -D warnings` ✅
- `cargo check -p sb-metrics --example serve` ✅
- `cargo test -p sb-core --lib metrics_body_with_registry_exports_owned_metric_without_shared_registry -- --nocapture` ✅

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

- `logging.rs` public compat 壳：为 Rust API 兼容保留
- `security_metrics.rs` public compat wrapper：已瘦身为单行委托；legacy public 边界保留默认 owner compat 语义
- `sb-metrics` LazyLock 指标静态：registry plumbing 和部分 helper 已收口；不继续做全量去全局化
- `geoip/mod.rs` compat 全局注册点：已收敛为弱默认 owner 优先
