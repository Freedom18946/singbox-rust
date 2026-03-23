<!-- tier: S -->
# 当前上下文（Active Context）

> **用途**：高频更新，每次任务结束时维护。**S-tier：每次会话必读。**
> **纪律**：仅保留当前阶段最关键事实。本文件严格 ≤100 行。

---

## 战略状态

**当前阶段**: 维护模式，L1-L25 全部 Closed
**Parity**: 92.9% (52/56)

## 最近完成（2026-03-24）

### logging.rs public compat API 恢复 — review follow-up

- 针对 `6c88a027` 的 review finding，恢复 `init_logging()` / `flush_logs()` 公共 compat wrapper，避免 maintenance mode 下的 Rust public API break
- 恢复 `ACTIVE_RUNTIME: LazyLock<StdMutex<Weak<LoggingRuntime>>>`、`current_compat_runtime()`、`install_active_runtime_compat()` 与私有 `runtime()` getter
- `main` 生产启动/退出路径仍继续显式持有并 flush `LoggingOwner`；compat 壳仅服务 legacy public API，不重新成为主路径 owner
- 保留 Claude 已修的 2 个 flaky tests：`HIGH_WATERMARK` 重置、`runtime_deps` serial + cleanup

**验证**:
- `cargo check -p app --features "admin_debug sbcore_rules_tool dev-cli"` ✅
- `cargo clippy -p app --all-features --all-targets -- -D warnings` ✅
- `cargo test -p app --bin app explicit_owner_does_not_install_compat_registry --features "admin_debug sbcore_rules_tool dev-cli" -- --nocapture` ✅
- `cargo test -p app --bin app test_flush_logs_async --features "admin_debug sbcore_rules_tool dev-cli" -- --nocapture` ✅
- `bash scripts/ci/tasks/inbound-errors.sh` ✅

## Compat 债务评估结论（三项）

| 项目 | 残留 | ROI | 决策 |
|------|------|-----|------|
| logging compat | `ACTIVE_RUNTIME` + `init_logging()` / `flush_logs()` 薄包装层 | 低 | **保留** — public API compat shell |
| sb-metrics LazyLock | 56 LazyLock + 40 便捷函数 | 很低 | **不做** — prometheus 惯用范式 |
| security_metrics compat | DEFAULT_STATE + 40 wrapper | 中等 | **可选** — 主链已解耦 |

## 构建基线（2026-03-24）

| 构建 | 状态 |
|------|------|
| `cargo check -p app` | ✅ |
| `cargo clippy -p app --all-features --all-targets -- -D warnings` | ✅ |
| `cargo test -p app --lib --features "admin_debug sbcore_rules_tool dev-cli"` | ✅ 49 passed |

## 剩余 Maintenance 债务（非阻塞）

- `logging.rs` public compat 壳：为 Rust API 兼容保留，不再作为继续削减目标
- `security_metrics.rs` Weak compat 壳：主链已解耦，40 wrapper 仅尾部 legacy 入口使用
- `sb-metrics` LazyLock：结论为"不碰"，prometheus crate 惯用范式
- `geoip/mod.rs` compat 全局注册点：已收敛为弱默认 owner 优先
