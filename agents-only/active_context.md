<!-- tier: S -->
# 当前上下文（Active Context）

> **用途**：高频更新，每次任务结束时维护。**S-tier：每次会话必读。**
> **纪律**：仅保留当前阶段最关键事实。本文件严格 ≤100 行。

---

## 战略状态

**当前阶段**: 维护模式，L1-L25 全部 Closed
**Parity**: 92.9% (52/56)

## 当前维护动作（2026-03-24）— Compat Shell 收口

### Compat 债务评估结论（三项）

| 项目 | 位置 | 残留 | 工作量 | ROI | 决策 |
|------|------|------|--------|-----|------|
| logging compat | `app/src/logging.rs` | `ACTIVE_RUNTIME` LazyLock + `init_logging()` + `flush_logs()` + 2 helper，~30 行死代码 | 30min | 极高 | **本轮执行** |
| sb-metrics LazyLock | `crates/sb-metrics/src/lib.rs` + 6 子模块 | 56 个 LazyLock 静态，32 register_collector，40+ 便捷函数，23 外部调用点 | 3-5天 | 很低 | **不做** — prometheus crate 设计哲学如此 |
| security_metrics compat | `app/src/admin_debug/security_metrics.rs` | `DEFAULT_STATE` Weak 注册表 + 40 个 wrapper 函数，16 外部调用点 | 2-4h | 中等 | **可选** — 主链已解耦 |

### 正在执行：logging.rs compat shell 清理

**目标**: 删除 `ACTIVE_RUNTIME` / `init_logging()` / `flush_logs()` / `current_compat_runtime()` / `install_active_runtime_compat()` 全部死代码

**背景**:
- 生产路径已走 `init_logging_with_owner()` + `LoggingOwner::flush()`
- 两个 compat pub fn 均标 `#[allow(dead_code)]`，零外部生产调用
- 仅 logging.rs 内部测试使用 `clear_active_runtime_for_test()` 引用 `ACTIVE_RUNTIME`

**验证基线**:
- `cargo check -p app`
- `cargo clippy -p app --all-features --all-targets -- -D warnings`
- `cargo test -p app --lib --features "admin_debug sbcore_rules_tool dev-cli"`

## 构建基线（2026-03-17，L25 后）

| 构建 | 状态 |
|------|------|
| `cargo clippy --workspace --all-features --all-targets -- -D warnings` | ✅ pass |
| `cargo test -p sb-core --lib` | ✅ 509 passed |
| `cargo test -p sb-api` | ✅ pass |
| `cargo test -p sb-subscribe --all-features --lib` | ✅ 16 passed |

## 剩余 Maintenance 债务（非阻塞）

- `security_metrics.rs` Weak compat 壳：主链已解耦，40 wrapper 仅尾部 legacy 入口使用
- `sb-metrics` LazyLock：结论为"不碰"，prometheus crate 惯用范式
- `geoip/mod.rs` compat 全局注册点：已收敛为弱默认 owner 优先
