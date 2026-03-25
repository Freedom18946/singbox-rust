<!-- tier: S -->
# 当前上下文（Active Context）

> **用途**：高频更新，每次任务结束时维护。**S-tier：每次会话必读。**
> **纪律**：仅保留当前阶段最关键事实。本文件严格 ≤100 行。

---

## 战略状态

**当前阶段**: 维护模式，L1-L25 全部 Closed
**Parity**: 92.9% (52/56)

## 最近完成（2026-03-25）

### http_server accept/connection lifecycle 收口 — 已完成

- `app/src/admin_debug/http_server.rs`:
  - `AdminDebugHandle` (CancellationToken + Option\<JoinHandle\>)
  - `Drop` impl 触发 cancel（与 Prefetcher 同 pattern）
  - `shutdown()` cancel + await join；显式 shutdown 更强（等待 drain），drop 仅发信号
  - `serve()` / `serve_plain()` / `spawn()` 底层改为 tracked accept loop
  - 新增 `spawn_plain_sync()` 供非 async 调用方使用
  - 抽取 `route_full_request()` 消除路由重复
- `app/src/admin_debug/mod.rs`: `init()` 返回 `AdminDebugHandle`（不再裸 `tokio::spawn`）
- `app/src/run_engine.rs`: `admin_debug_handle` 变量持有 handle，section 11 显式 shutdown
- `app/src/cli/run.rs`: `_admin_debug_handle` 存活至 run_supervisor 退出
- `app/src/telemetry.rs`: `init_and_listen()` 返回 `Option<AdminDebugHandle>`

**验证**:
- `cargo check -p app --features "admin_debug sbcore_rules_tool dev-cli prefetch"` ✅
- `cargo test -p app --lib "admin_debug::http_server"` ✅ (14 passed, 含 4 新 lifecycle 测试)
- `cargo test -p app --test admin_auth_contract` ✅ (7 passed)
- `cargo clippy -p app --all-features --all-targets -- -D warnings` ✅
- `bash scripts/ci/tasks/inbound-errors.sh` ✅

### prefetch / geoip / http_client — 已完成（earlier today）

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
- `outbound/anytls.rs` / `ssh`：仍是第一波 blocker
