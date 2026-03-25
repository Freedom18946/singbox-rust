<!-- tier: S -->
# 当前上下文（Active Context）

> **用途**：高频更新，每次任务结束时维护。**S-tier：每次会话必读。**
> **纪律**：仅保留当前阶段最关键事实。本文件严格 ≤100 行。

---

## 战略状态

**当前阶段**: 维护模式，L1-L25 全部 Closed
**Parity**: 92.9% (52/56)

## 最近完成（2026-03-25）

### prefetch hard global + lifecycle 收口 — 已完成

- `app/src/admin_debug/prefetch.rs`:
  - 删除 `GLOBAL: OnceCell<Prefetcher>` — hard global singleton
  - 删除 `Prefetcher::global()` — hard global API
  - 删除 `global_take()` — placeholder shutdown API
  - `enqueue_prefetch()` / `enqueue_prefetch_with_metrics()` 不再 fallback 到 `Prefetcher::global()`，无 owner 时返回 `false`
  - Worker lifecycle 改为 tracked/owned model：
    - 单 dispatcher task 直接拥有 `Receiver`（不再 `Arc<Mutex<Receiver>>`）
    - `CancellationToken` + `JoinHandle` 存储于 `Prefetcher`
    - `JoinSet` 管理并发 worker（不再裸 `tokio::spawn` N 个 worker）
    - `shutdown()` 是真实的 async shutdown（cancel + await handle）
    - `Drop` impl 触发 cancel
  - 模块文档更新为 explicit-owner + tracked-worker 描述
- `app/Cargo.toml`: `admin_debug` feature 新增 `tokio-util` 依赖（`CancellationToken`）

**保留的 compat**: `DEFAULT_PREFETCHER` weak-owner 机制不变，`install_default_prefetcher()` 仍是唯一安装入口。

**owner 安装点未改动**：`AppRuntimeDeps::new()` 和 `build_prefetch_runtime_deps()` 保持原样。

**验证**:
- `cargo check -p app --features "admin_debug sbcore_rules_tool dev-cli prefetch"` ✅
- `cargo test -p app --lib --features "admin_debug sbcore_rules_tool dev-cli prefetch"` ✅ (52 passed)
- `cargo test -p app --lib "admin_debug::prefetch"` ✅ (10 passed, 含 lifecycle 测试)
- `cargo clippy -p app --all-features --all-targets -- -D warnings` ✅
- `bash scripts/ci/tasks/inbound-errors.sh` ✅

### geoip / http_client hard global 收口 — 已完成（earlier today）

- 详见本文件历史快照

## Compat 债务评估结论

| 项目 | 残留 | 决策 |
|------|------|------|
| http_client | weak-owner only，hard global 已删 | **完成** |
| geoip | weak-owner only，hard global 已删 | **完成** |
| prefetch | weak-owner only，hard global 已删，worker lifecycle tracked | **完成** |
| logging compat | `ACTIVE_RUNTIME` 薄壳 | **保留** — public API |
| security_metrics compat | public wrapper + legacy boundary | **保留** — public API |
| sb-metrics LazyLock | registry plumbing 已收口 | **部分完成** |

## 剩余 Maintenance 债务（非阻塞）

- ~~`http_client` hard global~~ → **已收口**
- ~~`geoip` hard global~~ → **已收口**
- ~~`prefetch` hard global + lifecycle~~ → **已收口**
- `logging.rs` public compat 壳：为 Rust API 兼容保留
- `security_metrics.rs` public compat wrapper：已瘦身为单行委托
- `sb-metrics` LazyLock 指标静态：不继续做全量去全局化
- `http_server.rs` accept loop 裸 spawn：仍是第一波 blocker
- `outbound/anytls.rs` / `ssh`：仍是第一波 blocker
