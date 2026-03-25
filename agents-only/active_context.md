<!-- tier: S -->
# 当前上下文（Active Context）

> **用途**：高频更新，每次任务结束时维护。**S-tier：每次会话必读。**
> **纪律**：仅保留当前阶段最关键事实。本文件严格 ≤100 行。

---

## 战略状态

**当前阶段**: 维护模式，L1-L25 全部 Closed
**Parity**: 92.9% (52/56)

## 最近完成（2026-03-26）

### outbound/anytls.rs lifecycle 收口 — 已完成（含 follow-up）

- `crates/sb-adapters/src/outbound/anytls.rs`:
  - `SessionRuntime` owner：`JoinSet<()>` 持有 recv_loop / process_stream_data 的 JoinHandle（不再隐式丢弃）
  - `shutdown(self)` 方法：abort + await all（async 路径显式 join）
  - `JoinSet::drop` 作为 sync 兜底：abort all（connector drop 时）
  - `get_or_create_session()` 三阶段锁：短锁读→锁外 connect→短锁安装（stale runtime 在锁外 `shutdown().await`）
  - `connect()` bridge tasks 在 `JoinSet<()>` tracked，connector drop 时 abort
  - `listener.accept()` 临时 spawn 替换为 `tokio::try_join!`
  - 零 `tokio::spawn` 调用：所有任务通过 `JoinSet::spawn` 持有

**验证**:
- `cargo check -p sb-adapters --features adapter-anytls` ✅
- `cargo check -p app --features parity` ✅
- `cargo test -p app --test anytls_outbound_test` ✅ (6 passed)
- `cargo test -p sb-adapters --lib outbound::anytls` ✅ (6 passed, 含 lifecycle 测试)
- `cargo clippy -p sb-adapters --features adapter-anytls` ✅
- `bash scripts/ci/tasks/inbound-errors.sh` ✅

### http_server / prefetch / geoip / http_client — 已完成（2026-03-25）

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
- ~~`outbound/anytls.rs`~~ → **已收口**（`JoinSet` owner + `shutdown()` join + bridge tracked + lock-across-await 消除，零 `tokio::spawn`）
- `outbound/ssh.rs`：仍是第一波 blocker
