<!-- tier: S -->
# 当前上下文（Active Context）

> **用途**：高频更新，每次任务结束时维护。**S-tier：每次会话必读。**
> **纪律**：仅保留当前阶段最关键事实。本文件严格 ≤100 行。

---

## 战略状态

**当前阶段**: 维护模式，L1-L25 全部 Closed
**Parity**: 92.9% (52/56)

## 最近完成（2026-03-26）

### outbound/anytls.rs lifecycle 收口 — 已完成

- `crates/sb-adapters/src/outbound/anytls.rs`:
  - `SessionRuntime` owner：持有 `Arc<Session>` + 2 个 `AbortHandle`（recv_loop / process_stream_data）
  - `Drop for SessionRuntime` 在 session 替换或 connector drop 时 abort 后台 tasks
  - `get_or_create_session()` 改为三阶段：短锁读→锁外 connect→短锁安装（含竞争合并）
  - `connect()` bridge tasks 改为 `JoinSet<()>` tracked，connector drop 时 abort 所有残余
  - `listener.accept()` 临时 spawn 替换为 `tokio::try_join!`
  - 每次 `connect()` 入口 drain 已完成的 bridge tasks 防止无限累积

**验证**:
- `cargo check -p sb-adapters --features adapter-anytls` ✅
- `cargo check -p app --features parity` ✅
- `cargo test -p app --test anytls_outbound_test` ✅ (6 passed)
- `cargo test -p sb-adapters --lib outbound::anytls` ✅ (4 passed, 含新 lifecycle 测试)
- `cargo clippy -p sb-adapters --features adapter-anytls` ✅ (仅 pre-existing dead_code warning)
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
- ~~`outbound/anytls.rs`~~ → **已收口**（session owner + bridge JoinSet + lock-across-await 消除）
- `outbound/ssh.rs`：仍是第一波 blocker
