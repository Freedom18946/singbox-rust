<!-- tier: S -->
# 当前上下文（Active Context）

> **用途**：高频更新，每次任务结束时维护。**S-tier：每次会话必读。**
> **纪律**：仅保留当前阶段最关键事实。本文件严格 ≤100 行。

---

## 战略状态

**当前阶段**: 维护模式，L1-L25 全部 Closed
**Parity**: 92.9% (52/56)

## 最近完成（2026-03-26）

### sb-config outbound.rs Raw/Validated 边界试点 — 已完成

- `crates/sb-config/src/outbound/`:
  - **Raw 层（`raw.rs`）**：16 个 Raw 类型，全部 `#[serde(deny_unknown_fields)]`，承接所有 serde 反序列化
  - **Validated 层（`mod.rs`）**：16 个 domain 类型，不再 `derive(Deserialize)`，通过 `impl Deserialize via Raw bridge` 中转
  - **`From<Raw*> for *`**：16 组无损转换
  - **adapter 使用面零影响**：`HttpProxyConfig` / `Socks5Config` / `Socks4Config` / `TlsConfig` 等仍由 adapter 直接字段构造
  - **新增 27 个定点测试**：未知字段拒绝（8 顶层 + 3 嵌套）、合法解析（9）、默认值（4）、roundtrip（2）、适配器兼容（1）

**注意**：这是 sb-config 的第一刀。`ir/mod.rs` 与 `validator/v2.rs` 仍是结构 blocker，sb-config 整体仍在第一波 blocker 列表中。

**验证**:
- `cargo check -p sb-config` ✅
- `cargo check -p app --features parity` ✅
- `cargo test -p sb-config` ✅ (全部通过，含 27 个新 boundary 测试)
- `cargo test -p sb-config --test vless_config_test` ✅ (5 passed，现有测试未被打坏)
- `cargo clippy -p sb-config --all-features --all-targets -- -D warnings` ✅
- `bash scripts/ci/tasks/inbound-errors.sh` ✅

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
- ~~`outbound/anytls.rs`~~ → **已收口**（`JoinSet` owner + `shutdown()` join + bridge tracked + lock-across-await 消除，零 `tokio::spawn`）
- ~~`outbound/ssh.rs`~~ → **已收口**（`PostAuthSession` 最小能力封装消除 session 锁 + 三阶段 pool 锁 + `JoinSet` bridge owner，零 `tokio::spawn`）
