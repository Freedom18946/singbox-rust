<!-- tier: S -->
# 当前上下文（Active Context）

> **用途**：高频更新，每次任务结束时维护。**S-tier：每次会话必读。**
> **纪律**：仅保留当前阶段最关键事实。本文件严格 ≤100 行。

---

## 战略状态

**当前阶段**: 维护模式，L1-L25 全部 Closed
**Parity**: 92.9% (52/56)

## 最近完成（2026-03-26）

### validator/v2 route 子域拆分 — 已完成

- 新增 `crates/sb-config/src/validator/v2/route.rs`（362 行）
- **搬到 `route.rs` 的逻辑**：
  - `allowed_route_keys()` — route 允许字段集
  - `allowed_route_rule_keys()` — route rule 允许字段集
  - `allowed_rule_set_keys()` — rule_set 允许字段集
  - `rule_set_format_from_path()` / `rule_set_format_from_url()` — 格式推断（`pub(super)` 供 IR 逻辑复用）
  - `validate_route()` — `/route` 顶层 + `/route/rules` + `/route/rule_set` unknown-field 校验 + rule_set 结构/type/format/version 校验
- **`validate_v2()` 仍为统一 orchestration 入口**，route 部分 dispatch 到子模块
- **语义冻结**：issue ptr / code / severity / message 完全不变
- **mod.rs 从 5048 行瘦身至 4836 行**（-212 行），route.rs 362 行（含 14 个新定点测试）
- 新增 14 个 route 定点测试：unknown-field strict/allow_unknown（route/rule/rule_set）、rule_set 结构校验（not-object/missing-tag/invalid-type/missing-format/format-inference/invalid-version/valid-versions/no-route）

**注意**：`validator/v2` 已完成 outbound + route 两个子域拆分，dns/service/endpoint 尚未拆出。`ir/mod.rs` 仍未动。sb-config 整体仍在第一波 blocker 列表中。

**验证**:
- `cargo check -p sb-config` ✅
- `cargo check -p app --features parity` ✅
- `cargo test -p sb-config --test compatibility_matrix` ✅ (6 passed)
- `cargo test -p sb-config --test rule_set_parity` ✅ (4 passed)
- `cargo test -p sb-config --lib validator::v2` ✅ (74 passed，含 14 个新 route 测试)
- `cargo clippy -p sb-config --all-features --all-targets -- -D warnings` ✅
- `bash scripts/ci/tasks/inbound-errors.sh` ✅

### validator/v2 outbound 子域拆分 — 已完成

- `crates/sb-config/src/validator/v2.rs` 转为目录模块 `v2/mod.rs` + `v2/outbound.rs`
- **搬到 `outbound.rs` 的逻辑**：
  - `allowed_outbound_keys()` — outbound 允许字段集
  - `validate_outbounds()` — `/outbounds` 数组结构、type/tag/unknown-field 校验
  - `check_tls_capabilities()` — uTLS/ECH/REALITY TLS 诊断（含 QUIC+ECH 拦截）
- **`validate_v2()` 仍为统一 orchestration 入口**，outbound 部分 dispatch 到子模块
- **语义冻结**：issue ptr / code / severity / message 完全不变
- **mod.rs 从 5384 行瘦身至 5048 行**（-336 行），outbound.rs 610 行（含 13 个新定点测试）
- 新增 13 个 outbound 定点测试：数组校验、item 类型、type/tag 类型、unknown-field strict/allow_unknown、utls/reality/ECH

**注意**：`validator/v2` 已完成 outbound + route 两个子域拆分，dns/service/endpoint 尚未拆出。`ir/mod.rs` 仍未动。sb-config 整体仍在第一波 blocker 列表中。

**注意（历史）**：这是 sb-config 的第一刀。`ir/mod.rs` 与 `validator/v2/` 其余子域（dns/service/endpoint）仍是结构 blocker，sb-config 整体仍在第一波 blocker 列表中。

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
