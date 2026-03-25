<!-- tier: S -->
# 当前上下文（Active Context）

> **用途**：高频更新，每次任务结束时维护。**S-tier：每次会话必读。**
> **纪律**：仅保留当前阶段最关键事实。本文件严格 ≤100 行。

---

## 战略状态

**当前阶段**: 维护模式，L1-L25 全部 Closed
**Parity**: 92.9% (52/56)

## 最近完成（2026-03-26）

### validator/v2 service 子域拆分 — 已完成

- 新增 `crates/sb-config/src/validator/v2/service.rs`（135 行）
- **搬到 `service.rs` 的逻辑**：
  - `allowed_service_keys()` — service 允许字段集
  - `validate_services()` — `/services` unknown-field 校验
- **`validate_v2()` 仍为统一 orchestration 入口**，service 部分 dispatch 到子模块
- **语义冻结**：issue ptr / code / severity / message / hint 完全不变
- **mod.rs 从 4757 行瘦身至 4710 行**（-47 行），service.rs 135 行（含 4 个新定点测试）
- 新增 4 个 service 定点测试：unknown-field strict/allow_unknown、无 services 无误报、ptr 精确命中多 index

**注意**：`validator/v2` 已完成 outbound + route + dns + service 四个子域拆分，endpoint 尚未拆出。`ir/mod.rs` 仍未动。

**验证**:
- `cargo fmt --all` ✅
- `cargo check -p sb-config` ✅
- `cargo check -p app --features parity` ✅
- `cargo test -p sb-config --lib validator::v2` ✅ (86 passed，含 4 个新 service 测试)
- `cargo test -p sb-config --test compatibility_matrix` ✅ (6 passed)
- `cargo clippy -p sb-config --all-features --all-targets -- -D warnings` ✅
- `bash scripts/ci/tasks/inbound-errors.sh` ✅

### validator/v2 dns 子域拆分 — 已完成

- `v2/dns.rs`（221 行）：`allowed_dns_keys` / `allowed_dns_server_keys` / `allowed_dns_rule_keys` + `validate_dns` + 8 定点测试
- mod.rs 4836→4757 行（-79 行），语义冻结，验证全通过

### validator/v2 route 子域拆分 — 已完成

- `v2/route.rs`（362 行）：`allowed_route_keys` + rule/rule_set helpers + `validate_route` + 14 定点测试
- mod.rs 5048→4836 行（-212 行），语义冻结，验证全通过

### validator/v2 outbound 子域拆分 — 已完成

- `v2/outbound.rs`（610 行）：`allowed_outbound_keys` + `validate_outbounds` + `check_tls_capabilities` + 13 定点测试
- mod.rs 5384→5048 行（-336 行），语义冻结，验证全通过

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
