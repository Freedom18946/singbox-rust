<!-- tier: S -->
# 当前上下文（Active Context）

> **用途**：高频更新，每次任务结束时维护。**S-tier：每次会话必读。**
> **纪律**：仅保留当前阶段最关键事实。本文件严格 ≤100 行。

---

## 战略状态

**当前阶段**: 维护模式，L1-L25 全部 Closed
**Parity**: 92.9% (52/56)

## 最近完成（2026-04-01）

### WP-30aj：runtime-facing DNS env bridge owner 收口 — 已完成

- 新增 `app/src/dns_env.rs`，现在收纳 `apply_dns_env_from_config()` 与专属 helper；owner 已从 `app/src/run_engine.rs` 下沉到独立 runtime 模块
- `app/src/run_engine.rs` 对 DNS env bridge 现只保留 `opts.dns_env_bridge` gating 下的一行委托；返回值、日志语义与 feature gate 保持不变
- `run_engine.rs` 从 1500+ 行进一步降到 1188 行；`bootstrap.rs` 里的 DNS env 写入逻辑保持原样，这张卡**不是** bootstrap/run_engine 统一化卡
- 新增 11 个 DNS env 定点测试：覆盖 `udp://` / `https://` / `dot://` / `doq://` / `system`、strategy→`SB_DNS_QTYPE`/`SB_DNS_HE_ORDER`、TTL/hosts/static、`set_if_unset`、`bool` 返回语义，以及 2 个 owner pins
- 自验证：`cargo test -p app --lib dns_env` ✅ 11 passed；`cargo test -p app --lib` ✅ 48 passed；`cargo test -p app` ❌ 当前仓库默认 feature 组合下 `app/tests/e2e_subs_security.rs` 直接引用 `app::admin_debug::*`（不是本卡回归）；`cargo clippy -p app --all-features --all-targets -- -D warnings` 暴露的是既有 `admin_debug/mod.rs` / `telemetry.rs` 警告，不是 DNS env bridge 新告警
- **这是 runtime-facing DNS env bridge owner 收口卡，不是 `planned.rs` 卡，也不是 RuntimePlan/query API 卡**

### Earlier（2026-04-01）

- `WP-30ai` / `WP-30ah` / `WP-30ag`：`ir/multiplex.rs`、`ir/inbound.rs`、`ir/service.rs` owner 收口已完成；`ir/mod.rs` 现 252 行，主剩余是共享类型与 compat 暴露
- `WP-30af` / `WP-30ae`：`validator/v2` facade 与 root schema core owner 收口已完成；`validator/v2/mod.rs` 现 260 行，主剩余是 shared helper + TLS capability re-export
- `WP-30ad` ~ `WP-30k`：credentials/top-level/security/deprecation/outbound/route/dns/service/endpoint/inbound/planned seam 系列均已完成
- `normalize` / `minimize` owner 已迁入 `ir/normalize.rs` / `ir/minimize.rs`；`PlannedFacts` 仍是 crate-private，不新增 public `RuntimePlan` / builder / query API

## 剩余 Maintenance 债务（非阻塞）

- `logging.rs` public compat 壳：为 Rust API 兼容保留
- `security_metrics.rs` public compat wrapper：已瘦身为单行委托
- `sb-metrics` LazyLock 指标静态：不继续做全量去全局化
- `bootstrap.rs` 仍约 1722 行；`run_engine.rs` 虽已剥离 DNS env bridge，但仍是更大的 runtime orchestration 壳

## 后续战场（未启动）

- **WP-30 Phase 3 后续**：
  - validator/v2 facade seam 已收口；`mod.rs` 现 260 行，主剩余是 shared helper + TLS capability re-export
  - `ir/service.rs` / `ir/inbound.rs` / `ir/multiplex.rs` owner 已收口；`ir/mod.rs` 现 252 行，主剩余是 `Credentials` / `Listable<T>` / `StringOrObj<T>` + experimental / compat 暴露
  - 若继续细拆，应明确是 helper seam / compat seam 卡，而不是再把 facade 迁移误写成 RuntimePlan 卡
  - `PlannedFacts` 暴露 namespace 查询方法供 crate 内其他模块使用
  - 将 `PlannedFacts` 升级为 public `RuntimePlan`（需要先有稳定外部消费者）
  - 仍不是 `RuntimePlan` public 实作卡，也不是 crate-internal query API 卡
- runtime/bootstrap seam 继续收口，但 DNS env bridge 仍明确属于 runtime owner，**不**搬进 `planned.rs`
