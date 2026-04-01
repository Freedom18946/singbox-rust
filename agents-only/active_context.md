<!-- tier: S -->
# 当前上下文（Active Context）

> **用途**：高频更新，每次任务结束时维护。**S-tier：每次会话必读。**
> **纪律**：仅保留当前阶段最关键事实。本文件严格 ≤100 行。

---

## 战略状态

**当前阶段**: 维护模式，L1-L25 全部 Closed
**Parity**: 92.9% (52/56)

## 最近完成（2026-04-02）

### WP-30ao：run_engine runtime orchestration seam 超级卡 — 已完成

- 新增 `app/src/run_engine_runtime/{mod.rs,config_load.rs,debug_env.rs,output.rs,admin_start.rs,watch.rs,supervisor.rs}`，现收纳 config/raw loading、debug/pprof env、startup/reload output glue、admin/clash/api startup、watch/reload handle、signal/shutdown 与 `run_supervisor()` orchestration owner；`app/src/run_engine.rs` 改成 public facade + 委托
- `run_engine.rs` 从 1188 行降到 129 行；当前仓库事实：高层 public entry / option types 仍留在 `run_engine.rs`，但 runtime helper/starter owner 已迁入 `run_engine_runtime/*`；这张卡是 runtime/run_engine helper-starter 超级卡，不是 `planned.rs` / RuntimePlan 卡，也不触碰 `bootstrap_runtime/*` / `router_text.rs` / `dns_env.rs`
- 新增 15 个定点测试（默认 feature 13 个，`--features parity` 15 个），覆盖 config/raw loading 语义、debug env 应用、watch snapshot/change detection、clash_api listen parsing，以及 run_engine facade/source pins；`dns_env.rs` source pin 也已同步到新的 `run_engine_runtime::supervisor` 调用点
- 自验证：`cargo test -p app --lib run_engine_runtime` ✅ 13 passed；`cargo test -p app --lib run_engine_runtime::admin_start --features parity` ✅ 3 passed；`cargo test -p app --lib` ✅ 110 passed；`cargo test -p app` ❌ 当前仓库默认 feature 组合下 `app/tests/e2e_subs_security.rs` 直接引用 `app::admin_debug::*`（既有问题，不是本卡回归）；`cargo clippy -p app --all-features --all-targets -- -D warnings` ✅ 返回 0，但仍打印既有 `admin_debug/mod.rs` doc warning 与 `outbound_groups.rs` dead_code / needless_pass_by_value 类 warning
- **这是 runtime/run_engine helper-starter 超级卡，不是 `planned.rs` 卡，也不是 RuntimePlan/query API 卡**

### WP-30an：bootstrap runtime helper/starter owner 超级卡 — 已完成

- 新增 `app/src/bootstrap_runtime/{mod.rs,proxy_registry.rs,router_helpers.rs,dns_apply.rs,inbounds.rs,api_services.rs,runtime_shell.rs}`，现收纳 proxy registry env/pool parsing、router helper、legacy DNS apply helper、inbound starter facade、Clash/V2Ray API starter、`ServiceHandle`、`Runtime`/`shutdown()` owner；`app/src/bootstrap.rs` 改成高层 facade + 委托
- 当前仓库事实：`bootstrap.rs` 仍未接入 `lib.rs` / `run_engine` 主路径，因此 `bootstrap_runtime` 延续 `outbound_builder` 模式，以 test-only legacy runtime owner module + source pins 收口；这张卡是 runtime/bootstrap helper/starter 超级卡，不是 `planned.rs` / RuntimePlan 卡
- `bootstrap.rs` 从 1109 行降到 255 行；新增 21 个定点测试（默认 feature 16 个，`--features parity` 21 个），覆盖 proxy registry env/pool parsing、DNS token/dedup/normalize、inbound facade、Clash/V2Ray API invalid listen + shutdown handle、runtime shutdown timeout，以及 owner/source pins
- 自验证：`cargo test -p app --lib bootstrap_runtime` ✅ 16 passed；`cargo test -p app --lib bootstrap_runtime --features parity` ✅ 21 passed；`cargo test -p app --lib` ✅ 97 passed；`cargo test -p app` ❌ 当前仓库默认 feature 组合下 `app/tests/e2e_subs_security.rs` 直接引用 `app::admin_debug::*`（既有问题，不是本卡回归）；`cargo clippy -p app --all-features --all-targets -- -D warnings` ✅ 返回 0，但仍打印既有 `admin_debug/mod.rs` doc warning 与 `outbound_groups.rs` dead_code 类 warning
- **这是 runtime/bootstrap helper/starter 超级卡，不是 `planned.rs` 卡，也不是 RuntimePlan/query API 卡**

### WP-30am：bootstrap first-pass concrete outbound builder owner 收口 — 已完成

- 新增 `app/src/outbound_builder/{mod.rs,simple.rs,quic.rs,shadowsocks.rs,v2ray.rs}`，现在收纳 legacy bootstrap first-pass concrete outbound builder owner；按 simple proxy / QUIC / Shadowsocks / V2Ray family 拆分，并把 `resolve_host_port()`、ALPN/header mapping、default alias fill 等 shared helper 一并收口
- `app/src/bootstrap.rs` 的 `build_outbound_registry_from_ir()` 现把 first-pass 委托给 `crate::outbound_builder::build_first_pass_concrete_outbounds(...)`，second-pass selector/urltest binding 继续委托 `crate::outbound_groups::bind_selector_outbound_groups(...)`；这张卡不触碰 `router_text.rs` / `dns_env.rs` / `planned.rs` / RuntimePlan
- 当前仓库事实：`bootstrap.rs` 仍是未接入 `lib.rs` / `run_engine` 主路径的 legacy runtime 文件，因此 `outbound_builder` 以 test-only runtime owner module + source pins 形式收口，避免向 `app(lib)` target 引入新的未接线 warning
- 新增 15 个 first-pass 定点测试：覆盖 Direct/Block/Socks/Http、Hysteria2 brutal/ALPN、Tuic relay mode/zero-rtt、Shadowsocks method+multiplex、Vless/Vmess/Trojan transport/TLS，以及 2 个 owner pins
- 自验证：`cargo test -p app --lib outbound_builder` ✅ 15 passed；`cargo test -p app --lib outbound_groups` ✅ 11 passed；`cargo test -p app --lib` ✅ 81 passed；`cargo test -p app` ❌ 当前仓库默认 feature 组合下 `app/tests/e2e_subs_security.rs` 直接引用 `app::admin_debug::*`（既有问题，不是本卡回归）；`cargo clippy -p app --all-features --all-targets -- -D warnings` ✅ 返回 0，但仍打印既有 `admin_debug/mod.rs` doc warning 与 `outbound_groups.rs` dead_code 类 warning
- **这是 runtime/bootstrap first-pass concrete outbound builder 超级卡，不是 `planned.rs` 卡，也不是 RuntimePlan/query API 卡**

### WP-30al：selector/urltest second-pass runtime owner 收口 — 已完成

- 新增 `app/src/outbound_groups.rs`，现在收纳 selector/urltest second-pass connector binding owner、member lookup/filter、`to_adapter_connector()` 与 URLTest health-check 启动；owner 已从 `app/src/bootstrap.rs` 下沉到独立 runtime 模块
- `app/src/bootstrap.rs` 的 `build_outbound_registry_from_ir()` 现保留第一遍 concrete outbound 构建，并把 second-pass selector/urltest binding 委托给 `crate::outbound_groups::bind_selector_outbound_groups(...)`；空 members / 缺失 member / 不可转换 member 的 skip+warn 语义保持不变
- `bootstrap.rs` 从 1685 行降到 1443 行；`outbound_groups.rs` 411 行（含测试）；这张卡只收口 selector/urltest second-pass runtime owner，**不是** `planned.rs` 卡，也不是 outbound registry builder 大拆卡
- 新增 11 个 selector/urltest 定点测试：覆盖 selector/urltest 正常绑定、empty members skip、missing/unusable member skip、`to_adapter_connector()` 行为 pin，以及 2 个 owner pins
- 自验证：`cargo test -p app --lib outbound_groups` ✅ 11 passed；`cargo test -p app --lib` ✅ 66 passed；`cargo test -p app` ❌ 当前仓库默认 feature 组合下 `app/tests/e2e_subs_security.rs` 直接引用 `app::admin_debug::*`（不是本卡回归）；`cargo clippy -p app --all-features --all-targets -- -D warnings` ✅ 返回 0，但仍打印既有 `admin_debug/mod.rs` doc 段落 warning，且 `bootstrap.rs` 未接入 `lib.rs` 模块树导致 `outbound_groups.rs` 在 `app(lib)` target 下显示 dead_code 类 warning
- **这是 selector/urltest second-pass runtime owner 收口卡，不是 `planned.rs` 卡，也不是 RuntimePlan/query API 卡**

### WP-30ak：legacy router rules text emission owner 收口 — 已完成

- 新增 `app/src/router_text.rs`，现在收纳 `ir_to_router_rules_text()` 与专属 helper；owner 已从 `app/src/bootstrap.rs` 下沉到独立 runtime 模块
- `app/src/bootstrap.rs` 的 `build_router_index_from_config()` 现只保留 `to_ir` → `crate::router_text::ir_to_router_rules_text()` → `router_build_index_from_str()` 的薄委托；`unresolved` fallback、default 行、consumer 协议均保持不变
- `bootstrap.rs` 从 1722 行降到 1685 行；这张卡只收口 legacy router adapter/runtime owner，**不是** `planned.rs` 卡，也不是 bootstrap 大拆卡
- 新增 7 个 router text 定点测试：覆盖 domain / geosite / geoip / cidr4 / cidr6 / port / portrange / process / transport / protocol、missing `rule.outbound` → `unresolved`、missing `route.default` → `default=unresolved`、configured default 行、router consumer 兼容性，以及 2 个 owner pins
- 自验证：`cargo test -p app --lib router_text` ✅ 7 passed；`cargo test -p app --lib wp30ak` ✅ 2 passed；`cargo test -p app --lib` ✅ 55 passed；`cargo test -p app` ❌ 当前仓库默认 feature 组合下 `app/tests/e2e_subs_security.rs` 直接引用 `app::admin_debug::*`（不是本卡回归）；`cargo clippy -p app --all-features --all-targets -- -D warnings` ✅ pass（仅提示既有 `admin_debug/mod.rs` doc 段落 warning）
- **这是 legacy router adapter/runtime owner 收口卡，不是 `planned.rs` 卡，也不是 RuntimePlan/query API 卡**

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
- `bootstrap.rs` 现 255 行，保留 `build_outbound_registry_from_ir()` / `build_router_index_from_config()` / `start_from_config()` 高层 facade；剩余 helper/starter owner 已迁到 `app/src/bootstrap_runtime/*`，但该 bootstrap 路径本身仍是 legacy runtime 壳
- `run_engine.rs` 现 129 行 public facade；剩余 runtime orchestration owner 已迁入 `app/src/run_engine_runtime/*`，但更大的 runtime seam 仍未 actor 化 / RuntimeContext 化

## 后续战场（未启动）

- **WP-30 Phase 3 后续**：
  - validator/v2 facade seam 已收口；`mod.rs` 现 260 行，主剩余是 shared helper + TLS capability re-export
  - `ir/service.rs` / `ir/inbound.rs` / `ir/multiplex.rs` owner 已收口；`ir/mod.rs` 现 252 行，主剩余是 `Credentials` / `Listable<T>` / `StringOrObj<T>` + experimental / compat 暴露
  - 若继续细拆，应明确是 helper seam / compat seam 卡，而不是再把 facade 迁移误写成 RuntimePlan 卡
  - `PlannedFacts` 暴露 namespace 查询方法供 crate 内其他模块使用
  - 将 `PlannedFacts` 升级为 public `RuntimePlan`（需要先有稳定外部消费者）
  - 仍不是 `RuntimePlan` public 实作卡，也不是 crate-internal query API 卡
- runtime/bootstrap seam 继续收口，但 DNS env bridge 仍明确属于 runtime owner，**不**搬进 `planned.rs`
- runtime/bootstrap seam 继续收口，但 legacy router text emission 已迁入 `app/src/router_text.rs`，仍明确属于 runtime owner，**不**搬进 `planned.rs`
- runtime/bootstrap seam 继续收口，但 selector/urltest second-pass binding 已迁入 `app/src/outbound_groups.rs`，仍明确属于 runtime owner，**不**搬进 `planned.rs`
- runtime/bootstrap seam 继续收口，但 `app/src/outbound_builder/*` 当前是 legacy bootstrap 的 first-pass owner 模块，不是 RuntimePlan/query API seam
- runtime/bootstrap seam 继续收口，但 `app/src/bootstrap_runtime/*` 当前承接的 proxy registry/router helper/DNS apply/inbound starter/API starter/runtime shell 仍明确属于 runtime owner，**不**搬进 `planned.rs`
- runtime/run_engine seam 已以 `app/src/run_engine_runtime/*` 收口 helper/starter owner；若继续推进，应聚焦 runtime context / manager lifecycle，而不是回退成重新拆 `planned.rs`
