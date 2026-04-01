<!-- tier: S -->
# 当前上下文（Active Context）

> **用途**：高频更新，每次任务结束时维护。**S-tier：每次会话必读。**
> **纪律**：仅保留当前阶段最关键事实。本文件严格 ≤100 行。

---

## 战略状态

**当前阶段**: 维护模式，L1-L25 全部 Closed
**Parity**: 92.9% (52/56)

## 最近完成（2026-04-02）

### WP-30ar：sb-config DNS phase-boundary stabilization 超级卡 — 已完成
- 新增 `crates/sb-config/src/ir/dns_raw.rs`，把 `RawDnsServerIR` / `RawDnsRuleIR` / `RawDnsHostIR` / `RawDnsIR` 与 `From<RawDns*> for Dns*` bridge 从 5533 行 `ir/raw.rs` 巨石中抽出；`ir/raw.rs` 现仅为 `RawConfigRoot` broader boundary + DNS Raw compat/re-export 壳，`crate::ir::*` 既有路径保持稳定
- `crates/sb-config/src/ir/dns.rs` 现明确为 validated DNS owner，并直接从 `dns_raw` 委托 `Deserialize`；`validator/v2/dns.rs` 仍只承接 DNS validation + lowering owner，`planned.rs` 仍只做 DNS namespace/reference facts，`ir/normalize.rs` / `ir/minimize.rs` 继续明确不是 DNS planning owner；这张卡是 **DNS subtree raw/validated/planned boundary stabilization**，不是 `planned.rs` / RuntimePlan / app runtime 卡
- 新增并迁移 DNS subtree 专属测试与 source pins，覆盖 Raw unknown-field rejection、Raw->Validated bridge、validated `Deserialize` 语义、`planned.rs` 的 DNS refs-only scope，以及 `normalize` / `minimize` 对 DNS planning 非 owner 的 pin；自验证：`cargo test -p sb-config --lib dns` ✅ 104 passed，`cargo test -p sb-config --test outbound_raw_boundary_test` ✅ 27 passed，`cargo test -p sb-config --lib` ✅ 672 passed，`cargo clippy -p sb-config --all-features --all-targets -- -D warnings` ✅

### WP-30ap：app crate baseline stabilization 超级卡 — 已完成
- `app/tests/e2e_subs_security.rs` 现以 `#![cfg(feature = "admin_debug")]` gate 整个 feature-specific integration suite；新增 `app/tests/wp30ap_baseline_gates.rs` source pins，默认 `cargo test -p app` 不再被 `admin_debug` feature mismatch 卡住，`cargo test -p app --test e2e_subs_security --features admin_debug` ✅ 23 passed
- `app/src/lib.rs` 现将 `outbound_groups` 与 `outbound_builder` / `bootstrap_runtime` 对齐为 `#[cfg(all(feature = "router", test))]` legacy runtime owner seam；`app/src/admin_debug/mod.rs` doc 段落 warning 已修正；`cargo clippy -p app --all-features --all-targets -- -D warnings` ✅ 0 warning output
- `app/tests/dns_transport_comprehensive_test.rs` 的 system resolver baseline pin 已按当前 `sb-core::dns::config_builder` 事实更新为 `cached_resolver`；`comprehensive_security_integration` 现先安装 `security_metrics` owner 再断言 snapshot，这两处都属于 test/baseline 收口，不改 runtime 语义；**这仍是 app baseline stabilization 卡，不是 `planned.rs` / RuntimePlan / sb-config 语义卡**
- 自验证：`cargo test -p app --lib` ✅ 110 passed；`cargo test -p app` ✅ 全量通过；`cargo test -p app --test e2e_subs_security --features admin_debug` ✅ 23 passed；`cargo clippy -p app --all-features --all-targets -- -D warnings` ✅

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

- `WP-30aq`：`ir/{credentials,value_wrappers}.rs` 与 `validator/v2/helpers.rs` 已把 shared compat/helper seam 收成稳定薄壳；后续 sb-config 主战场因此转向 DNS subtree 的 raw/validated/planned 边界，并在 2026-04-02 的 `WP-30ar` 完成第一轮稳定化
- `WP-30ai` / `WP-30ah` / `WP-30ag` / `WP-30af` / `WP-30ae`：`ir` service/inbound/multiplex owner 与 validator facade/schema core 收口已完成；这些成果在 2026-04-02 的 `WP-30aq` 中继续被薄壳化为稳定 compat facade
- `WP-30ad` ~ `WP-30k`：credentials/top-level/security/deprecation/outbound/route/dns/service/endpoint/inbound/planned seam 系列均已完成；`normalize` / `minimize` owner 已迁入 `ir/normalize.rs` / `ir/minimize.rs`

## 剩余 Maintenance 债务（非阻塞）

- `logging.rs` public compat 壳：为 Rust API 兼容保留
- `security_metrics.rs` public compat wrapper：已瘦身为单行委托
- `sb-metrics` LazyLock 指标静态：不继续做全量去全局化
- `bootstrap.rs` 现 255 行，保留 `build_outbound_registry_from_ir()` / `build_router_index_from_config()` / `start_from_config()` 高层 facade；剩余 helper/starter owner 已迁到 `app/src/bootstrap_runtime/*`，但该 bootstrap 路径本身仍是 legacy runtime 壳
- `run_engine.rs` 现 129 行 public facade；剩余 runtime orchestration owner 已迁入 `app/src/run_engine_runtime/*`，但更大的 runtime seam 仍未 actor 化 / RuntimeContext 化
- `sb-config` DNS subtree 已完成 Raw owner 稳定化，但 `PlannedFacts` 仍未升级为 public `RuntimePlan`，crate 内也仍无稳定 namespace/query API

## 后续战场（未启动）

- **WP-30 Phase 3 后续**：
  - `WP-30aq` + `WP-30ar` 已把 `ir/mod.rs` / `validator/v2/mod.rs` facade 与 DNS Raw owner 稳定化；若继续推进，应聚焦更宽的 validated/planned consumer seam，而不是回退成重拆 facade 或误推 RuntimePlan
  - `PlannedFacts` 暴露 namespace 查询方法供 crate 内其他模块使用
  - 将 `PlannedFacts` 升级为 public `RuntimePlan`（需要先有稳定外部消费者）
  - 仍不是 `RuntimePlan` public 实作卡，也不是 crate-internal query API 卡
- runtime/bootstrap seam 继续收口，但 DNS env bridge 仍明确属于 runtime owner，**不**搬进 `planned.rs`
- runtime/bootstrap seam 继续收口，但 legacy router text emission 已迁入 `app/src/router_text.rs`，仍明确属于 runtime owner，**不**搬进 `planned.rs`
- runtime/bootstrap seam 继续收口，但 selector/urltest second-pass binding 已迁入 `app/src/outbound_groups.rs`，仍明确属于 runtime owner，**不**搬进 `planned.rs`
- runtime/bootstrap seam 继续收口，但 `app/src/outbound_builder/*` 当前是 legacy bootstrap 的 first-pass owner 模块，不是 RuntimePlan/query API seam
- runtime/bootstrap seam 继续收口，但 `app/src/bootstrap_runtime/*` 当前承接的 proxy registry/router helper/DNS apply/inbound starter/API starter/runtime shell 仍明确属于 runtime owner，**不**搬进 `planned.rs`
- runtime/run_engine seam 已以 `app/src/run_engine_runtime/*` 收口 helper/starter owner；若继续推进，应聚焦 runtime context / manager lifecycle，而不是回退成重新拆 `planned.rs`
