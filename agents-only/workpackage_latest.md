<!-- tier: S -->
# 工作阶段总览（Workpackage Map）

> **用途**：阶段划分 + 当前位置。S-tier，每次会话必读。
> **纪律**：Phase 关闭后压缩为一行状态。本文件严格 ≤120 行。
> **对比**：本文件管"在哪"；`active_context.md` 管"刚做了什么 / 下一步"。

---

## 已关闭阶段（一行总结）

| 阶段 | 交付 | 关闭时间 |
|------|------|----------|
| L1-L17 | 架构整固、功能对齐、CI / 发布收口 | 2026-01 ~ 2026-02 |
| MIG-02 / L21 | 隐式回退消除，541 V7 assertions，生产路径零隐式直连回退 | 2026-03-07 |
| L18 Phase 1-4 | 认证替换、证据模型收口、GUI gate 复验、长跑恢复决策门 | 2026-03-11 |
| L22 | dual-kernel parity 52/60 (86.7%)，16 个 both-case，Sniff Phase A+B | 2026-03-15 |
| 后 L22 补丁 | QUIC 多包重组、OverrideDestination、UDP datagram sniff、编译修复 | 2026-03-15 |
| L23 | TUN/Sniff 运行时补全、Provider wiring、T4 Protocol Suite、parity 92.9% | 2026-03-16 |
| L24 | 性能/安全/质量/功能补全，30 任务 (B1-B4)，综合验收 39/41 PASS | 2026-03-17 |
| L25 | 生产加固 + 跨平台补全 + 文档完善，10/10 任务，4 批次全部交付 | 2026-03-17 |

---

## 当前状态：维护模式（L1-L25 全部 Closed）

**全部阶段关闭**。项目进入稳定维护。

### 维护卡（2026-04-02）

- **WP-30ao**: run_engine runtime orchestration seam 超级卡 — 已完成
  - 新增 `app/src/run_engine_runtime/{mod.rs,config_load.rs,debug_env.rs,output.rs,admin_start.rs,watch.rs,supervisor.rs}`，迁入 config/raw loading、debug env、startup/reload output glue、admin/clash/api startup、watch/reload handle 与 supervisor startup/shutdown orchestration owner
  - `app/src/run_engine.rs` 现仅保留 public facade / option types / thin delegates；`run_supervisor()` 实际 owner 已迁到 `crate::run_engine_runtime::supervisor::run_supervisor(...)`
  - `run_engine.rs` 从 1188 → 129 行（-1059）；新增 15 个定点测试（默认 feature 13 个，`--features parity` 15 个），覆盖 config/raw merge、debug env、watch snapshot/change detection、clash_api listen parsing 与 facade/source pins
  - 这张卡是 runtime/run_engine helper-starter 超级卡，不是 `planned.rs` / RuntimePlan 卡；不触碰 `bootstrap_runtime/*`、`router_text.rs`、`dns_env.rs`、`planned.rs`
  - 自验证：`cargo test -p app --lib run_engine_runtime` + `cargo test -p app --lib run_engine_runtime::admin_start --features parity` + `cargo test -p app --lib`；`cargo test -p app` 仍受当前仓库默认 feature 组合下的 `e2e_subs_security` / `admin_debug` 不匹配影响失败；`cargo clippy -p app --all-features --all-targets -- -D warnings` 返回 0，但仍打印既有 `admin_debug/mod.rs` doc warning 与 `outbound_groups.rs` dead_code / needless_pass_by_value 类 warning

- **WP-30an**: bootstrap runtime helper/starter owner 超级卡 — 已完成
  - 新增 `app/src/bootstrap_runtime/{mod.rs,proxy_registry.rs,router_helpers.rs,dns_apply.rs,inbounds.rs,api_services.rs,runtime_shell.rs}`，迁入 proxy registry env/pool parsing、router helper、legacy DNS apply helper、inbound starter facade、Clash/V2Ray API starter、`ServiceHandle` 与 `Runtime`/`shutdown()` owner
  - `app/src/bootstrap.rs` 现仅保留 `build_outbound_registry_from_ir()` / `build_router_index_from_config()` / `start_from_config()` 等高层 facade，并把剩余 runtime helper/starter 统一委托给 `crate::bootstrap_runtime::*`
  - 当前仓库事实是 `bootstrap.rs` 仍未接入 `lib.rs` / `run_engine` 主路径，因此 `bootstrap_runtime` 与 `outbound_builder` 一样以 test-only legacy runtime owner module + source pins 形式收口；这张卡是 runtime/bootstrap helper/starter 超级卡，不是 `planned.rs` / RuntimePlan 卡
  - `bootstrap.rs` 从 1109 → 255 行（-854）；新增 21 个定点测试（默认 feature 16 个，`--features parity` 21 个），覆盖 proxy registry env/pool parsing、DNS token/dedup/normalize、inbound facade、Clash/V2Ray API invalid listen + shutdown handle、runtime shutdown timeout 与 owner pins
  - 自验证：`cargo test -p app --lib bootstrap_runtime` + `cargo test -p app --lib bootstrap_runtime --features parity` + `cargo test -p app --lib`；`cargo test -p app` 仍受当前仓库默认 feature 组合下的 `e2e_subs_security` / `admin_debug` 不匹配影响失败；`cargo clippy -p app --all-features --all-targets -- -D warnings` 返回 0，但仍打印既有 `admin_debug/mod.rs` doc warning 与 `outbound_groups.rs` dead_code 类 warning
- **WP-30am**: bootstrap first-pass concrete outbound builder owner 收口 — 已完成
  - 新增 `app/src/outbound_builder/{mod.rs,simple.rs,quic.rs,shadowsocks.rs,v2ray.rs}`，迁入 legacy bootstrap first-pass concrete builder owner，按 simple proxy / QUIC / Shadowsocks / V2Ray family 拆分；`resolve_host_port()`、ALPN/header mapping、default alias fill 等 shared helper 一并下沉
  - `app/src/bootstrap.rs` 的 `build_outbound_registry_from_ir()` 现把 first-pass 委托给 `crate::outbound_builder::build_first_pass_concrete_outbounds(...)`，并继续把 second-pass 委托给 `crate::outbound_groups::bind_selector_outbound_groups(...)`
  - 当前仓库事实是 `bootstrap.rs` 仍未接入 `lib.rs` / `run_engine` 主路径，因此 `outbound_builder` 以 test-only runtime owner module + source pins 形式收口；这张卡是 runtime/bootstrap seam 超级卡，不是 `planned.rs` / RuntimePlan 卡
  - `bootstrap.rs` 从 1443 → 1109 行（-334）；新增 15 个 first-pass 定点测试（simple/QUIC/Shadowsocks/V2Ray family + 2 pins）
  - 自验证：`cargo test -p app --lib outbound_builder` + `cargo test -p app --lib outbound_groups` + `cargo test -p app --lib`；`cargo test -p app` 仍受当前仓库默认 feature 组合下的 `e2e_subs_security` / `admin_debug` 不匹配影响失败；`cargo clippy -p app --all-features --all-targets -- -D warnings` 返回 0，但仍打印既有 `admin_debug/mod.rs` doc warning 与 `outbound_groups.rs` dead_code 类 warning
- **WP-30al**: selector/urltest second-pass runtime owner 收口 — 已完成
  - 新增 `app/src/outbound_groups.rs`，迁入 selector/urltest second-pass connector binding owner、member lookup/filter、`to_adapter_connector()` 与 URLTest health-check 启动
  - `app/src/bootstrap.rs` 的 `build_outbound_registry_from_ir()` 现保留第一遍 concrete outbound 构建，并把 second-pass 委托给 `crate::outbound_groups::bind_selector_outbound_groups(...)`
  - second-pass selector/urltest binding 仍是 runtime/bootstrap seam：继续依赖 runtime connector types、Tokio runtime、cache/urltest history 服务；这张卡不是 `planned.rs` / RuntimePlan 卡
  - `bootstrap.rs` 从 1685 → 1443 行（-242），`outbound_groups.rs` 411 行（含测试）
  - 新增 11 个 selector/urltest 定点测试（正常绑定、missing/unusable/empty members skip、`to_adapter_connector()` pin + 2 个 owner pins）
  - 自验证：`cargo test -p app --lib outbound_groups` + `cargo test -p app --lib`；`cargo test -p app` 仍受当前仓库默认 feature 组合下的 `e2e_subs_security` / `admin_debug` 不匹配影响失败；`cargo clippy -p app --all-features --all-targets -- -D warnings` 返回 0，但仍打印既有 `admin_debug/mod.rs` doc warning，且 `bootstrap.rs` 未接入 `lib.rs` 模块树导致 `app(lib)` target 对 `outbound_groups.rs` 报 dead_code 类 warning
- **WP-30ak**: legacy router rules text emission owner 收口 — 已完成
  - 新增 `app/src/router_text.rs`，迁入 `ir_to_router_rules_text()` 与专属 helper；`app/src/bootstrap.rs` 的 `build_router_index_from_config()` 改为 `to_ir` → `router_text` → `router_build_index_from_str()` 的薄委托
  - legacy router text emission 仍是 runtime/legacy adapter seam：继续输出供 `router_build_index_from_str()` 消费的字符串协议，保留 missing `rule.outbound` / missing `route.default` 的 `unresolved` fallback 语义
  - `bootstrap.rs` 从 1722 → 1685 行（-37），`router_text.rs` 189 行（含测试）；这张卡是 runtime/bootstrap seam 收口，不是 `planned.rs` / RuntimePlan 卡
  - 新增 7 个 router text 定点测试（domain/geosite/geoip/cidr4/cidr6/port/portrange/process/transport/protocol、missing outbound/default fallback、consumer 兼容性 + 2 pins）
  - 自验证：`cargo test -p app --lib router_text` + `cargo test -p app --lib wp30ak` + `cargo test -p app --lib`；`cargo test -p app` 仍受当前仓库默认 feature 组合下的 `e2e_subs_security` / `admin_debug` 不匹配影响失败；`cargo clippy -p app --all-features --all-targets -- -D warnings` ✅ pass（仅提示既有 `admin_debug/mod.rs` doc warning）
- **WP-30aj**: runtime-facing DNS env bridge owner 收口 — 已完成
  - 新增 `app/src/dns_env.rs`，迁入 `apply_dns_env_from_config()` 与专属 helper；初始调用点在 `app/src/run_engine.rs`，当前已随 `WP-30ao` 下沉到 `app/src/run_engine_runtime/supervisor.rs`
  - `run_engine.rs` 从 1500+ 行降到 1188 行；`bootstrap.rs` DNS env 写入逻辑保持不动；这张卡是 runtime/bootstrap seam 收口，不是 `planned.rs` / RuntimePlan 卡
  - 新增 11 个 DNS env 定点测试（server 形态、strategy/HE、TTL/hosts/static、`set_if_unset`、`bool` 语义 + 2 pins）
  - 自验证：`cargo test -p app --lib dns_env` + `cargo test -p app --lib`；`cargo test -p app` 受当前仓库默认 feature 组合下的 `e2e_subs_security` / `admin_debug` 不匹配影响失败；`cargo clippy -p app --all-features --all-targets -- -D warnings` 暴露的是既有 `admin_debug/mod.rs` / `telemetry.rs` warnings
- **WP-30ai**: `ir/multiplex.rs` multiplex/brutal owner 收口 — 已完成
  - 新增 `ir/multiplex.rs`，迁入 `MultiplexOptionsIR` / `BrutalIR` owner 与 `Deserialize` impl；`ir/mod.rs` 改为 `mod multiplex;` + `pub use multiplex::{...}` 薄壳
  - `ir/mod.rs` 从 321 → 252 行（-69），`ir/multiplex.rs` 199 行（含测试）；`Credentials` / `Listable<T>` / `StringOrObj<T>` 仍留在 `ir/mod.rs` 作为更宽共享类型
  - 这是 `ir/multiplex.rs` owner 收口卡，不是 RuntimePlan 卡
  - 自验证：`cargo test -p sb-config --lib ir::multiplex` + `cargo test -p sb-config --lib multiplex` + `cargo test -p sb-config --test outbound_raw_boundary_test multiplex` + `cargo test -p sb-config --lib` + `cargo clippy -p sb-config --all-features --all-targets -- -D warnings`
- **WP-30ah**: `ir/inbound.rs` masquerade owner 收口 — 已完成
  - `MasqueradeIR` + 3 个 leaf 类型迁入 `ir/inbound.rs`；`ir/mod.rs` 改为 `pub use inbound::{...}` 薄壳
  - `ir/mod.rs` 从 406 → 321 行（-85）；`raw.rs` 继续持有 strict Raw bridge，语义不变
  - `MultiplexOptionsIR` / `BrutalIR` / `Credentials` / `Listable<T>` / `StringOrObj<T>` 仍留在 `ir/mod.rs` 作为跨域共享类型
  - 这是 `ir/inbound.rs` owner 收口卡，不是 RuntimePlan 卡
  - 自验证：inbound/masquerade 定点测试 + raw bridge 定点测试 + `cargo test -p sb-config --lib ir::inbound` + `cargo test -p sb-config --lib` + `cargo clippy -p sb-config --all-features --all-targets -- -D warnings`
- **WP-30ag**: `ir/service.rs` service/DERP owner 收口 — 已完成
  - `InboundTlsOptionsIR` + 6 个 `Derp*` 类型迁入 `ir/service.rs`；`ir/mod.rs` 改为 `pub use service::{...}` 薄壳
  - `ir/mod.rs` 从 703 → 406 行（-297），`ir/service.rs` 从 331 → 694 行（含测试）
  - `Listable<T>` / `StringOrObj<T>` / `Credentials` 仍留在 `ir/mod.rs` 作为跨域共享类型
  - 这是 `ir/service.rs` owner 收口卡，不是 RuntimePlan 卡
  - 自验证：service/DERP 定点测试 + raw bridge 定点测试 + `cargo test -p sb-config --lib` + `cargo clippy -p sb-config --all-features --all-targets -- -D warnings`
- **WP-30af**: validator/v2 facade owner 迁移 — 已完成
  - 新增 `validator/v2/facade.rs`，收纳 `validate_v2()` / `to_ir_v1()` / `pack_output()` 实际 owner
  - `validator/v2/mod.rs` 改成 thin delegate + shared helper + TLS re-export
  - mod.rs 从 742 → 260 行（-482），`facade.rs` 759 行（含测试）
  - 这是 validator/v2 facade owner 迁移卡，不是 RuntimePlan 卡
  - 17 个 facade 定点测试（含 2 个 facade pins）
- **WP-30ae**: root schema core owner 迁移 — 已完成
  - `validator/v2/schema_core.rs` 现在是 root schema validation 的实际 owner
  - `validate_v2()` 对 root schema validation 只做一行委托 `schema_core::validate_root_schema()`
  - mod.rs 从 793 → 742 行（-51）
  - 这是 validator/v2 root schema core owner 迁移卡，不是 RuntimePlan 卡
  - 9 个测试（7 功能 + 2 pins）
- **WP-30ad**: credential normalization owner 迁移 — 已完成（earlier）
- **WP-30ac**: top-level lowering owner 迁移 — 已完成（earlier）
- **WP-30ab**: security warning owner 迁移 — 已完成（earlier）
- **WP-30aa**: deprecation detection owner 迁移 — 已完成（earlier）
- **WP-30z ~ WP-30q**: outbound/route/dns/service/endpoint/inbound/planned seam 系列 — 已完成（earlier）

### 构建基线（2026-04-01，WP-30ai 后）

| 构建 | 状态 |
|------|------|
| `cargo clippy -p sb-config --all-features --all-targets -- -D warnings` | ✅ pass |
| `cargo test -p sb-config --lib` | ✅ 649 passed |
