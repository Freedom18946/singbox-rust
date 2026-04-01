# WP-30k planned.rs preflight seam inventory

## Scope

- 这份 inventory 只记录 **仓库当前事实**，用于约束 `planned.rs` 的第一刀切口。
- 本卡目标是把 `planned.rs` 从泛 skeleton 升级成“前置契约 + 迁移地图”，不是实现 `RuntimePlan`。
- 本文聚焦：
  - `crates/sb-config/src/ir/planned.rs`
  - `crates/sb-config/src/lib.rs`
  - `crates/sb-config/src/ir/validated.rs`
  - `crates/sb-config/src/validator/v2/mod.rs`
  - `crates/sb-config/src/normalize.rs`
  - `crates/sb-config/src/minimize.rs`
  - `crates/sb-config/src/present.rs`
  - `app/src/bootstrap.rs`
  - `app/src/outbound_groups.rs`
  - `app/src/router_text.rs`
  - `app/src/dns_env.rs`
  - `app/src/run_engine.rs`
- 本文不把维护工作表述成 parity completion，也不把 runtime/bootstrap 现状误写成 `planned.rs` 已实现。

## Current Owners

| Responsibility | Current owner | Current file | Current stage | Why not already planned | Suggested first-cut target |
| --- | --- | --- | --- | --- | --- |
| Inbound tag uniqueness (`ib.tag`) | `Config::validate()` | `crates/sb-config/src/lib.rs:455-467` | post-validated semantic check | 现在走 `Config` 兼容入口，错误面直接返回给上层；还没有独立 planned fact layer | 后续可抽成 private planned tag scan，但先保持现有报错语义 |
| Outbound + endpoint shared tag namespace | `Config::validate()` | `crates/sb-config/src/lib.rs:469-483` | post-validated semantic check | 这是最接近 planned tag inventory 的现有 owner，但 today 只是即时检查，不产出计划事实 | **第一刀候选**：private tag namespace inventory |
| Selector / URLTest member existence (`members -> outbound tag`) | `Config::validate()` | `crates/sb-config/src/lib.rs:485-500` | post-validated semantic check | 目前只做 literal tag existence 检查，没有独立 reference graph | **第一刀候选**：private reference graph over validated IR |
| Route rule outbound existence (`rule.outbound`) | `Config::validate()` | `crates/sb-config/src/lib.rs:501-507` | post-validated semantic check | 与上面共用同一 tag set，但还没形成可复用 planned seam | **第一刀候选**：并入同一 private reference inventory |
| `route.default` existence | `Config::validate()` | `crates/sb-config/src/lib.rs:509-513` | post-validated semantic check | 仍是一次性检查；没有把 default route target 收成计划事实 | **第一刀候选**：并入同一 private reference inventory |
| Selector / URLTest 必须至少有一个 member | `ConfigIR::validate()` | `crates/sb-config/src/ir/validated.rs:256-302` | validated IR self-check | 这是 IR shape/business rule，不需要 tag graph 也能判定 | 暂留 `validated.rs` |
| Parse-time defaults: Shadowsocks `method` 默认值 + URLTest 默认 timing/url + selector/urltest 空 members 容器 | `validator/v2::to_ir_v1()` | `crates/sb-config/src/validator/v2/mod.rs:1669-1714` | raw -> validated parse | 这些默认值/alias 是原始输入兼容层的一部分；移动到 planned 会改变 validated IR 入口语义 | 暂留 `validator/v2` |
| Parse-time route alias fill: `route.final` / `route.default` 回填 | `validator/v2::to_ir_v1()` | `crates/sb-config/src/validator/v2/mod.rs:2283-2295` | raw -> validated parse | 这是 schema/compat 归一化，不是 runtime planning | 暂留 `validator/v2` |
| Credential ENV materialization (`username_env` / `password_env`) | `normalize_credentials()` | `crates/sb-config/src/validator/v2/mod.rs:529-542,3070-3071` | raw -> validated parse | 这是 parse-time secret resolution，发生在 validated IR 形成前 | 暂留 `validator/v2` |
| DNS / service detour strings are parsed but not bound | `validator/v2::to_ir_v1()` + validated fields | `crates/sb-config/src/validator/v2/mod.rs:2598-2612,2932-2945`; `crates/sb-config/src/ir/dns.rs:57-78`; `crates/sb-config/src/ir/service.rs:67-69` | validated payload population | 这些引用 today 只有“存字符串”，仓库里还没有统一 cross-reference binder | 第二刀候选：planned cross-ref expansion，先别和第一刀一起做 |
| Rule token canonicalization (domain/port/network/protocol) | `normalize_rule()` / `normalize_config()` | `crates/sb-config/src/normalize.rs:80-112` | post-validated canonicalization | 这里只做 token 规范化，不看 tag namespace，也不构建 runtime plan | 暂留 `normalize.rs` |
| Negation-aware minimization policy | `minimize_config()` | `crates/sb-config/src/minimize.rs:177-189` | post-validated optimization | 这是 CLI/输出优化策略，不是 planning contract | 暂留 `minimize.rs` |
| Legacy JSON view projection (`ConfigIR -> Value`) | `to_view()` | `crates/sb-config/src/present.rs:13-279` | presentation/export | 这里只做 literal projection，不做 reference binding 或 defaults replay | 暂留 `present.rs` |
| Selector / URLTest second-pass connector binding | `app::outbound_groups::bind_selector_outbound_groups()` | `app/src/outbound_groups.rs` | runtime construction | 这里直接实例化 `sb-core` connectors，并带 runtime-only side effects（health check / connector conversion）；`bootstrap.rs` 现只保留第一遍 concrete builder + second-pass 委托 | 暂留 runtime owner；planned 未来最多提供输入事实，不负责构造 connector |
| Legacy bootstrap first-pass concrete outbound builder | `app::outbound_builder::build_first_pass_concrete_outbounds()` | `app/src/outbound_builder/{mod.rs,simple.rs,quic.rs,shadowsocks.rs,v2ray.rs}` | runtime maintenance seam | 这里负责 simple proxy / QUIC / Shadowsocks / V2Ray family 的 runtime-flavored config build；`bootstrap.rs` 现只保留 thin delegate，但该 bootstrap 路径本身仍是 legacy owner，不是 live runtime plan | 暂留 runtime owner；planned 未来最多提供输入事实，不负责 protocol runtime config build |
| Router rules text emission with `unresolved` fallback | `app::router_text::ir_to_router_rules_text()` | `app/src/router_text.rs` | runtime construction | 这是 legacy router adapter path，仍输出字符串协议；`bootstrap.rs` 现只做委托 | 暂留 runtime owner |
| Legacy bootstrap runtime helper/starter seams | `app::bootstrap_runtime::*` | `app/src/bootstrap_runtime/{proxy_registry,router_helpers,dns_apply,inbounds,api_services,runtime_shell}.rs` | runtime maintenance seam | 这里直接改 env、启动 inbound/API task、持有 shutdown handle/runtime shell；虽已从 `bootstrap.rs` 下沉，但仍明确属于 legacy runtime/bootstrap owner，而不是 planned fact graph | 暂留 runtime owner |
| DNS env bridge from raw config (`dns` -> env vars) | `app::dns_env::apply_dns_env_from_config()` | `app/src/dns_env.rs` | runtime startup | 直接读 raw JSON 并改进程环境，完全是 runtime/bootstrap concern；当前由 `app/src/run_engine_runtime/supervisor.rs` 调用，`run_engine.rs` 仅保留 facade | 暂留 runtime owner |

## Candidate Moves Into planned.rs

1. 第一刀只收 `sb-config` 内已经存在的 tag/reference 事实，不引入 runtime 依赖。
   - 入口候选：从 `Config::validate()` 里 today 已经存在的 outbound/endpoint tag namespace、selector/urltest members、`rule.outbound`、`route.default` 这四类检查抽出一个 private seam。
   - 目标形态：private helper / internal fact struct；不要公开 `RuntimePlan` 类型。
2. 第二刀再考虑把 today 仅“存字符串”的引用关系补齐为 planned facts。
   - 典型样本：`DnsServerIR.detour`、`ServiceIR.detour`、`address_resolver`、`service`。
   - 这一步需要比第一刀更大的 tag domain 设计，所以不应和第一刀捆绑。
3. planned.rs 未来应消费 validated IR，而不是替代 `validator/v2` 的 parse-time alias/default 逻辑。

## Not Yet Safe To Move

- `validator/v2::to_ir_v1()` 的 parse-time defaults / alias fill / ENV resolution 还不安全。
  - 代表点：`crates/sb-config/src/validator/v2/mod.rs:1669-1714`, `crates/sb-config/src/validator/v2/mod.rs:2283-2295`, `crates/sb-config/src/validator/v2/mod.rs:529-542`.
- `normalize.rs` / `minimize.rs` / `present.rs` 仍是独立边界，不该被包装成 planned。
  - 它们分别负责 token canonicalization、输出优化策略、legacy projection。
- `app/src/outbound_groups.rs` 的 selector/urltest connector 组装、`app/src/outbound_builder/*` 的 legacy bootstrap first-pass concrete builder、`app/src/router_text.rs` 的 legacy router text emission、`app/src/bootstrap_runtime/*` 的 helper/starter seams，以及 `app/src/dns_env.rs` 的 DNS env bridge 仍是 runtime/bootstrap 责任。
  - 它们 today 直接依赖 runtime types、Tokio runtime、进程 env side effects。
- `ir_to_router_rules_text()` 这类字符串化 adapter 还不该并入 planned。
  - 这是 legacy router adapter seam，不是 `sb-config` 内的 runtime-neutral plan fact。

## First-Cut Status (WP-30l implemented)

WP-30l 已实现 first-cut private planned seam。`Config::validate()` 现在将以下四类检查委托给 `crate::ir::planned::validate_outbound_references()`：

1. **outbound/endpoint shared tag namespace uniqueness** — `TagNamespace::scan()` 扫描 `ConfigIR.outbounds` + `ConfigIR.endpoints`，检测重复 tag
2. **selector/urltest member reference existence** — `ReferenceValidator::check_selector_members()` 校验每个 member 是否存在于 tag namespace
3. **route rule outbound reference existence** — `ReferenceValidator::check_rule_outbounds()` 校验 `route.rules[*].outbound`
4. **`route.default` reference existence** — `ReferenceValidator::check_route_default()` 校验默认出站

### 已落地的 seam 结构（first-cut）

- `TagNamespace`：crate-private struct，持有扫描到的 outbound/endpoint tag set
- `ReferenceValidator`：crate-private struct，对 tag namespace 做引用存在性校验
- `validate_outbound_references()`：crate-private 入口函数，供 `Config::validate()` 调用
- 所有类型均 `pub(crate)`，不通过 `ir/mod.rs` 或 `lib.rs` re-export

## Second-Cut Status (WP-30m implemented)

WP-30m 将 planned seam 扩展为多 namespace cross-reference inventory。`Config::validate()` 现在额外调用 `crate::ir::planned::validate_cross_references()`，承接四类新增检查：

5. **`DnsServerIR.detour` → outbound/endpoint shared tag namespace** — `CrossReferenceValidator::check_dns_server_detour()`
6. **`DnsServerIR.address_resolver` → DNS server tag namespace** — `CrossReferenceValidator::check_dns_server_address_resolver()`
7. **`DnsServerIR.service` → service tag namespace** — `CrossReferenceValidator::check_dns_server_service()`
8. **`ServiceIR.detour` → inbound tag namespace** — `CrossReferenceValidator::check_service_detour()`

### 已落地的 seam 结构（second-cut 新增）

- `InboundNamespace`：crate-private struct，持有扫描到的 inbound tag set
- `DnsServerNamespace`：crate-private struct，持有扫描到的 DNS server tag set
- `ServiceNamespace`：crate-private struct，持有扫描到的 service tag set
- `CrossReferenceValidator`：crate-private struct，对四个 namespace 做跨域引用存在性校验
- `validate_cross_references()`：crate-private 入口函数，供 `Config::validate()` 调用（在 `validate_outbound_references()` 之后）

## Third-Cut Status (WP-30n implemented)

WP-30n 将 planned seam 进一步扩展，新增三类 DNS server tag reference 检查。复用已有的 `DnsServerNamespace` 和 `CrossReferenceValidator`：

9. **`DnsRuleIR.server` → DNS server tag namespace** — `CrossReferenceValidator::check_dns_rule_server()`
10. **`DnsIR.default` → DNS server tag namespace** — `CrossReferenceValidator::check_dns_default()`
11. **`DnsIR.final_server` → DNS server tag namespace** — `CrossReferenceValidator::check_dns_final_server()`

这三类检查都复用 `DnsServerNamespace`，在 `validate_cross_references()` 中于 WP-30m 四类检查之后执行。

### 四个 namespace 域（updated）

| Namespace | 来源 | 引用者 |
| --- | --- | --- |
| outbound/endpoint shared | `OutboundIR.name` + `EndpointIR.tag` | selector members, rule outbound, route.default, `DnsServerIR.detour` |
| inbound | `InboundIR.tag` | `ServiceIR.detour` |
| DNS server | `DnsServerIR.tag` | `DnsServerIR.address_resolver`, `DnsRuleIR.server`, `DnsIR.default`, `DnsIR.final_server` |
| service | `ServiceIR.tag` | `DnsServerIR.service` |

## Fact Graph Status (WP-30q: collect-phase completeness)

WP-30o 将 WP-30l/m/n 的离散 helper 收成 `PlannedFacts`。WP-30p 吸收了 inbound tag uniqueness。WP-30q 补齐了 DNS server 和 service tag uniqueness，使 collect 阶段对全部 4 个 namespace 做唯一性校验。

### 核心变更

- 引入 `PlannedFacts` struct，持有全部四个 namespace inventory：`TagNamespace`、`InboundNamespace`、`DnsServerNamespace`、`ServiceNamespace`
- 清晰分离两个阶段：
  - **Collect** — `PlannedFacts::collect(&ConfigIR)` 扫描所有 namespace facts，检查**全部 4 个 namespace** 的 tag 唯一性
  - **Validate** — `PlannedFacts::validate(&self, &ConfigIR)` 校验全部 11 类引用关系
- 单一入口函数 `validate_planned_facts(&ConfigIR)` 替代之前的 `validate_outbound_references()` + `validate_cross_references()` 两步调用
- `Config::validate()` 现在是 thin entry point，只做一次 `validate_planned_facts(&self.ir)` 调用，不持有任何自己的校验逻辑
- 原有 `ReferenceValidator` 和 `CrossReferenceValidator` 被内化为 `PlannedFacts` 的 private methods
- namespace scan 方法从 `pub(crate)` 降级为 `fn`（仅 `PlannedFacts` 需要调用）

### Namespace facts（4 域，全部含唯一性检查）

1. **outbound/endpoint shared** — `OutboundIR.name` + `EndpointIR.tag`（含唯一性检查）
2. **inbound** — `InboundIR.tag`（含唯一性检查，WP-30p 从 lib.rs 吸收）
3. **DNS server** — `DnsServerIR.tag`（含唯一性检查，WP-30q）
4. **service** — `ServiceIR.tag`（含唯一性检查，WP-30q）

**注意**: inbound 与 outbound/endpoint 仍是**独立 namespace**，同名 tag 分别出现在两个 namespace 中不冲突（Go parity）。

### Reference facts（11 类）

1. outbound/endpoint shared tag namespace uniqueness
2. selector/urltest member → outbound/endpoint namespace
3. route rule outbound → outbound/endpoint namespace
4. route.default → outbound/endpoint namespace
5. DnsServerIR.detour → outbound/endpoint namespace
6. DnsServerIR.address_resolver → DNS server namespace
7. DnsServerIR.service → service namespace
8. ServiceIR.detour → inbound namespace
9. DnsRuleIR.server → DNS server namespace
10. DnsIR.default → DNS server namespace
11. DnsIR.final_server → DNS server namespace

### 这仍然不是 public RuntimePlan

- `PlannedFacts` 是 `pub(crate)`，不通过 `ir/mod.rs` 或 `lib.rs` re-export
- 没有 public builder API
- 没有 public `PlannedConfigIR`
- 但内部结构已经足够清楚，可以作为未来 `RuntimePlan` 的前体

### 仍未搬的责任面

- ~~**Inbound tag uniqueness**~~ — WP-30p 已吸收入 `PlannedFacts::collect()`
- **validator/v2 parse-time defaults/alias/ENV** — 仍留在 validator
- ~~**normalize owner**~~ — WP-30r 已迁移到 `ir/normalize.rs`，原 `normalize.rs` 保留为 thin compat shell
- ~~**minimize owner**~~ — WP-30s 已迁移到 `ir/minimize.rs`，原 `minimize.rs` 保留为 thin compat shell
- **present** — 仍是独立边界
- **bootstrap/run_engine runtime binding** — 仍是 runtime owner 责任
- **runtime-facing DNS env bridge** — 仍在 `app::dns_env::apply_dns_env_from_config()`
- **crate-internal namespace query API** — 仍不暴露（没有稳定的 crate 内消费者）

### 约束（不变）

- 不新增 public `RuntimePlan` / `PlannedConfigIR` / builder API
- 不搬 runtime connector construction
- 不碰 `validator/v2` 业务逻辑与 parse-time defaults
- 不改变 `normalize` / `minimize` / `present` 现有行为（WP-30r/30s 只做 owner 迁移，不改语义）

## Test Pins

### WP-30k 原有 pins（仍有效）

- `crates/sb-config/src/ir/validated.rs`
  - `planned_preflight_pin_current_owner_validated_validate_requires_selector_members`
  - pin 当前 owner：`ConfigIR::validate()` 仍负责 selector/urltest 的 planning-adjacent member 形状校验。
- `crates/sb-config/src/normalize.rs`
  - ~~`planned_preflight_pin_current_owner_normalize_only_rewrites_rule_tokens`~~ → WP-30r superseded by `wp30r_pin_compat_shell_is_pure_delegate` + `wp30r_pin_compat_shell_normalize_config_delegates`
  - pin: `normalize.rs` 现在是 thin compat shell，只转发到 `crate::ir::normalize`
- `crates/sb-config/src/lib.rs`
  - `planned_preflight_pin_current_owner_dns_detour_validated_but_not_env_bound`
  - **WP-30m updated**: dns.detour reference existence 现在已由 planned.rs 校验（`validate_cross_references`），但 runtime env binding 仍不在 sb-config 内。此 pin 确认 missing detour 被拒绝，且 IR 保留原始字符串。

### WP-30l 新增 pins（WP-30o renamed/superseded）

- `crates/sb-config/src/ir/planned.rs`（unit tests）：
  - ~~`planned_pin_tag_namespace_owned_by_planned_seam`~~ → superseded by `planned_pin_fact_graph_owns_tag_namespace`
  - ~~`planned_pin_member_ref_owned_by_planned_seam`~~ → superseded by `planned_pin_fact_graph_owns_member_refs`
- `crates/sb-config/src/lib.rs`（integration tests）：
  - `wp30l_duplicate_outbound_tag_error_unchanged` — pin: 错误文案不变
  - `wp30l_selector_missing_member_error_unchanged` — pin: 错误文案不变
  - `wp30l_rule_outbound_missing_error_unchanged` — pin: 错误文案不变
  - `wp30l_route_default_missing_error_unchanged` — pin: 错误文案不变
  - `wp30l_valid_outbound_selector_route_passes` — 合法组合仍通过
  - ~~`wp30l_pin_inbound_duplicate_tag_still_in_lib_validate`~~ → WP-30p superseded by `wp30p_pin_inbound_duplicate_tag_owned_by_fact_graph`

### WP-30m 新增 pins（WP-30o renamed/superseded）

- `crates/sb-config/src/ir/planned.rs`（unit tests）：
  - ~~`planned_pin_cross_ref_owned_by_planned_seam`~~ → superseded by `planned_pin_fact_graph_owns_cross_refs`
  - ~~`planned_pin_service_detour_owned_by_planned_seam`~~ → merged into `planned_pin_fact_graph_owns_cross_refs`
  - `planned_pin_dns_env_bridge_not_in_planned` — pin: runtime-facing DNS env bridge 仍不在 planned.rs（保留，名称不变）
- `crates/sb-config/src/lib.rs`（integration tests）：
  - `wp30m_dns_detour_missing_outbound_rejected` — dns server detour 指向缺失 outbound 被拒绝
  - `wp30m_dns_address_resolver_missing_rejected` — address_resolver 指向缺失 dns server 被拒绝
  - `wp30m_dns_service_missing_rejected` — service 指向缺失 service tag 被拒绝
  - `wp30m_service_detour_missing_inbound_rejected` — service detour 指向缺失 inbound 被拒绝
  - `wp30m_valid_cross_references_pass` — 合法 cross-reference 组合仍通过
  - `wp30m_pin_dns_env_bridge_not_in_planned_seam` — pin: runtime-facing DNS env bridge 仍不在 planned.rs

### WP-30n 新增 pins（WP-30o renamed/superseded）

- `crates/sb-config/src/ir/planned.rs`（unit tests）：
  - ~~`planned_pin_dns_rule_server_owned_by_planned_seam`~~ → superseded by `planned_pin_fact_graph_owns_dns_server_refs`
  - ~~`planned_pin_dns_default_final_owned_by_planned_seam`~~ → merged into `planned_pin_fact_graph_owns_dns_server_refs`
- `crates/sb-config/src/lib.rs`（integration tests，保留不变）：
  - `wp30n_dns_rule_server_missing_rejected` — dns rule server 指向缺失 dns server 被拒绝
  - `wp30n_dns_default_missing_rejected` — dns default 指向缺失 dns server 被拒绝
  - `wp30n_dns_final_server_missing_rejected` — dns final_server 指向缺失 dns server 被拒绝
  - `wp30n_valid_dns_rule_default_final_pass` — 合法 dns rule server + default + final 组合仍通过

### WP-30o 新增 pins

- `crates/sb-config/src/ir/planned.rs`（unit tests）：
  - `planned_pin_fact_graph_owns_tag_namespace` — pin: tag namespace uniqueness 现在由 PlannedFacts fact graph 持有
  - `planned_pin_fact_graph_owns_member_refs` — pin: selector/urltest member reference check 现在由 PlannedFacts fact graph 持有
  - `planned_pin_fact_graph_owns_cross_refs` — pin: DNS/service cross-reference check 现在由 PlannedFacts fact graph 持有
  - `planned_pin_fact_graph_owns_dns_server_refs` — pin: DNS rule server + DnsIR.default/final_server reference check 现在由 PlannedFacts fact graph 持有
  - `planned_pin_dns_env_bridge_not_in_planned` — pin: runtime-facing DNS env bridge 仍不在 planned.rs（保留自 WP-30m）
  - ~~`planned_pin_inbound_uniqueness_not_in_fact_graph`~~ → WP-30p superseded by `planned_pin_fact_graph_owns_inbound_uniqueness`
- `crates/sb-config/src/lib.rs`（integration tests，WP-30l/m/n 全部保留不变）：
  - 所有 `wp30l_*`、`wp30m_*`、`wp30n_*` integration tests 继续通过，确认错误文案和外部行为不变

### WP-30p 新增/迁移 pins

- `crates/sb-config/src/ir/planned.rs`（unit tests）：
  - `planned_pin_fact_graph_owns_inbound_uniqueness` — pin: inbound tag uniqueness 现在由 PlannedFacts fact graph 持有（WP-30p，supersedes `planned_pin_inbound_uniqueness_not_in_fact_graph`）
  - `planned_pin_validate_is_thin_entry_point` — pin: `Config::validate()` 现在是 thin entry point，不持有自己的校验逻辑
  - `planned_pin_inbound_outbound_independent_namespaces` — pin: inbound 与 outbound/endpoint 仍是独立 namespace
  - `fact_graph_collect_duplicate_inbound_rejected` — unit test: duplicate inbound tag 被 collect 阶段拒绝
- `crates/sb-config/src/lib.rs`（integration tests）：
  - `wp30p_pin_inbound_duplicate_tag_owned_by_fact_graph` — pin: inbound duplicate tag 错误文案不变，owner 已迁移到 fact graph（supersedes `wp30l_pin_inbound_duplicate_tag_still_in_lib_validate`）
  - `wp30p_pin_inbound_outbound_same_tag_allowed` — pin: inbound/outbound 同名 tag 允许共存（独立 namespace，Go parity）
  - `wp30p_pin_dns_env_bridge_still_not_moved` — pin: runtime-facing DNS env bridge 仍不在 planned.rs
  - 所有 `wp30l_*`、`wp30m_*`、`wp30n_*` integration tests 继续通过

### WP-30q 新增 pins

- `crates/sb-config/src/ir/planned.rs`（unit tests）：
  - `planned_pin_fact_graph_owns_dns_server_uniqueness` — pin: DNS server tag uniqueness 现在由 PlannedFacts fact graph 持有（WP-30q）
  - `planned_pin_fact_graph_owns_service_uniqueness` — pin: service tag uniqueness 现在由 PlannedFacts fact graph 持有（WP-30q）
  - `fact_graph_collect_duplicate_dns_server_rejected` — unit test: duplicate DNS server tag 被 collect 阶段拒绝
  - `fact_graph_collect_distinct_dns_servers_pass` — unit test: distinct DNS server tags 通过
  - `fact_graph_collect_empty_dns_tag_not_checked` — unit test: empty DNS server tag 不参与唯一性检查
  - `fact_graph_collect_duplicate_service_rejected` — unit test: duplicate service tag 被 collect 阶段拒绝
  - `fact_graph_collect_distinct_services_pass` — unit test: distinct service tags 通过
  - `fact_graph_collect_empty_service_tag_not_checked` — unit test: empty service tag 不参与唯一性检查
  - `fact_graph_collect_none_service_tag_not_checked` — unit test: None service tag 不参与唯一性检查
- `crates/sb-config/src/lib.rs`（integration tests）：
  - `wp30q_duplicate_dns_server_tag_rejected` — duplicate DNS server tag via Config::validate() 被拒绝
  - `wp30q_distinct_dns_server_tags_pass` — distinct DNS server tags 通过
  - `wp30q_duplicate_service_tag_rejected` — duplicate service tag via Config::validate() 被拒绝
  - `wp30q_distinct_service_tags_pass` — distinct service tags 通过
  - `wp30q_pin_validate_still_thin_entry_point` — pin: Config::validate() 仍是 thin entry point，全 namespace 唯一性检查完成后仍通过
  - 所有 `wp30l_*`、`wp30m_*`、`wp30n_*`、`wp30p_*` integration tests 继续通过

### WP-30r 新增/迁移 pins

- `crates/sb-config/src/ir/normalize.rs`（unit tests）：
  - `wp30r_pin_normalize_only_rewrites_rule_tokens` — pin: normalize 只做 token canonicalization，不碰 planned references（取代旧 `planned_preflight_pin_current_owner_normalize_only_rewrites_rule_tokens`）
  - `wp30r_pin_owner_is_ir_normalize` — pin: normalization 实际 owner 在 ir/normalize.rs
  - `domain_norm_and_ports` — unit test: 基础 domain/port normalization（从旧 normalize.rs 迁移）
- `crates/sb-config/src/normalize.rs`（compat shell tests）：
  - `wp30r_pin_compat_shell_is_pure_delegate` — pin: normalize.rs 现在是 thin compat shell，只转发
  - `wp30r_pin_compat_shell_normalize_config_delegates` — pin: normalize_config 通过 compat shell 正常工作

### WP-30s 新增 pins

- `crates/sb-config/src/ir/minimize.rs`（unit tests）：
  - `wp30s_pin_owner_is_ir_minimize` — pin: minimization 实际 owner 在 ir/minimize.rs
  - `wp30s_pin_minimize_is_not_planned` — pin: minimize 是 post-validated optimization，不是 planned contract
  - `wp30s_pin_negation_only_normalizes` — pin: negation 存在时只做 normalization，不做 fold/dedup
  - `skip_when_neg` — unit test: negation 触发 SkippedByNegation（从旧 minimize.rs 迁移）
  - `apply_when_no_neg` — unit test: 无 negation 时 fold/dedup 正常执行
- `crates/sb-config/src/minimize.rs`（compat shell tests）：
  - `wp30s_pin_compat_shell_is_pure_delegate` — pin: minimize.rs 现在是 thin compat shell，只转发
  - `wp30s_pin_compat_shell_minimize_config_delegates` — pin: minimize_config 通过 compat shell 正常工作
