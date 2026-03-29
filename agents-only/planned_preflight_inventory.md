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
| Selector / URLTest second-pass connector binding | `build_outbound_registry_from_ir()` | `app/src/bootstrap.rs:174-479,482-610` | runtime construction | 这里直接实例化 `sb-core` connectors，并带 runtime-only side effects（health check / connector conversion） | 暂留 runtime owner；planned 未来最多提供输入事实，不负责构造 connector |
| Router rules text emission with `unresolved` fallback | `ir_to_router_rules_text()` | `app/src/bootstrap.rs:708-758` | runtime construction | 这是 legacy router adapter path，仍输出字符串协议 | 暂留 runtime owner |
| DNS env bridge from raw config (`dns` -> env vars) | `apply_dns_env_from_config()` | `app/src/run_engine.rs:1198-1471` | runtime startup | 直接读 raw JSON 并改进程环境，完全是 runtime/bootstrap concern | 暂留 runtime owner |

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
- `app/src/bootstrap.rs` 的 selector/urltest connector 组装与 `app/src/run_engine.rs` 的 DNS env bridge 仍是 runtime/bootstrap 责任。
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

### 仍未搬的责任面

- **Inbound tag uniqueness** — 故意留在 `Config::validate()` (lib.rs)，因为 inbound 和 outbound/endpoint 是独立 namespace
- **validator/v2 parse-time defaults/alias/ENV** — 仍留在 validator
- **normalize/minimize/present** — 仍是独立边界
- **bootstrap/run_engine runtime binding** — 仍是 runtime owner 责任
- **runtime-facing DNS env bridge** — 仍在 `app::run_engine::apply_dns_env_from_config()`

### 约束（不变）

- 不新增 public `RuntimePlan` / `PlannedConfigIR` / builder API
- 不搬 runtime connector construction
- 不碰 `validator/v2` 业务逻辑与 parse-time defaults
- 不改变 `normalize` / `minimize` / `present` 现有行为

## Test Pins

### WP-30k 原有 pins（仍有效）

- `crates/sb-config/src/ir/validated.rs`
  - `planned_preflight_pin_current_owner_validated_validate_requires_selector_members`
  - pin 当前 owner：`ConfigIR::validate()` 仍负责 selector/urltest 的 planning-adjacent member 形状校验。
- `crates/sb-config/src/normalize.rs`
  - `planned_preflight_pin_current_owner_normalize_only_rewrites_rule_tokens`
  - pin 当前 owner：`normalize_config()` 只做规则 token canonicalization，不重写 `rule.outbound` / `route.default` 这类 planned references。
- `crates/sb-config/src/lib.rs`
  - `planned_preflight_pin_current_owner_dns_detour_validated_but_not_env_bound`
  - **WP-30m updated**: dns.detour reference existence 现在已由 planned.rs 校验（`validate_cross_references`），但 runtime env binding 仍不在 sb-config 内。此 pin 确认 missing detour 被拒绝，且 IR 保留原始字符串。

### WP-30l 新增 pins

- `crates/sb-config/src/ir/planned.rs`（unit tests）：
  - `planned_pin_tag_namespace_owned_by_planned_seam` — pin: tag namespace check 现在由 planned.rs seam 持有
  - `planned_pin_member_ref_owned_by_planned_seam` — pin: member reference check 现在由 planned.rs seam 持有
- `crates/sb-config/src/lib.rs`（integration tests）：
  - `wp30l_duplicate_outbound_tag_error_unchanged` — pin: 错误文案不变
  - `wp30l_selector_missing_member_error_unchanged` — pin: 错误文案不变
  - `wp30l_rule_outbound_missing_error_unchanged` — pin: 错误文案不变
  - `wp30l_route_default_missing_error_unchanged` — pin: 错误文案不变
  - `wp30l_valid_outbound_selector_route_passes` — 合法组合仍通过
  - `wp30l_pin_inbound_duplicate_tag_still_in_lib_validate` — pin: inbound duplicate tag 仍留在 lib.rs

### WP-30m 新增 pins

- `crates/sb-config/src/ir/planned.rs`（unit tests）：
  - `planned_pin_cross_ref_owned_by_planned_seam` — pin: DNS detour cross-reference check 现在由 planned.rs seam 持有
  - `planned_pin_service_detour_owned_by_planned_seam` — pin: service detour → inbound 现在由 planned.rs seam 持有
  - `planned_pin_dns_env_bridge_not_in_planned` — pin: runtime-facing DNS env bridge 仍不在 planned.rs
- `crates/sb-config/src/lib.rs`（integration tests）：
  - `wp30m_dns_detour_missing_outbound_rejected` — dns server detour 指向缺失 outbound 被拒绝
  - `wp30m_dns_address_resolver_missing_rejected` — address_resolver 指向缺失 dns server 被拒绝
  - `wp30m_dns_service_missing_rejected` — service 指向缺失 service tag 被拒绝
  - `wp30m_service_detour_missing_inbound_rejected` — service detour 指向缺失 inbound 被拒绝
  - `wp30m_valid_cross_references_pass` — 合法 cross-reference 组合仍通过
  - `wp30m_pin_dns_env_bridge_not_in_planned_seam` — pin: runtime-facing DNS env bridge 仍不在 planned.rs

### WP-30n 新增 pins

- `crates/sb-config/src/ir/planned.rs`（unit tests）：
  - `planned_pin_dns_rule_server_owned_by_planned_seam` — pin: DNS rule server reference check 现在由 planned.rs seam 持有
  - `planned_pin_dns_default_final_owned_by_planned_seam` — pin: DnsIR.default/final_server reference check 现在由 planned.rs seam 持有
- `crates/sb-config/src/lib.rs`（integration tests）：
  - `wp30n_dns_rule_server_missing_rejected` — dns rule server 指向缺失 dns server 被拒绝
  - `wp30n_dns_default_missing_rejected` — dns default 指向缺失 dns server 被拒绝
  - `wp30n_dns_final_server_missing_rejected` — dns final_server 指向缺失 dns server 被拒绝
  - `wp30n_valid_dns_rule_default_final_pass` — 合法 dns rule server + default + final 组合仍通过
